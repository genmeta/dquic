/// Upper bound on the contiguous ClientHello retained before choosing an endpoint.
/// This matches qtls's default handshake input limit.
pub(crate) const MAX_CLIENT_HELLO: usize = 256 * 1024;

/// Reads a routing name, not an authenticated identity. The original bytes must
/// still be passed to the one TLS session for full validation.
pub(crate) fn peek_server_name(crypto: &[u8]) -> Result<Option<&str>, &'static str> {
    let Some(&kind) = crypto.first() else {
        return Ok(None);
    };
    if kind != 1 {
        return Err("expected ClientHello");
    }
    if crypto.len() < 4 {
        return Ok(None);
    }
    let length = ((crypto[1] as usize) << 16) | ((crypto[2] as usize) << 8) | crypto[3] as usize;
    if length > MAX_CLIENT_HELLO - 4 {
        return Err("ClientHello exceeds buffer limit");
    }
    let Some(mut body) = crypto.get(4..4 + length) else {
        return Ok(None);
    };
    if take(&mut body, 2)? != [3, 3] {
        return Err("invalid ClientHello legacy version");
    }
    take(&mut body, 32)?;
    let session_len = take(&mut body, 1)?[0] as usize;
    if session_len > 32 {
        return Err("invalid session id length");
    }
    take(&mut body, session_len)?;
    let ciphers = vector(&mut body)?;
    if ciphers.is_empty() || ciphers.len() % 2 != 0 {
        return Err("invalid cipher suites");
    }
    let compression_len = take(&mut body, 1)?[0] as usize;
    if take(&mut body, compression_len)? != [0] {
        return Err("invalid compression methods");
    }
    let mut extensions = vector(&mut body)?;
    if !body.is_empty() {
        return Err("trailing ClientHello bytes");
    }
    let mut name = None;
    while !extensions.is_empty() {
        let kind = u16_value(&mut extensions)?;
        let mut extension = vector(&mut extensions)?;
        if kind != 0 {
            continue;
        }
        if name.is_some() {
            return Err("duplicate server_name extension");
        }
        let mut names = vector(&mut extension)?;
        if !extension.is_empty() {
            return Err("invalid server_name extension length");
        }
        while !names.is_empty() {
            if take(&mut names, 1)?[0] != 0 {
                return Err("unsupported server name type");
            }
            if name.is_some() {
                return Err("duplicate host name");
            }
            let host = std::str::from_utf8(vector(&mut names)?)
                .map_err(|_| "invalid host name encoding")?;
            if host.len() > 253
                || !matches!(
                    qtls::ServerName::try_from(host),
                    Ok(qtls::ServerName::DnsName(_))
                )
            {
                return Err("invalid DNS server name");
            }
            name = Some(host);
        }
        if name.is_none() {
            return Err("empty server name list");
        }
    }
    name.map(Some).ok_or("ClientHello has no server name")
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], &'static str> {
    let (head, tail) = input
        .split_at_checked(length)
        .ok_or("truncated ClientHello field")?;
    *input = tail;
    Ok(head)
}

fn u16_value(input: &mut &[u8]) -> Result<u16, &'static str> {
    let bytes = take(input, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn vector<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], &'static str> {
    let length = u16_value(input)? as usize;
    take(input, length)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(name: &[u8], duplicate: bool) -> Vec<u8> {
        let mut sni = vec![0];
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        let mut extension = vec![0, 0];
        extension.extend_from_slice(&((sni.len() + 2) as u16).to_be_bytes());
        extension.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extension.extend(sni);
        if duplicate {
            extension.extend(extension.clone());
        }
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.extend([0, 0, 2, 0x13, 1, 1, 0]);
        body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        body.extend(extension);
        let mut output = vec![1];
        output.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        output.extend(body);
        output
    }

    #[test]
    fn fragmented_hello_waits_without_losing_the_original_bytes() {
        let bytes = hello(b"server.example", false);
        for n in 0..bytes.len() {
            assert_eq!(peek_server_name(&bytes[..n]), Ok(None));
        }
        assert_eq!(peek_server_name(&bytes), Ok(Some("server.example")));
        let mut with_next_message = bytes.clone();
        with_next_message.extend([2, 0, 0, 0]);
        assert_eq!(
            peek_server_name(&with_next_message),
            Ok(Some("server.example"))
        );
    }

    #[test]
    fn rejects_oversize_and_ambiguous_names_before_tls_allocation() {
        assert!(peek_server_name(&[1, 0xff, 0xff, 0xff]).is_err());
        assert!(peek_server_name(&[2]).is_err());
        assert!(peek_server_name(&hello(b"server.example", true)).is_err());
        for name in [b"".as_slice(), b"127.0.0.1", b"bad\0name", b"\xff"] {
            assert!(peek_server_name(&hello(name, false)).is_err());
        }
    }

    #[test]
    fn malformed_completed_messages_never_wait_for_more_bytes() {
        let bytes = hello(b"server.example", false);
        // Advertise each truncated body as complete: these are malformed, not fragments.
        for n in 4..bytes.len() {
            let mut shortened = bytes[..n].to_vec();
            shortened[1..4].copy_from_slice(&((n - 4) as u32).to_be_bytes()[1..]);
            assert!(peek_server_name(&shortened).is_err(), "length {n}");
        }
    }
}
