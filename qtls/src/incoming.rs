//! Stateless inspection of contiguous Initial-level TLS input.

use std::sync::Arc;

use bytes::Bytes;

use crate::{PeerTlsError, ServerName, TlsError};

const CLIENT_HELLO: u8 = 1;
const SERVER_NAME: u16 = 0;
const QUIC_TRANSPORT_PARAMETERS: u16 = 0x39;
const HANDSHAKE_HEADER_LEN: usize = 4;

/// Routing facts and the exact TLS encoding of one complete ClientHello.
#[derive(Clone, Debug)]
pub struct ClientHello {
    server_name: Option<Arc<str>>,
    transport_parameters: Bytes,
    encoded: Bytes,
}

impl ClientHello {
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    pub fn transport_parameters(&self) -> &[u8] {
        &self.transport_parameters
    }

    pub fn encoded(&self) -> &Bytes {
        &self.encoded
    }
}

/// Inspect contiguous Initial CRYPTO bytes without starting a TLS connection.
///
/// Incomplete input returns `Ok(None)`. A complete ClientHello is copied once so
/// the caller can pass it to the selected server TLS connection.
pub fn client_hello(bytes: &[u8], max_bytes: usize) -> Result<Option<ClientHello>, TlsError> {
    if bytes.len() > max_bytes {
        return Err(resource_limit(max_bytes));
    }
    if bytes.len() < HANDSHAKE_HEADER_LEN {
        return Ok(None);
    }
    if bytes[0] != CLIENT_HELLO {
        return Err(protocol_error(
            "first TLS handshake message is not ClientHello",
        ));
    }
    let body_len = usize::from(bytes[1]) << 16 | usize::from(bytes[2]) << 8 | usize::from(bytes[3]);
    let encoded_len = HANDSHAKE_HEADER_LEN + body_len;
    if encoded_len > max_bytes {
        return Err(resource_limit(max_bytes));
    }
    if bytes.len() < encoded_len {
        return Ok(None);
    }
    if bytes.len() != encoded_len {
        return Err(protocol_error(
            "unexpected Initial CRYPTO data after ClientHello",
        ));
    }

    parse(Bytes::copy_from_slice(bytes)).map(Some)
}

fn parse(encoded: Bytes) -> Result<ClientHello, TlsError> {
    let mut hello = Reader::new(&encoded[HANDSHAKE_HEADER_LEN..]);
    hello.take(2, "legacy version")?;
    hello.take(32, "random")?;
    hello.vector_u8("legacy session ID")?;
    let cipher_suites = hello.vector_u16("cipher suites")?;
    if cipher_suites.is_empty() || cipher_suites.len() % 2 != 0 {
        return Err(protocol_error("invalid ClientHello cipher suites"));
    }
    if hello.vector_u8("legacy compression methods")?.is_empty() {
        return Err(protocol_error(
            "ClientHello has no legacy compression method",
        ));
    }
    let extensions = hello.vector_u16("extensions")?;
    hello.finish("trailing ClientHello bytes")?;

    let mut extensions = Reader::new(extensions);
    let mut saw_server_name = false;
    let mut server_name = None;
    let mut transport_parameters = None;
    while !extensions.is_empty() {
        let extension_type = extensions.u16("extension type")?;
        let extension = extensions.vector_u16("extension")?;
        match extension_type {
            SERVER_NAME => {
                if saw_server_name {
                    return Err(protocol_error(
                        "duplicate ClientHello server_name extension",
                    ));
                }
                saw_server_name = true;
                server_name = parse_server_name(extension)?;
            }
            QUIC_TRANSPORT_PARAMETERS => {
                if transport_parameters.is_some() {
                    return Err(protocol_error(
                        "duplicate QUIC transport parameters extension",
                    ));
                }
                transport_parameters = Some(Bytes::copy_from_slice(extension));
            }
            _ => {}
        }
    }
    let Some(transport_parameters) = transport_parameters else {
        return Err(protocol_error(
            "ClientHello is missing QUIC transport parameters",
        ));
    };

    Ok(ClientHello {
        server_name,
        transport_parameters,
        encoded,
    })
}

fn parse_server_name(extension: &[u8]) -> Result<Option<Arc<str>>, TlsError> {
    let mut extension = Reader::new(extension);
    let names = extension.vector_u16("server name list")?;
    extension.finish("trailing server_name extension bytes")?;
    if names.is_empty() {
        return Err(protocol_error("ClientHello server name list is empty"));
    }

    let mut names = Reader::new(names);
    let mut server_name = None;
    while !names.is_empty() {
        let name_type = names.u8("server name type")?;
        let name = names.vector_u16("server name")?;
        if name_type != 0 {
            continue;
        }
        if server_name.is_some() {
            return Err(protocol_error("duplicate ClientHello host_name"));
        }
        let name = std::str::from_utf8(name)
            .map_err(|_| protocol_error("ClientHello host_name is not UTF-8"))?;
        let name = ServerName::try_from(name.to_owned())
            .map_err(|_| protocol_error("ClientHello host_name is not a valid DNS name"))?;
        let ServerName::DnsName(name) = name else {
            return Err(protocol_error("ClientHello host_name is not a DNS name"));
        };
        server_name = Some(Arc::from(name.as_ref()));
    }
    Ok(server_name)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], TlsError> {
        let Some(end) = self.offset.checked_add(len) else {
            return Err(protocol_error(format!(
                "invalid ClientHello {field} length"
            )));
        };
        let Some(value) = self.bytes.get(self.offset..end) else {
            return Err(protocol_error(format!("truncated ClientHello {field}")));
        };
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, TlsError> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, TlsError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn vector_u8(&mut self, field: &'static str) -> Result<&'a [u8], TlsError> {
        let len = usize::from(self.u8(field)?);
        self.take(len, field)
    }

    fn vector_u16(&mut self, field: &'static str) -> Result<&'a [u8], TlsError> {
        let len = usize::from(self.u16(field)?);
        self.take(len, field)
    }

    fn finish(&self, message: &'static str) -> Result<(), TlsError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(protocol_error(message))
        }
    }
}

fn protocol_error(reason: impl Into<String>) -> TlsError {
    PeerTlsError::Protocol(reason.into()).into()
}

fn resource_limit(limit: usize) -> TlsError {
    PeerTlsError::ResourceLimit {
        resource: "ClientHello bytes",
        limit,
    }
    .into()
}
