use std::sync::Arc;

use qtls::{
    CertificateDer, Epoch, HandshakeSummary, PrivateKeyDer, TlsError, TlsEvent, TlsHandshake,
};

pub fn server_config(
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    ocsp: Vec<u8>,
) -> rustls::ServerConfig {
    let mut config =
        rustls::ServerConfig::builder_with_provider(Arc::new(qtls::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert_with_ocsp(vec![certificate], key, ocsp)
            .unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    config
}

// The backend peer can present credentials that LocalAuthority correctly refuses to construct.
// Only qtls errors are returned: a backend failure is an unexpected test setup failure.
pub fn drive(
    mut tls: TlsHandshake,
    mut peer: rustls::quic::Connection,
) -> Result<(HandshakeSummary, rustls::quic::Connection), TlsError> {
    let mut epoch = Epoch::Initial;
    let mut summary = None;
    for _ in 0..32 {
        let mut progressed = drain_peer(&mut peer, &mut tls, &mut epoch)?;
        while let Some(event) = tls.next_event() {
            progressed = true;
            match event {
                TlsEvent::WriteCrypto { bytes, .. } => {
                    peer.read_hs(&bytes).unwrap();
                    drain_peer(&mut peer, &mut tls, &mut epoch)?;
                }
                TlsEvent::HandshakeComplete(value) => {
                    assert!(summary.replace(value).is_none());
                }
                _ => {}
            }
        }
        // Drain post-handshake tickets before returning, so resumption storage is populated.
        if !progressed {
            assert!(tls.is_complete() && !peer.is_handshaking());
            return Ok((summary.unwrap(), peer));
        }
    }
    panic!("handshake did not complete");
}

fn drain_peer(
    peer: &mut rustls::quic::Connection,
    tls: &mut TlsHandshake,
    epoch: &mut Epoch,
) -> Result<bool, TlsError> {
    let mut progressed = false;
    loop {
        let mut bytes = Vec::new();
        let change = peer.write_hs(&mut bytes);
        if !bytes.is_empty() {
            progressed = true;
            if let Err(error) = tls.receive_crypto(*epoch, &bytes) {
                assert!(!tls.is_complete());
                while let Some(event) = tls.next_event() {
                    assert!(!matches!(event, TlsEvent::HandshakeComplete(_)));
                }
                return Err(error);
            }
        }
        match change {
            Some(rustls::quic::KeyChange::Handshake { .. }) => *epoch = Epoch::Handshake,
            Some(rustls::quic::KeyChange::OneRtt { .. }) => *epoch = Epoch::Data,
            None if bytes.is_empty() => return Ok(progressed),
            None => {}
        }
    }
}
