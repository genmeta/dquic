use std::sync::Arc;

use bytes::Bytes;
use tls_backend::pki_types::pem::PemObject;

const CERT: &[u8] = include_bytes!("../keychain/localhost/server.cert");
const KEY: &[u8] = include_bytes!("../keychain/localhost/server.key");
const CA_CERT: &[u8] = include_bytes!("../keychain/localhost/ca.cert");
const OCSP: &[u8] = include_bytes!("../keychain/localhost/server.ocsp");

fn tls_server(provider: Arc<qtls::CryptoProvider>, alpn: Vec<Vec<u8>>) -> qtls::TlsServer {
    qtls::RootCerts::set([qtls::CertificateDer::from_pem_slice(CA_CERT).unwrap()]).unwrap();
    let local = qtls::LocalAuthority::new(
        &provider,
        "localhost".into(),
        vec![qtls::CertificateDer::from_pem_slice(CERT).unwrap()],
        qtls::PrivateKeyDer::from_pem_slice(KEY).unwrap(),
        OCSP.to_vec(),
    )
    .unwrap();
    qtls::TlsServer::new(qtls::ServerTlsConfig {
        provider,
        alpn,
        authority: local,
        resumption: qtls::ServerResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap()
}

pub(crate) fn handshake() -> ([qtls::OneRttKeyMaterial; 2], [qtls::HandshakeSummary; 2]) {
    handshake_with(Arc::new(qtls::default_provider()))
}

pub fn handshake_with(
    provider: Arc<qtls::CryptoProvider>,
) -> ([qtls::OneRttKeyMaterial; 2], [qtls::HandshakeSummary; 2]) {
    qtls::RootCerts::set([qtls::CertificateDer::from_pem_slice(CA_CERT).unwrap()]).unwrap();
    let client = qtls::TlsClient::new(qtls::ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec(), b"ssh".to_vec()],
        authority: None,
        resumption: qtls::ClientResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap();
    let server = tls_server(provider, vec![b"ssh".to_vec(), b"h3".to_vec()]);
    let mut peers = [
        client
            .start(qtls::ClientStart {
                server_name: "localhost".try_into().unwrap(),
                quic_version: qtls::QuicVersion::V1,
                local_transport_parameters: Bytes::new(),
            })
            .unwrap(),
        server.start(qtls::QuicVersion::V1, Bytes::new()).unwrap(),
    ];
    let mut keys = [None, None];
    let mut summaries = [None, None];
    for _ in 0..16 {
        for i in 0..2 {
            while let Some(event) = peers[i].next_event() {
                match event {
                    qtls::TlsEvent::WriteCrypto {
                        epoch: level,
                        bytes,
                    } => peers[1 - i].receive_crypto(level, &bytes).unwrap(),
                    qtls::TlsEvent::InstallKeys(qtls::InstalledKeys::OneRtt(key)) => {
                        keys[i] = Some(key)
                    }
                    qtls::TlsEvent::HandshakeComplete(summary) => summaries[i] = Some(summary),
                    _ => {}
                }
            }
        }
        if summaries.iter().all(Option::is_some) {
            break;
        }
    }
    (keys.map(Option::unwrap), summaries.map(Option::unwrap))
}
