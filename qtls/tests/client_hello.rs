use std::sync::Arc;

use bytes::Bytes;
use qtls::{
    CertificateDer, ClientResumptionConfig, ClientStart, ClientTlsConfig, CryptoLevel,
    LocalAuthority, PrivateKeyDer, QuicVersion, RootCerts, ServerName, ServerResumptionConfig,
    ServerTlsConfig, TlsClient, TlsEvent, TlsServer, default_provider, incoming,
};
use rustls::pki_types::pem::PemObject;

const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");
const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
const SERVER_OCSP: &[u8] = include_bytes!("../../tests/keychain/localhost/server.ocsp");

fn client_hello() -> Bytes {
    RootCerts::set([CertificateDer::from_pem_slice(CA_CERT).unwrap()]).unwrap();
    let client = TlsClient::new(ClientTlsConfig {
        provider: Arc::new(default_provider()),
        alpn: vec![b"h3".to_vec()],
        local: None,
        resumption: ClientResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap();
    let mut tls = client
        .start(ClientStart {
            server_name: ServerName::try_from("one.example").unwrap().to_owned(),
            quic_version: QuicVersion::V1,
            local_transport_parameters: Bytes::from_static(b"client-parameters"),
        })
        .unwrap();
    let Some(TlsEvent::WriteCrypto { level, bytes }) = tls.next_event() else {
        panic!("client must emit ClientHello first")
    };
    assert_eq!(level, CryptoLevel::Initial);
    bytes
}

#[test]
fn fragmented_client_hello_is_preparsed_and_preserved() {
    let encoded = client_hello();
    for end in 0..encoded.len() {
        assert!(
            incoming::client_hello(&encoded[..end], encoded.len())
                .unwrap()
                .is_none()
        );
    }
    let parsed = incoming::client_hello(&encoded, encoded.len())
        .unwrap()
        .unwrap();
    assert_eq!(parsed.server_name(), Some("one.example"));
    assert_eq!(parsed.transport_parameters(), b"client-parameters");
    assert_eq!(parsed.encoded(), &encoded);
}

#[test]
fn encoded_client_hello_starts_the_selected_server() {
    let encoded = client_hello();
    let parsed = incoming::client_hello(&encoded, encoded.len())
        .unwrap()
        .unwrap();

    let provider = Arc::new(default_provider());
    let authority = LocalAuthority::new(
        &provider,
        Arc::from("one.example"),
        vec![CertificateDer::from_pem_slice(SERVER_CERT).unwrap()],
        PrivateKeyDer::from_pem_slice(SERVER_KEY).unwrap(),
        SERVER_OCSP.to_vec(),
    )
    .unwrap();
    let endpoint = TlsServer::new(ServerTlsConfig {
        provider,
        alpn: vec![b"h3".to_vec()],
        local: authority,
        resumption: ServerResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap();
    let mut server = endpoint
        .start(
            QuicVersion::V1,
            Bytes::from_static(b"selected-server-parameters"),
        )
        .unwrap();
    server
        .receive_crypto(CryptoLevel::Initial, parsed.encoded())
        .unwrap();

    let observed = std::iter::from_fn(|| server.next_event()).find_map(|event| match event {
        TlsEvent::ClientHello {
            server_name,
            transport_parameters,
        } => Some((server_name, transport_parameters)),
        _ => None,
    });
    let (server_name, transport_parameters) = observed.unwrap();
    assert_eq!(server_name.as_deref(), Some("one.example"));
    assert_eq!(transport_parameters, b"client-parameters".as_slice());
}

#[test]
fn declared_or_received_client_hello_cannot_exceed_the_limit() {
    let encoded = client_hello();

    assert!(
        incoming::client_hello(&encoded, encoded.len() - 1)
            .unwrap_err()
            .to_string()
            .contains("limit")
    );

    assert!(
        incoming::client_hello(&encoded[..4], 4)
            .unwrap_err()
            .to_string()
            .contains("limit")
    );
}

#[test]
fn quic_transport_parameters_are_required() {
    let mut encoded = client_hello().to_vec();
    let parameters = b"client-parameters";
    let offset = encoded
        .windows(parameters.len())
        .position(|window| window == parameters)
        .unwrap();
    assert_eq!(&encoded[offset - 4..offset - 2], &[0x00, 0x39]);
    encoded[offset - 4..offset - 2].copy_from_slice(&[0x12, 0x34]);

    assert!(
        incoming::client_hello(&encoded, encoded.len())
            .unwrap_err()
            .to_string()
            .contains("transport parameters")
    );
}
