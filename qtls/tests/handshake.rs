use std::sync::Arc;

use bytes::Bytes;
use qtls::{
    CertificateDer, ClientResumptionConfig, ClientStart, ClientTlsConfig, CryptoLevel,
    HandshakeSummary, InstalledKeys, LocalAuthority, MemoryResumptionStore, OneRttKeyMaterial,
    PrivateKeyDer, QuicVersion, RootCerts, ServerResumptionConfig, ServerTlsConfig,
    SessionSealKeyRing, SignatureScheme, TicketKeyRing, TlsClient, TlsEvent, TlsHandshake,
    TlsLimits, TlsServer, default_provider as crypto_provider,
};
use rustls::pki_types::pem::PemObject;

const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");
const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
const CLIENT_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/client.cert");
const CLIENT_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/client.key");
const SERVER_OCSP: &[u8] = include_bytes!("../../tests/keychain/localhost/server.ocsp");
const SERVER_REVOKED_OCSP: &[u8] =
    include_bytes!("../../tests/keychain/localhost/server-revoked.ocsp");
const CLIENT_OCSP: &[u8] = include_bytes!("../../tests/keychain/localhost/client.ocsp");

fn ticket_key_ring() -> TicketKeyRing {
    #[cfg(feature = "aws-lc-rs")]
    let ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().unwrap();
    #[cfg(not(feature = "aws-lc-rs"))]
    let ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
    TicketKeyRing::new(ticketer)
}

struct Observed {
    summary: Option<HandshakeSummary>,
    parameters: Option<Bytes>,
    server_name: Option<Option<Arc<str>>>,
    handshake_keys: bool,
    one_rtt: Option<OneRttKeyMaterial>,
    zero_rtt: bool,
}

impl Observed {
    fn new() -> Self {
        Self {
            summary: None,
            parameters: None,
            server_name: None,
            handshake_keys: false,
            one_rtt: None,
            zero_rtt: false,
        }
    }
}

#[test]
fn mutual_auth_publishes_both_authorities() {
    set_roots();
    let provider = Arc::new(crypto_provider());
    let server_authority = authority(&provider, "localhost", SERVER_CERT, SERVER_KEY, SERVER_OCSP);
    let client_authority = authority(&provider, "client", CLIENT_CERT, CLIENT_KEY, CLIENT_OCSP);

    let client = TlsClient::new(ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: Some(client_authority),
        resumption: ClientResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })
    .unwrap();
    let server = TlsServer::new(ServerTlsConfig {
        provider,
        alpn: vec![b"h3".to_vec()],
        local: server_authority,
        resumption: ServerResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })
    .unwrap();

    let (client_tls, server_tls, mut client_events, mut server_events) =
        handshake(&client, &server).unwrap();

    assert_eq!(
        client_events.parameters.as_deref(),
        Some(b"server-params".as_slice())
    );
    assert_eq!(
        server_events.parameters.as_deref(),
        Some(b"client-params".as_slice())
    );
    assert_eq!(
        server_events.server_name.flatten().as_deref(),
        Some("localhost")
    );
    assert!(client_events.handshake_keys && server_events.handshake_keys);
    assert!(!client_events.zero_rtt && !server_events.zero_rtt);

    let client_summary = client_events.summary.take().unwrap();
    assert_eq!(client_summary.alpn.as_deref(), Some(b"h3".as_slice()));
    assert_eq!(client_summary.local.as_ref().unwrap().name(), "client");
    assert_eq!(client_summary.remote.as_ref().unwrap().name(), "localhost");
    let server_summary = server_events.summary.take().unwrap();
    assert_eq!(server_summary.local.as_ref().unwrap().name(), "localhost");
    assert_eq!(server_summary.remote.as_ref().unwrap().name(), "client");

    test_updated_packet_keys(
        client_events.one_rtt.take().unwrap(),
        server_events.one_rtt.take().unwrap(),
    );

    let client_tls = client_tls.finish().unwrap();
    let server_tls = server_tls.finish().unwrap();
    let mut client_export = [0u8; 32];
    let mut server_export = [0u8; 32];
    client_tls
        .export_keying_material(&mut client_export, b"qtls test", Some(b"context"))
        .unwrap();
    server_tls
        .export_keying_material(&mut server_export, b"qtls test", Some(b"context"))
        .unwrap();
    assert_eq!(client_export, server_export);
}

#[test]
fn anonymous_client_completes_without_remote_authority() {
    set_roots();
    let provider = Arc::new(crypto_provider());
    let server_authority = authority(&provider, "localhost", SERVER_CERT, SERVER_KEY, SERVER_OCSP);
    let client = TlsClient::new(ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: None,
        resumption: ClientResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })
    .unwrap();
    let server = TlsServer::new(ServerTlsConfig {
        provider,
        alpn: vec![b"h3".to_vec()],
        local: server_authority,
        resumption: ServerResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })
    .unwrap();

    let (_, _, client_events, server_events) = handshake(&client, &server).unwrap();
    assert!(client_events.summary.unwrap().local.is_none());
    assert!(server_events.summary.unwrap().remote.is_none());
}

#[test]
fn server_certificate_requires_current_matching_good_ocsp() {
    set_roots();
    let provider = Arc::new(crypto_provider());
    let client = TlsClient::new(ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: None,
        resumption: ClientResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })
    .unwrap();

    assert!(
        LocalAuthority::new(
            &provider,
            "localhost".into(),
            vec![CertificateDer::from_pem_slice(SERVER_CERT).unwrap()],
            PrivateKeyDer::from_pem_slice(SERVER_KEY).unwrap(),
            Vec::new(),
        )
        .is_err()
    );

    for ocsp in [CLIENT_OCSP, SERVER_REVOKED_OCSP] {
        let server = TlsServer::new(ServerTlsConfig {
            provider: provider.clone(),
            alpn: vec![b"h3".to_vec()],
            local: authority(&provider, "localhost", SERVER_CERT, SERVER_KEY, ocsp),
            resumption: ServerResumptionConfig::Disabled,
            limits: TlsLimits::default(),
        })
        .unwrap();
        assert!(handshake(&client, &server).is_err());
    }

    let mut invalid_signature = SERVER_OCSP.to_vec();
    let signature = invalid_signature
        .windows(3)
        .position(|bytes| bytes == [0x03, 0x48, 0x00])
        .unwrap()
        + 3;
    invalid_signature[signature] ^= 1;
    let server = TlsServer::new(ServerTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: authority(
            &provider,
            "localhost",
            SERVER_CERT,
            SERVER_KEY,
            &invalid_signature,
        ),
        resumption: ServerResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })
    .unwrap();
    assert!(handshake(&client, &server).is_err());
}

#[test]
fn presented_client_certificate_requires_matching_ocsp() {
    set_roots();
    let provider = Arc::new(crypto_provider());

    assert!(
        LocalAuthority::new(
            &provider,
            "client".into(),
            vec![CertificateDer::from_pem_slice(CLIENT_CERT).unwrap()],
            PrivateKeyDer::from_pem_slice(CLIENT_KEY).unwrap(),
            Vec::new(),
        )
        .is_err()
    );

    let client = TlsClient::new(ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: Some(authority(
            &provider,
            "client",
            CLIENT_CERT,
            CLIENT_KEY,
            SERVER_OCSP,
        )),
        resumption: ClientResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })
    .unwrap();
    let server = TlsServer::new(ServerTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: authority(&provider, "localhost", SERVER_CERT, SERVER_KEY, SERVER_OCSP),
        resumption: ServerResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })
    .unwrap();
    assert!(handshake(&client, &server).is_err());
}

#[test]
fn stateful_resumption_restores_authorities_without_revalidating_the_certificate() {
    set_roots();
    let provider = Arc::new(crypto_provider());
    let store = Arc::new(MemoryResumptionStore::new(16));
    let client_seal_keys = Arc::new(SessionSealKeyRing::new(7, [0x17; 32]));
    let server_seal_keys = Arc::new(SessionSealKeyRing::new(9, [0x29; 32]));

    let client = TlsClient::new(ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: Some(authority(
            &provider,
            "client",
            CLIENT_CERT,
            CLIENT_KEY,
            CLIENT_OCSP,
        )),
        resumption: ClientResumptionConfig::Enabled {
            namespace: Arc::from("integration-test"),
            store: store.clone(),
            seal_keys: client_seal_keys,
        },
        limits: TlsLimits::default(),
    })
    .unwrap();
    let server = TlsServer::new(ServerTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: authority(&provider, "localhost", SERVER_CERT, SERVER_KEY, SERVER_OCSP),
        resumption: ServerResumptionConfig::Stateful {
            namespace: Arc::from("integration-test"),
            store,
            seal_keys: server_seal_keys,
        },
        limits: TlsLimits::default(),
    })
    .unwrap();

    let (_, _, first_client, first_server) = handshake(&client, &server).unwrap();
    assert_eq!(
        first_client.summary.unwrap().remote.unwrap().name(),
        "localhost"
    );
    assert_eq!(
        first_server.summary.unwrap().remote.unwrap().name(),
        "client"
    );

    let (_, _, second_client, second_server) = handshake(&client, &server).unwrap();
    let second_client_summary = second_client.summary.unwrap();
    assert_eq!(second_client_summary.local.unwrap().name(), "client");
    assert_eq!(second_client_summary.remote.unwrap().name(), "localhost");
    assert_eq!(
        second_server.summary.unwrap().remote.unwrap().name(),
        "client"
    );

    let fallback_server = TlsServer::new(ServerTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: authority(&provider, "localhost", SERVER_CERT, SERVER_KEY, SERVER_OCSP),
        resumption: ServerResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })
    .unwrap();
    let (_, _, fallback_client, fallback_server) = handshake(&client, &fallback_server).unwrap();
    let fallback_client = fallback_client.summary.unwrap();
    assert_eq!(fallback_client.local.unwrap().name(), "client");
    assert_eq!(fallback_client.remote.unwrap().name(), "localhost");
    assert_eq!(
        fallback_server.summary.unwrap().remote.unwrap().name(),
        "client"
    );
}

#[test]
fn stateless_resumption_restores_the_verified_client_authority() {
    set_roots();
    let provider = Arc::new(crypto_provider());
    let client = TlsClient::new(ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: Some(authority(
            &provider,
            "client",
            CLIENT_CERT,
            CLIENT_KEY,
            CLIENT_OCSP,
        )),
        resumption: ClientResumptionConfig::Enabled {
            namespace: Arc::from("stateless-test"),
            store: Arc::new(MemoryResumptionStore::new(8)),
            seal_keys: Arc::new(SessionSealKeyRing::new(1, [0x31; 32])),
        },
        limits: TlsLimits::default(),
    })
    .unwrap();
    let server = TlsServer::new(ServerTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: authority(&provider, "localhost", SERVER_CERT, SERVER_KEY, SERVER_OCSP),
        resumption: ServerResumptionConfig::Stateless {
            ticket_keys: Arc::new(ticket_key_ring()),
        },
        limits: TlsLimits::default(),
    })
    .unwrap();

    handshake(&client, &server).unwrap();
    let (_, _, client_events, server_events) = handshake(&client, &server).unwrap();

    let client_summary = client_events.summary.unwrap();
    assert_eq!(client_summary.local.unwrap().name(), "client");
    assert_eq!(client_summary.remote.unwrap().name(), "localhost");
    assert_eq!(
        server_events.summary.unwrap().remote.unwrap().name(),
        "client"
    );
}

#[test]
fn initial_keys_interoperate_for_v1_and_v2() {
    set_roots();
    let provider = Arc::new(crypto_provider());
    let client = TlsClient::new(ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: None,
        resumption: ClientResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })
    .unwrap();
    let server = TlsServer::new(ServerTlsConfig {
        provider,
        alpn: vec![b"h3".to_vec()],
        local: authority(
            &Arc::new(crypto_provider()),
            "localhost",
            SERVER_CERT,
            SERVER_KEY,
            SERVER_OCSP,
        ),
        resumption: ServerResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })
    .unwrap();

    for version in [QuicVersion::V1, QuicVersion::V2] {
        let client_keys = client.initial_keys(version, b"destination cid").unwrap();
        let server_keys = server.initial_keys(version, b"destination cid").unwrap();
        test_direction(&client_keys.sealing.packet, &server_keys.opening.packet);

        let sample = [7u8; 16];
        let mut first = 0xc3;
        let original_first = first;
        let mut packet_number = [1, 2, 3];
        let original_packet_number = packet_number;
        client_keys
            .sealing
            .header
            .protect(&sample, &mut first, &mut packet_number)
            .unwrap();
        server_keys
            .opening
            .header
            .unprotect(&sample, &mut first, &mut packet_number)
            .unwrap();
        assert_eq!(first, original_first);
        assert_eq!(packet_number, original_packet_number);
    }
}

#[test]
fn wrong_crypto_level_is_rejected_but_empty_input_is_a_noop() {
    set_roots();
    let provider = Arc::new(crypto_provider());
    let client = TlsClient::new(ClientTlsConfig {
        provider,
        alpn: vec![b"h3".to_vec()],
        local: None,
        resumption: ClientResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })
    .unwrap();
    let mut handshake = client
        .start(ClientStart {
            server_name: "localhost".try_into().unwrap(),
            quic_version: QuicVersion::V1,
            local_transport_parameters: Bytes::new(),
        })
        .unwrap();

    handshake
        .receive_crypto(CryptoLevel::Handshake, &[])
        .unwrap();
    let error = handshake
        .receive_crypto(CryptoLevel::Handshake, &[1])
        .unwrap_err();
    assert!(error.to_string().contains("expected Initial"));
    let terminal = handshake
        .receive_crypto(CryptoLevel::Initial, &[1])
        .unwrap_err();
    assert!(terminal.to_string().contains("terminal state"));
}

fn set_roots() {
    RootCerts::set([CertificateDer::from_pem_slice(CA_CERT).unwrap()]).unwrap();
}

fn authority(
    provider: &rustls::crypto::CryptoProvider,
    name: &str,
    certificate_pem: &[u8],
    key_pem: &[u8],
    ocsp: &[u8],
) -> LocalAuthority {
    let certificate = CertificateDer::from_pem_slice(certificate_pem).unwrap();
    let key = PrivateKeyDer::from_pem_slice(key_pem).unwrap();
    LocalAuthority::new(
        provider,
        Arc::from(name),
        vec![certificate],
        key,
        ocsp.to_vec(),
    )
    .unwrap()
}

fn handshake(
    client: &TlsClient,
    server: &TlsServer,
) -> Result<(TlsHandshake, TlsHandshake, Observed, Observed), qtls::TlsError> {
    let mut client = client.start(ClientStart {
        server_name: "localhost".try_into().unwrap(),
        quic_version: QuicVersion::V1,
        local_transport_parameters: Bytes::from_static(b"client-params"),
    })?;
    let mut server = server.start(QuicVersion::V1, Bytes::from_static(b"server-params"))?;
    let mut client_events = Observed::new();
    let mut server_events = Observed::new();

    for _ in 0..16 {
        let progressed = transfer(&mut client, &mut server, &mut client_events)?
            | transfer(&mut server, &mut client, &mut server_events)?;
        if client.is_complete() && server.is_complete() {
            transfer(&mut client, &mut server, &mut client_events)?;
            transfer(&mut server, &mut client, &mut server_events)?;
            return Ok((client, server, client_events, server_events));
        }
        assert!(progressed, "handshake made no progress");
    }
    panic!("handshake did not complete");
}

fn transfer(
    sender: &mut TlsHandshake,
    receiver: &mut TlsHandshake,
    observed: &mut Observed,
) -> Result<bool, qtls::TlsError> {
    let mut progressed = false;
    while let Some(event) = sender.next_event() {
        progressed = true;
        match event {
            TlsEvent::WriteCrypto { level, bytes } => {
                for chunk in bytes.chunks(7) {
                    receiver.receive_crypto(level, chunk)?;
                }
            }
            TlsEvent::InstallKeys(InstalledKeys::ZeroRtt(_)) => observed.zero_rtt = true,
            TlsEvent::InstallKeys(InstalledKeys::Handshake(_)) => observed.handshake_keys = true,
            TlsEvent::InstallKeys(InstalledKeys::OneRtt(keys)) => observed.one_rtt = Some(keys),
            TlsEvent::ClientHello {
                server_name,
                transport_parameters,
            } => {
                observed.server_name = Some(server_name);
                observed.parameters = Some(transport_parameters);
            }
            TlsEvent::ServerTransportParameters(parameters) => {
                observed.parameters = Some(parameters)
            }
            TlsEvent::HandshakeComplete(summary) => observed.summary = Some(summary),
            TlsEvent::Alert(_) => {}
        }
    }
    Ok(progressed)
}

fn test_updated_packet_keys(mut client: OneRttKeyMaterial, mut server: OneRttKeyMaterial) {
    test_direction(&client.packet.sealing, &server.packet.opening);
    test_direction(&server.packet.sealing, &client.packet.opening);
    for _ in 0..3 {
        let client_keys = client.next_secret.next_packet_keys();
        let server_keys = server.next_secret.next_packet_keys();
        test_direction(&client_keys.sealing, &server_keys.opening);
        test_direction(&server_keys.sealing, &client_keys.opening);
    }
}

fn test_direction(sealing: &qtls::PacketKey, opening: &qtls::PacketKey) {
    let header = b"header";
    let plaintext = b"protected payload";
    let mut payload = plaintext.to_vec();
    let mut tag = vec![0; sealing.tag_len()];
    sealing.seal(42, header, &mut payload, &mut tag).unwrap();
    payload.extend_from_slice(&tag);
    let opened = opening.open(42, header, &mut payload).unwrap();
    assert_eq!(opened, plaintext);
}

#[test]
fn authority_signs_without_exposing_the_signing_key() {
    let provider = crypto_provider();
    let authority = authority(&provider, "localhost", SERVER_CERT, SERVER_KEY, SERVER_OCSP);
    let signature = authority
        .sign(SignatureScheme::ECDSA_NISTP256_SHA256, b"message")
        .unwrap();
    assert!(!signature.is_empty());
    assert!(
        authority
            .sign(SignatureScheme::ED25519, b"message")
            .is_err()
    );
}
