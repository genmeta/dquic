#![allow(dead_code)]

use std::sync::Arc;

use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    param::{
        ParameterId, WriteParameters,
        handy::{client_parameters, server_parameters},
    },
};
use tls_backend::pki_types::pem::PemObject;

const CERT: &[u8] = include_bytes!("../../../tests/keychain/localhost/server.cert");
const KEY: &[u8] = include_bytes!("../../../tests/keychain/localhost/server.key");
const CA_CERT: &[u8] = include_bytes!("../../../tests/keychain/localhost/ca.cert");
const CLIENT_CERT: &[u8] = include_bytes!("../../../tests/keychain/localhost/client.cert");
const CLIENT_KEY: &[u8] = include_bytes!("../../../tests/keychain/localhost/client.key");
const SERVER_OCSP: &[u8] = include_bytes!("../../../tests/keychain/localhost/server.ocsp");
const CLIENT_OCSP: &[u8] = include_bytes!("../../../tests/keychain/localhost/client.ocsp");

pub fn endpoints(mutual: bool) -> (qtls::TlsClient, qtls::TlsServer) {
    set_roots();
    let provider = Arc::new(qtls::default_provider());
    let authority = |name, cert, key, ocsp: &[u8]| {
        qtls::LocalAuthority::new(
            &provider,
            Arc::from(name),
            vec![qtls::CertificateDer::from_pem_slice(cert).unwrap()],
            qtls::PrivateKeyDer::from_pem_slice(key).unwrap(),
            ocsp.to_vec(),
        )
        .unwrap()
    };
    let client = qtls::TlsClient::new(qtls::ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: mutual.then(|| authority("client", CLIENT_CERT, CLIENT_KEY, CLIENT_OCSP)),
        resumption: qtls::ClientResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap();
    let server = qtls::TlsServer::new(qtls::ServerTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: authority("localhost", CERT, KEY, SERVER_OCSP),
        resumption: qtls::ServerResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap();
    (client, server)
}

pub fn client_without_alpn() -> qtls::TlsClient {
    set_roots();
    qtls::TlsClient::new(qtls::ClientTlsConfig {
        provider: Arc::new(qtls::default_provider()),
        alpn: Vec::new(),
        local: None,
        resumption: qtls::ClientResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap()
}

pub fn quic_endpoint() -> qconnection::QuicEndpoint {
    set_roots();
    let provider = qtls::default_provider();
    let identity = qbase::endpoint::Endpoint::new(
        &provider,
        "localhost",
        vec![qtls::CertificateDer::from_pem_slice(CERT).unwrap()],
        qtls::PrivateKeyDer::from_pem_slice(KEY).unwrap(),
        SERVER_OCSP.to_vec(),
    )
    .unwrap();
    let (client_parameters, server_parameters) = parameters();
    let mut endpoint = qconnection::QuicEndpoint::new(identity);
    endpoint.client_parameters = client_parameters;
    endpoint.server_parameters = server_parameters;
    endpoint
}

fn set_roots() {
    qtls::RootCerts::set([qtls::CertificateDer::from_pem_slice(CA_CERT).unwrap()]).unwrap();
}

#[allow(dead_code)]
pub fn backends(mutual: bool) -> [qtls::TlsHandshake; 2] {
    let (client, server) = endpoints(mutual);
    let (c, s) = parameters();
    let mut cb = BytesMut::new();
    cb.put_parameters(&c);
    let mut sb = BytesMut::new();
    sb.put_parameters(&s);
    [
        client
            .start(qtls::ClientStart {
                server_name: "localhost".try_into().unwrap(),
                quic_version: qtls::QuicVersion::V1,
                local_transport_parameters: cb.freeze(),
            })
            .unwrap(),
        server.start(qtls::QuicVersion::V1, sb.freeze()).unwrap(),
    ]
}

pub fn parameters() -> (
    qbase::param::ClientParameters,
    qbase::param::ServerParameters,
) {
    let mut c = client_parameters();
    let mut s = server_parameters();
    c.set(
        ParameterId::InitialSourceConnectionId,
        ConnectionId::from_slice(b"client00"),
    )
    .unwrap();
    s.set(
        ParameterId::InitialSourceConnectionId,
        ConnectionId::from_slice(b"server00"),
    )
    .unwrap();
    s.set(
        ParameterId::OriginalDestinationConnectionId,
        ConnectionId::from_slice(b"original"),
    )
    .unwrap();
    (c, s)
}

pub fn seal<H, const N: usize>(
    header: H,
    keys: &qtls::DirectionalKeys,
    journal: &qrecovery::journal::ArcSentJournal,
    sources: [&mut dyn for<'b> qbase::packet::assemble::Package<&'b mut BytesMut>; N],
) -> Result<BytesMut, qbase::error::Error>
where
    H: qbase::packet::HeaderSize + qbase::packet::GetType,
    for<'a> &'a mut BytesMut: qbase::packet::header::io::WriteHeader<H>,
{
    use qbase::packet::assemble::Assemble;
    let mut buffer = BytesMut::with_capacity(1200);
    let pn = journal.next_pn().unwrap();
    let packet = qconnection::send::Packet::new(header, pn, &mut buffer)?;
    let mut limits = qbase::packet::assemble::Constraints {
        flow_ctrl: usize::MAX,
        send_quota: 1200,
        credit: 1200,
        min_size: 1200,
        max_size: 1200,
        ..Default::default()
    };
    let mut packet = qconnection::send::SendingPacket {
        packet,
        keys,
        limits: &mut limits,
    };
    let mut frames = Vec::new();
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        matches!(packet.assemble(&mut cx, sources.map(|source| source as &mut dyn qbase::packet::Package<&mut BytesMut>), &mut frames), std::task::Poll::Ready(Ok(n)) if n > 0)
    );
    packet.seal()?;
    journal.on_assembled(pn.0, None, frames.drain(..));
    Ok(buffer)
}

/// Tests that use localhost DNS opt in explicitly; mock-only tests do not call this.
pub fn use_system_resolver() {
    static REGISTER: std::sync::Once = std::sync::Once::new();
    REGISTER.call_once(|| qresolve::Resolver::add(Arc::new(qresolve::SystemResolver)));
}
