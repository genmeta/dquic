#![allow(dead_code)]

use std::sync::Arc;

use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    param::{ClientParameters, ParameterId, ServerParameters, WriteParameters},
};
use tls_backend::pki_types::pem::PemObject;

const CERT: &[u8] = include_bytes!("../keychain/localhost/server.cert");
const KEY: &[u8] = include_bytes!("../keychain/localhost/server.key");
const CA_CERT: &[u8] = include_bytes!("../keychain/localhost/ca.cert");
const CLIENT_CERT: &[u8] = include_bytes!("../keychain/localhost/client.cert");
const CLIENT_KEY: &[u8] = include_bytes!("../keychain/localhost/client.key");
const SERVER_OCSP: &[u8] = include_bytes!("../keychain/localhost/server.ocsp");
const CLIENT_OCSP: &[u8] = include_bytes!("../keychain/localhost/client.ocsp");

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
        authority: mutual.then(|| authority("client", CLIENT_CERT, CLIENT_KEY, CLIENT_OCSP)),
        resumption: qtls::ClientResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap();
    let server = qtls::TlsServer::new(qtls::ServerTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        authority: authority("localhost", CERT, KEY, SERVER_OCSP),
        resumption: qtls::ServerResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap();
    (client, server)
}

pub fn anonymous_client() -> qtls::TlsClient {
    set_roots();
    qtls::TlsClient::new(qtls::ClientTlsConfig {
        provider: Arc::new(qtls::default_provider()),
        alpn: vec![b"h3".to_vec()],
        authority: None,
        resumption: qtls::ClientResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap()
}

pub fn identity() -> Arc<qbase::endpoint::Endpoint> {
    set_roots();
    qbase::endpoint::Endpoint::new(
        "localhost",
        vec![qtls::CertificateDer::from_pem_slice(CERT).unwrap()],
        qtls::PrivateKeyDer::from_pem_slice(KEY).unwrap(),
        SERVER_OCSP.to_vec(),
    )
    .unwrap()
}

pub fn quic_endpoint() -> qconnection::QuicEndpoint {
    let (client_parameters, server_parameters) = parameters();
    let mut endpoint: qconnection::QuicEndpoint = identity().into();
    for (id, value) in client_parameters.iter() {
        endpoint
            .set_parameters(qbase::role::Role::Client, *id, value.clone())
            .unwrap();
    }
    for (id, value) in server_parameters.iter() {
        endpoint
            .set_parameters(qbase::role::Role::Server, *id, value.clone())
            .unwrap();
    }
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
    let mut c = ClientParameters::default();
    let mut s = ServerParameters::default();
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
    let mut frames = Vec::new();
    let packet = qconnection::send::Packet::new(header, pn, &mut buffer, &mut frames)?;
    let mut limits = qbase::packet::assemble::Constraints {
        flow_ctrl: usize::MAX,
        send_quota: 1200,
        credit: 1200,
        min_size: 1200,
        max_size: 1200,
        ..Default::default()
    };
    let mut packet = qconnection::send::Envelope {
        packet,
        keys,
        limits: &mut limits,
    };
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        matches!(packet.assemble(&mut cx, &mut sources.map(|source| source as &mut dyn qbase::packet::Package<&mut BytesMut>)), std::task::Poll::Ready(Ok(n)) if n > 0)
    );
    packet.seal()?;
    journal.on_sealed(
        pn.0,
        None,
        packet.packet.buffer.len(),
        packet.packet.meta,
        frames.drain(..),
    );
    Ok(buffer)
}

/// Tests that use localhost DNS opt in explicitly; mock-only tests do not call this.
pub fn use_system_resolver() {
    static REGISTER: std::sync::Once = std::sync::Once::new();
    REGISTER.call_once(|| qresolve::Resolver::add(Arc::new(qresolve::SystemResolver)));
}

/// Build an isolated connection for component tests without a live router.
pub fn initial_paths(
    role: qbase::role::Role,
    scid: ConnectionId,
    odcid: ConnectionId,
    keys: qtls::BidirectionalKeys,
) -> Arc<qconnection::Paths> {
    initial_paths_with_timeouts(
        role,
        scid,
        odcid,
        keys,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    )
}

pub fn initial_paths_with_timeouts(
    role: qbase::role::Role,
    scid: ConnectionId,
    odcid: ConnectionId,
    keys: qtls::BidirectionalKeys,
    max_idle_timeout: std::time::Duration,
    defer_idle_timeout: std::time::Duration,
) -> Arc<qconnection::Paths> {
    let reliable_frames = qconnection::ArcReliableFrames::with_capacity(0);
    let router = Arc::new(qtransport::router::QuicRouter::new());
    let (inbox, _) = qtransport::packet::channel::new();
    let local_cids = qconnection::ArcLocalCids::new(
        role,
        odcid,
        scid,
        router.registry_on_issuing_scid(inbox, reliable_frames.clone()),
    );
    qconnection::Paths::new(
        role,
        (scid, odcid),
        keys,
        reliable_frames,
        local_cids,
        max_idle_timeout,
        defer_idle_timeout,
    )
}

pub fn initial_phase(paths: &qconnection::Paths) -> Arc<qconnection::InitialPhase> {
    let qconnection::ConnPhase::Initial(initial) = paths.phase().get() else {
        panic!("expected Initial");
    };
    initial
}

/// A ready CID cell for component tests that do not run the connection lifecycle.
pub fn dcid(cid: ConnectionId) -> qbase::cid::ArcCidCell<qconnection::ArcReliableFrames> {
    let remote =
        qbase::cid::ArcRemoteCids::new(cid, 2, qconnection::ArcReliableFrames::with_capacity(0));
    remote.apply_dcid()
}

/// Initial packet keys shared by send, receive, and punch component tests.
pub fn initial_keys(server: bool) -> qtls::BidirectionalKeys {
    qtls::default_provider()
        .cipher_suites
        .iter()
        .find_map(|suite| suite.tls13().and_then(|suite| suite.quic_suite()))
        .unwrap()
        .keys(
            b"original",
            if server {
                tls_backend::Side::Server
            } else {
                tls_backend::Side::Client
            },
            tls_backend::quic::Version::V1,
        )
        .into()
}

/// An isolated connection with no paths or idle expiry for TLS task tests.
pub fn paths(
    role: qbase::role::Role,
) -> (
    Arc<qconnection::Paths>,
    qtransport::terminate::ArcTerminator,
) {
    let paths = initial_paths(
        role,
        ConnectionId::from_slice(b"local"),
        ConnectionId::from_slice(b"original"),
        initial_keys(role == qbase::role::Role::Server),
    );
    let terminator = paths.terminator.clone();
    (paths, terminator)
}

/// Records the notification delivered to a registered component.
#[derive(Default)]
pub struct CloseObserver(std::sync::Mutex<Option<qconnection::Error>>);

impl qbase::Close for CloseObserver {
    fn close_with_error(&self, error: qconnection::Error) {
        *self.0.lock().unwrap() = Some(error);
    }
}

impl CloseObserver {
    pub fn notified(&self) -> Option<qconnection::Error> {
        self.0.lock().unwrap().clone()
    }
}

pub fn observe_close(terminator: &qtransport::terminate::ArcTerminator) -> Arc<CloseObserver> {
    let observer = Arc::new(CloseObserver::default());
    terminator.register(observer.clone());
    observer
}

/// Hold receiver resources independently of the active sending queue in tests.
pub fn initial_space(
    spaces: &qtransport::space::ArcSpaces,
) -> Arc<qtransport::space::Space<qtransport::keys::ArcKeys>> {
    let initial = spaces
        .read()
        .unwrap()
        .get::<qtransport::space::InitialSpace>(qbase::Epoch::Initial)
        .unwrap();
    Arc::new(initial.space.clone())
}
