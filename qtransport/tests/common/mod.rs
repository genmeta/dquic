#![allow(dead_code)]

#[path = "../support/open.rs"]
pub mod opening;

use std::sync::Arc;

use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    packet::PacketContent,
    param::{ClientParameters, ParameterId, ServerParameters, WriteParameters},
};
use tls_backend::pki_types::pem::PemObject;

const CERT: &[u8] = include_bytes!("../../../qconnection/tests/keychain/localhost/server.cert");
const KEY: &[u8] = include_bytes!("../../../qconnection/tests/keychain/localhost/server.key");
const CA_CERT: &[u8] = include_bytes!("../../../qconnection/tests/keychain/localhost/ca.cert");
const CLIENT_CERT: &[u8] = include_bytes!("../../../qconnection/tests/keychain/localhost/client.cert");
const CLIENT_KEY: &[u8] = include_bytes!("../../../qconnection/tests/keychain/localhost/client.key");
const SERVER_OCSP: &[u8] = include_bytes!("../../../qconnection/tests/keychain/localhost/server.ocsp");
const CLIENT_OCSP: &[u8] = include_bytes!("../../../qconnection/tests/keychain/localhost/client.ocsp");

/// Construct component-test paths without starting a competing sending task.
pub fn registered_path(paths: &qtransport::Paths, path: qtransport::path::Path) -> Arc<qtransport::path::Path> {
    let path = Arc::new(path);
    paths.entries.lock().unwrap().insert(path.pathway, path.clone());
    path
}

pub fn path_credit(path: &qtransport::path::Path) -> Option<usize> {
    path.validation.credit().unwrap()
}

pub fn packet_metadata(packets: &[qbase::packet::assemble::Metadata], epoch: qbase::Epoch) -> Option<qbase::packet::assemble::Metadata> {
    packets.iter().find(|meta| meta.epoch() == epoch).copied()
}

pub fn space_epochs(spaces: &qtransport::space::ArcSpaces) -> Vec<qbase::Epoch> {
    qbase::Epoch::EPOCHS.into_iter().filter(|&epoch| spaces.get(epoch).is_some()).collect()
}

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

pub fn parameters() -> (qbase::param::ClientParameters, qbase::param::ServerParameters) {
    let mut c = ClientParameters::default();
    let mut s = ServerParameters::default();
    c.set(ParameterId::InitialSourceConnectionId, ConnectionId::from_slice(b"client00")).unwrap();
    s.set(ParameterId::InitialSourceConnectionId, ConnectionId::from_slice(b"server00")).unwrap();
    s.set(ParameterId::OriginalDestinationConnectionId, ConnectionId::from_slice(b"original")).unwrap();
    (c, s)
}

pub fn seal<H, const N: usize>(
    header: H,
    keys: &qtls::DirectionalKeys,
    journal: &qrecovery::journal::ArcSentJournal,
    sources: [&mut dyn for<'b> qbase::packet::assemble::Package<&'b mut [u8]>; N],
) -> Result<BytesMut, qbase::error::Error>
where
    H: qbase::packet::HeaderSize + qbase::packet::GetType + Into<qbase::packet::long::DataHeader>,
    for<'a> &'a mut BytesMut: qbase::packet::header::io::WriteHeader<H>,
{
    let mut buffer = BytesMut::zeroed(1200);
    let pn = journal.next_pn().unwrap();
    let mut frames = Vec::new();
    let mut packet = qtransport::send::Packet::new(qbase::packet::DataHeader::Long(header.into()), pn, keys);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        matches!(packet.assemble(&mut cx, &mut std::io::Cursor::new(buffer.as_mut()), 1200, PacketContent::EffectivePayload, &mut frames, &mut sources.map(|source| source as &mut dyn qbase::packet::Package<&mut [u8]>)), std::task::Poll::Ready((n, _)) if n > 0)
    );
    buffer.resize(1200, 0);
    packet.padding(&mut buffer, 1200 - packet.len());
    packet.seal(&mut buffer);
    journal.on_sealed(pn.0, None, buffer.len(), packet.meta, frames.drain(..));
    Ok(buffer)
}

pub fn handshake_facts(role: qbase::role::Role, multipath: bool) -> Arc<qbase::handshake::HandshakeFacts> {
    let facts = Arc::new(qbase::handshake::HandshakeFacts::with_role(role));
    if !multipath {
        facts.quit_mp_replaying();
    }
    facts
}

/// Build an isolated connection for component tests without a live router.
pub fn initial_paths(
    role: qbase::role::Role,
    scid: ConnectionId,
    odcid: ConnectionId,
    keys: qtls::BidirectionalKeys,
) -> Arc<qtransport::Paths> {
    initial_paths_with_timeouts(role, scid, odcid, keys, std::time::Duration::ZERO, std::time::Duration::ZERO, handshake_facts(role, true))
}

pub fn initial_paths_with_timeouts(
    role: qbase::role::Role,
    scid: ConnectionId,
    odcid: ConnectionId,
    keys: qtls::BidirectionalKeys,
    max_idle_timeout: std::time::Duration,
    defer_idle_timeout: std::time::Duration,
    facts: Arc<qbase::handshake::HandshakeFacts>,
) -> Arc<qtransport::Paths> {
    let reliable_frames = qtransport::ArcReliableFrames::with_capacity(0);
    let router = Arc::new(qtransport::router::QuicRouter::new());
    let (inbox, _) = qtransport::packet::channel::new();
    let local_cids = qtransport::ArcLocalCids::new(role, odcid, scid, router.registry_on_issuing_scid(inbox, reliable_frames.clone()));
    let initial_space =
        Arc::new(qtransport::space::InitialSpace::new(scid, qtransport::keys::ArcKeys::new(Arc::new(keys)), None, facts.clone()));
    let remote_cids = match role {
        qbase::role::Role::Client => qtransport::ArcRemoteCids::client(odcid, reliable_frames.clone()),
        qbase::role::Role::Server => qtransport::ArcRemoteCids::server(odcid, reliable_frames.clone()),
    };
    remote_cids.set_limit(10);
    qtransport::Paths::new(
        initial_space,
        facts,
        qtransport::CidRegistry::new(local_cids, remote_cids),
        reliable_frames,
        max_idle_timeout,
        defer_idle_timeout,
    )
}

/// Read and return one test batch through its already applied CID handle.
pub fn cid_value(dcid: &qtransport::ArcDcid) -> ConnectionId {
    let std::task::Poll::Ready(Some(cid)) = dcid.poll_borrow(&mut std::task::Context::from_waker(std::task::Waker::noop())) else {
        panic!("expected a ready CID");
    };
    dcid.refresh();
    cid
}

/// A ready CID cell for component tests that do not run the connection lifecycle.
pub fn dcid(cid: ConnectionId) -> qtransport::ArcDcid {
    let remote = qtransport::ArcRemoteCids::server(cid, qtransport::ArcReliableFrames::with_capacity(0));
    remote.upgrade();
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
pub fn paths(role: qbase::role::Role) -> (Arc<qtransport::Paths>, qtransport::terminate::ArcTerminator) {
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
pub struct CloseObserver(std::sync::Mutex<Option<qtransport::Error>>);

impl qbase::Close for CloseObserver {
    fn close_with_error(&self, error: qtransport::Error) {
        *self.0.lock().unwrap() = Some(error);
    }
}

impl CloseObserver {
    pub fn notified(&self) -> Option<qtransport::Error> {
        self.0.lock().unwrap().clone()
    }
}

pub fn observe_close(terminator: &qtransport::terminate::ArcTerminator) -> Arc<CloseObserver> {
    let observer = Arc::new(CloseObserver::default());
    terminator.register(observer.clone());
    observer
}

/// Hold receiver resources independently of the active sending queue in tests.
pub fn initial_space(spaces: &qtransport::space::ArcSpaces) -> Arc<qtransport::space::Space<qtransport::keys::ArcKeys>> {
    let initial = spaces.get_as::<qtransport::space::InitialSpace>(qbase::Epoch::Initial).unwrap();
    Arc::new(initial.space.clone())
}

pub mod spaces;

pub fn take_heartbeat(path: &qtransport::path::Path) -> bool {
    use std::task::{Context, Poll, Waker};

    use bytes::BytesMut;
    use qbase::packet::{GetType, OneRttHeader, Package, PacketBuffer};

    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let limits_quota = 1;
    let limits_length = 1;
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let mut writer_0 = bytes::BufMut::limit(&mut bytes, limits_length);
    match path
        .heartbeat
        .clone()
        .poll_dump(&mut Context::from_waker(Waker::noop()), &mut PacketBuffer::new(&mut writer_0, limits_quota, &mut frames, ty, 0, 0))
    {
        Poll::Ready(1) => {
            assert!(frames.is_empty());
            assert_eq!(&bytes[..], &[1]);
            true
        }
        Poll::Pending | Poll::Ready(0) => false,
        other => panic!("unexpected heartbeat result: {other:?}"),
    }
}

/// Wait for the sending task started by Paths::add_path to release its path.
pub async fn wait_for_sender_exit(path: &Arc<qtransport::path::Path>) {
    tokio::time::timeout(std::time::Duration::from_secs(4), async {
        while Arc::strong_count(path) > 1 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("sending task must release its path");
}

pub fn retire_all(paths: &qtransport::Paths) {
    paths.terminator.terminate();
    paths.clean();
}

pub mod path_fixtures;

/// Congestion control for standalone space-assembly tests without a path task.
pub fn send_cc() -> qcongestion::ArcCC {
    let validation = qbase::net::validate::ArcValidation::new();
    validation.exempt().unwrap();
    qcongestion::ArcCC::new(
        qcongestion::Algorithm::NewReno,
        std::time::Duration::from_millis(25),
        Default::default(),
        handshake_facts(qbase::role::Role::Client, true),
        validation,
        Arc::new(std::sync::atomic::AtomicU16::new(1200)),
    )
}

/// Start a fresh validation attempt with callbacks that do not retain the path.
pub fn revalidate(path: &Arc<qtransport::path::Path>) {
    use qcongestion::Transport as _;
    let blocked = Arc::downgrade(path);
    let charged = blocked.clone();
    path.validation
        .revalidate(
            move || {
                if let Some(path) = blocked.upgrade() {
                    path.cc.on_blocked();
                }
            },
            move || {
                if let Some(path) = charged.upgrade() {
                    path.cc.on_charged();
                }
            },
        )
        .unwrap();
}
