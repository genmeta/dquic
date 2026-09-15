use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicU8, Ordering},
    },
};

use futures::StreamExt;
use qbase::{
    error::{Error, ErrorKind, QuicError},
    net::{addr::EndpointAddr, route::Pathway},
};
use qresolve::Resolve;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    endpoint::{Connected, Endpoint, External, Internal, Loopback, Scope},
    handshake::incoming::Incoming,
    listener::Listener,
    router::Router,
};

pub(crate) struct Network {
    pub(crate) listener: Arc<Listener>,
    pub(crate) router: Arc<Router>,
    pub(crate) protocol: Arc<qprotocol::QuicProtocol>,
    pub(crate) dock: Arc<qprotocol::Dock>,
    pub(crate) addresses: qprotocol::AddressBook,
    pub(crate) provider: Arc<tls_backend::crypto::CryptoProvider>,
    pub(crate) verifier: Arc<dyn qtls::VerifyIdentity>,
    pub(crate) verify_client: Option<Arc<dyn qtls::VerifyIdentity>>,
    pub(crate) initial: qtls::ServerTlsEndpoint,
    pub(crate) stop: CancellationToken,
    sockets: Mutex<HashMap<(String, IpAddr), Arc<qudp::UdpSocket>>>,
    scope: AtomicU8,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    #[expect(
        clippy::type_complexity,
        reason = "connection requests are passed directly as tuples"
    )]
    clients: mpsc::Sender<(
        Option<Endpoint>,
        String,
        CancellationToken,
        oneshot::Sender<Result<Connected, Error>>,
    )>,
}

impl Network {
    pub(crate) fn global() -> Result<Arc<Self>, Error> {
        static GLOBAL: OnceLock<Mutex<Weak<Network>>> = OnceLock::new();
        let mut global = GLOBAL
            .get_or_init(|| Mutex::new(Weak::new()))
            .lock()
            .unwrap();
        if let Some(network) = global
            .upgrade()
            .filter(|network| !network.stop.is_cancelled())
        {
            return Ok(network);
        }
        tokio::runtime::Handle::try_current()
            .map_err(|_| crate::internal("qconn requires a Tokio runtime"))?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|error| crate::internal(error.to_string()))?;
        let network = Self::new(Arc::new(crate::tls::Verifier(verifier)), None)?;
        *global = Arc::downgrade(&network);
        Ok(network)
    }

    pub(crate) fn new(
        verifier: Arc<dyn qtls::VerifyIdentity>,
        verify_client: Option<Arc<dyn qtls::VerifyIdentity>>,
    ) -> Result<Arc<Self>, Error> {
        let (incoming, queue) = mpsc::channel(32);
        let (clients, connecting) = mpsc::channel(32);
        let router = Router::new(incoming);
        let protocol = Arc::new(qprotocol::QuicProtocol::new());
        let routes = router.clone();
        protocol.on_receive(move |bytes, pathway, link| routes.receive(bytes, pathway, link));
        let dock = qprotocol::Dock::new(Arc::new(qprotocol::topology::Topology::new(
            Arc::new(qprotocol::StunProtocol::new()),
            Arc::new(qprotocol::ForwardProtocol::new()),
            protocol.clone(),
        )));
        let (listener, accepted) = Listener::new();
        let provider = Arc::new(qtls::default_provider());
        let initial = qtls::ServerTlsEndpoint::new(qtls::ServerTlsConfig {
            provider: provider.clone(),
            alpn: vec![b"qconn".to_vec()],
            resolve_local: listener.clone(),
            verify_client: None,
            resumption: qtls::ServerResumptionConfig::Disabled,
            limits: qtls::TlsLimits::default(),
        })
        .map_err(|error| crate::internal(error.to_string()))?;
        let network = Arc::new(Self {
            listener,
            router,
            protocol,
            dock,
            addresses: qprotocol::AddressBook::new(),
            provider,
            verifier,
            verify_client,
            initial,
            stop: CancellationToken::new(),
            sockets: Mutex::new(HashMap::new()),
            scope: 0.into(),
            tasks: Mutex::new(Vec::new()),
            clients,
        });
        network
            .tasks
            .lock()
            .unwrap()
            .push(tokio::spawn(Listener::dispatch(
                accepted,
                network.stop.clone(),
            )));
        network
            .tasks
            .lock()
            .unwrap()
            .push(tokio::spawn(Self::incoming(
                network.clone(),
                queue,
                connecting,
            )));
        Ok(network)
    }

    pub(crate) fn bind_scope(&self, scope: Scope) -> Result<(), Error> {
        if scope.is_empty() {
            return Err(crate::internal("listen scope is empty"));
        }
        self.scope.fetch_or(scope.bits(), Ordering::AcqRel);
        let mut candidates = Vec::new();
        if scope.contains(Loopback) {
            candidates.push((String::new(), "127.0.0.1".parse::<IpAddr>().unwrap(), None));
            candidates.push((String::new(), "::1".parse::<IpAddr>().unwrap(), None));
        }
        if scope.intersects(Internal | External) {
            for interface in qinterface::device::Devices::global().interfaces().values() {
                if !interface.is_up() || interface.is_loopback() {
                    continue;
                }
                if !scope.contains(Internal) && !interface.default && interface.gateway.is_none() {
                    continue;
                }
                let device = qudp::BoundDevice::new(interface.name.clone(), interface.index)
                    .map_err(|error| crate::internal(error.to_string()))?;
                if let Some(ip) = interface
                    .ipv4
                    .iter()
                    .map(|network| network.addr())
                    .find(|ip| !ip.is_unspecified() && !ip.is_multicast() && !ip.is_link_local())
                {
                    candidates.push((interface.name.clone(), ip.into(), Some(device.clone())));
                }
                if let Some(ip) = interface
                    .ipv6
                    .iter()
                    .map(|network| network.addr())
                    .find(|ip| {
                        !ip.is_unspecified() && !ip.is_multicast() && !ip.is_unicast_link_local()
                    })
                {
                    candidates.push((interface.name.clone(), ip.into(), Some(device)));
                }
            }
        }
        let mut sockets = self.sockets.lock().unwrap();
        let mut available = false;
        let mut failure = None;
        for (name, ip, device) in candidates {
            if sockets.contains_key(&(name.clone(), ip)) {
                available = true;
                continue;
            }
            let socket = match device {
                Some(device) => qudp::UdpSocket::bind_to_device(SocketAddr::new(ip, 0), device),
                None => qudp::UdpSocket::bind(SocketAddr::new(ip, 0)),
            };
            let socket = match socket {
                Ok(socket) => Arc::new(socket),
                Err(error) => {
                    failure = Some(error);
                    continue;
                }
            };
            let bound = socket
                .local_addr()
                .map_err(|error| crate::internal(error.to_string()))?;
            let endpoint = EndpointAddr::direct(bound);
            self.protocol
                .register(endpoint, &socket)
                .map_err(|error| crate::internal(error.to_string()))?;
            if let Err(error) = self.dock.add(socket.clone()) {
                self.protocol.unregister(endpoint, &socket);
                failure = Some(error);
                continue;
            }
            if ip.is_loopback()
                || match ip {
                    IpAddr::V4(ip) => ip.is_private(),
                    IpAddr::V6(ip) => ip.is_unique_local(),
                }
            {
                self.addresses
                    .insert_inner(bound, endpoint)
                    .map_err(|error| crate::internal(error.to_string()))?;
            } else {
                self.addresses
                    .insert_outer(bound, endpoint)
                    .map_err(|error| crate::internal(error.to_string()))?;
            }
            sockets.insert((name, ip), socket);
            available = true;
        }
        if available {
            Ok(())
        } else {
            Err(QuicError::with_default_fty(
                ErrorKind::NoViablePath,
                failure.map_or_else(
                    || "no usable interface".to_owned(),
                    |error| error.to_string(),
                ),
            )
            .into())
        }
    }

    pub(crate) async fn connect(
        self: &Arc<Self>,
        endpoint: Option<Endpoint>,
        name: &str,
    ) -> Result<Connected, Error> {
        let cancel = CancellationToken::new();
        let guard = cancel.clone().drop_guard();
        let (reply, result) = oneshot::channel();
        self.clients
            .send((endpoint, name.to_owned(), cancel, reply))
            .await
            .map_err(|_| crate::internal("network stopped"))?;
        let connected = result
            .await
            .map_err(|_| crate::internal("connection task stopped"))?;
        if connected.is_ok() {
            guard.disarm();
        }
        connected
    }

    pub(crate) async fn resolve(&self, name: &str) -> Result<Vec<Pathway>, Error> {
        let mut peers = Vec::new();
        if let Some(registration) = self.listener.select(name) {
            for socket in self.sockets.lock().unwrap().values() {
                let bound = socket
                    .local_addr()
                    .map_err(|error| crate::internal(error.to_string()))?;
                let route = Pathway::new(EndpointAddr::direct(bound), EndpointAddr::direct(bound));
                if registration
                    .scope
                    .allows(route, qbase::net::route::Link::new(bound, bound))
                {
                    peers.push(route.remote());
                }
            }
        } else {
            let mut resolved = qresolve::SystemResolver
                .lookup(name, "443", None)
                .await
                .map_err(|error| crate::internal(error.to_string()))?;
            while let Some((_, endpoint)) = resolved.next().await {
                if !peers.contains(&endpoint) {
                    peers.push(endpoint);
                }
            }
        }
        let local_scope = if peers
            .iter()
            .any(|peer| matches!(peer, EndpointAddr::Direct { addr } if addr.ip().is_loopback()))
        {
            Loopback
        } else {
            Internal | External
        };
        self.bind_scope(local_scope)?;
        let locals = self
            .sockets
            .lock()
            .unwrap()
            .values()
            .filter_map(|socket| socket.local_addr().ok())
            .collect::<Vec<_>>();
        let mut paths = Vec::new();
        for peer in peers {
            let EndpointAddr::Direct { addr } = peer else {
                continue;
            };
            for local in &locals {
                if local.is_ipv4() == addr.is_ipv4()
                    && local.ip().is_loopback() == addr.ip().is_loopback()
                {
                    paths.push(Pathway::new(EndpointAddr::direct(*local), peer));
                    if paths.len() == 4 {
                        return Ok(paths);
                    }
                }
            }
        }
        if paths.is_empty() {
            return Err(QuicError::with_default_fty(
                ErrorKind::NoViablePath,
                "no resolved peer has a local route",
            )
            .into());
        }
        Ok(paths)
    }

    #[expect(
        clippy::type_complexity,
        reason = "connection requests are passed directly as tuples"
    )]
    async fn incoming(
        network: Arc<Self>,
        mut incoming: mpsc::Receiver<Incoming>,
        mut clients: mpsc::Receiver<(
            Option<Endpoint>,
            String,
            CancellationToken,
            oneshot::Sender<Result<Connected, Error>>,
        )>,
    ) {
        let mut tasks = tokio::task::JoinSet::new();
        let mut processing = HashSet::new();
        let (matured, mut ready) = mpsc::channel(8);
        loop {
            tokio::select! {
                _ = network.stop.cancelled() => break,
                client = clients.recv() => {
                    let Some((endpoint, name, cancel, reply)) = client else { break };
                    if !cancel.is_cancelled() {
                        tasks.spawn(crate::lifecycle::run_client(network.clone(), endpoint, name, cancel, reply));
                    }
                }
                id = ready.recv() => { if let Some(id) = id { processing.remove(&id); } },
                result = tasks.join_next_with_id(), if !tasks.is_empty() => {
                    let id = match result { Some(Ok((id, ()))) => id, Some(Err(error)) => error.id(), None => continue };
                    processing.remove(&id);
                }
                incoming = incoming.recv(), if processing.len() < 8 => {
                    let Some(incoming) = incoming else { break };
                    let timeout = network.listener.idle_timeout();
                    if timeout != std::time::Duration::ZERO && incoming.received_at.elapsed() >= timeout { continue }
                    let task = tasks.spawn(crate::lifecycle::run_server(network.clone(), incoming, matured.clone()));
                    processing.insert(task.id());
                }
            }
        }
        while tasks.join_next().await.is_some() {}
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        self.stop.cancel();
        for task in self.tasks.get_mut().unwrap().drain(..) {
            task.abort();
        }
        self.dock.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use qbase::{
        param::{ArcParameters, Parameters},
        role::Role,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    const CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
    const KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");
    const CLIENT_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/client.cert");
    const CLIENT_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/client.key");

    fn endpoint(name: &str, cert: &[u8], key: &[u8]) -> Endpoint {
        Endpoint::new(
            &rustls::crypto::ring::default_provider(),
            name,
            vec![CertificateDer::from_pem_slice(cert).unwrap()],
            PrivateKeyDer::from_pem_slice(key).unwrap(),
            None,
            ArcParameters::from(Parameters::new_server(
                qbase::param::handy::server_parameters(),
            )),
        )
        .unwrap()
    }

    async fn round_trip(mutual: bool, lose_handshake: bool, lose_path: bool) {
        let network = Network::new(
            crate::tls::tests::verifier("localhost", CERT),
            mutual.then(|| crate::tls::tests::verifier("client", CLIENT_CERT)),
        )
        .unwrap();
        network.bind_scope(Loopback).unwrap();
        if lose_handshake {
            let routes = network.router.clone();
            let dropped = std::sync::atomic::AtomicBool::new(false);
            network.protocol.on_receive(move |bytes, pathway, link| {
                if bytes.first().is_some_and(|first| first & 0xf0 == 0xe0)
                    && !dropped.swap(true, Ordering::AcqRel)
                {
                    return;
                }
                routes.receive(bytes, pathway, link);
            });
        }
        let server = endpoint("localhost", CERT, KEY);
        let (accepted, mut connections) = mpsc::channel(1);
        network
            .listener
            .register(
                Arc::new(server.clone()),
                Loopback,
                Arc::new(move |conn| {
                    accepted
                        .try_send(conn)
                        .unwrap_or_else(|_| panic!("duplicate delivery"));
                }),
            )
            .unwrap();
        let client_endpoint = mutual.then(|| endpoint("client", CLIENT_CERT, CLIENT_KEY));
        let (local, remote, client) = network.connect(client_endpoint, "localhost").await.unwrap();
        assert_eq!(local.is_some(), mutual);
        assert_eq!(remote.name(), "localhost");
        assert_eq!(client.role(), Role::Client);
        let (remote, local, accepted) = connections.recv().await.unwrap();
        assert_eq!(remote.is_some(), mutual);
        assert_eq!(local.name(), "localhost");
        assert_eq!(accepted.role(), Role::Server);
        assert_eq!(accepted.alpn(), Some(b"qconn".as_slice()));

        let transport = client.transport();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let paths = transport.paths.snapshot();
                if paths
                    .iter()
                    .all(|path| path.verified.load(Ordering::Acquire))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("remaining candidates were not validated after confirmation");

        let (_, (mut client_reader, mut client_writer)) =
            client.open_bi_stream().await.unwrap().unwrap();
        client_writer
            .write_all(b"request through qprotocol")
            .await
            .unwrap();
        let (_, (mut server_reader, mut server_writer)) =
            accepted.accept_bi_stream().await.unwrap();
        let mut bytes = vec![0; 25];
        server_reader.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"request through qprotocol");
        server_writer.write_all(b"response").await.unwrap();
        let mut response = [0; 8];
        client_reader.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");

        let payload = vec![0x5a; 64 * 1024];
        let mut received = vec![0; payload.len()];
        tokio::try_join!(
            client_writer.write_all(&payload),
            server_reader.read_exact(&mut received),
        )
        .unwrap();
        assert_eq!(received, payload);

        network.listener.unregister(&server).unwrap();
        if lose_path {
            assert!(
                transport.paths.snapshot().len() > 1,
                "test requires IPv4 and IPv6 loopback"
            );
            let preferred = transport.paths.preferred().unwrap();
            let socket = network.protocol.find_socket(preferred.local()).unwrap();
            network.protocol.unregister(preferred.local(), &socket);
            network.dock.remove(&socket);
            network.addresses.remove_bound(socket.local_addr().unwrap());
        }
        // Unregistering affects incubation/delivery, not this established pair.
        client_writer.write_all(b"!").await.unwrap();
        server_reader.read_exact(&mut [0]).await.unwrap();
        if lose_path {
            server_writer.write_all(b"?").await.unwrap();
            client_reader.read_exact(&mut [0]).await.unwrap();
        }
        client.close(0u32.into(), "test complete").unwrap();
        let _ = client.closed().await;
        let _ = accepted.closed().await;
        assert!(client.open_uni_stream().await.is_err());
        network.stop.cancel();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn udp_anonymous_connection_streams_and_close() {
        tokio::time::timeout(Duration::from_secs(10), round_trip(false, false, false))
            .await
            .expect("connection round trip timed out");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn udp_mutual_authorities_connection_streams_and_close() {
        tokio::time::timeout(Duration::from_secs(10), round_trip(true, false, false))
            .await
            .expect("mutual-auth round trip timed out");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn udp_lost_handshake_flight_recovers() {
        tokio::time::timeout(Duration::from_secs(10), round_trip(false, true, false))
            .await
            .expect("lost handshake flight was not recovered");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn udp_failed_primary_uses_validated_path() {
        tokio::time::timeout(Duration::from_secs(10), round_trip(false, false, true))
            .await
            .expect("validated path did not take over");
    }
}
