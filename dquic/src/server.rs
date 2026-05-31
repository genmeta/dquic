use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    ops::{Deref, DerefMut},
    pin::pin,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use futures::StreamExt;
use qbase::{
    packet::{DataHeader, GetDcid, Packet, long::DataHeader as LongHeader},
    param::ServerParameters,
    token::TokenProvider,
    util::BoundQueue,
};
use qconnection::{
    self,
    qinterface::{self, bind_uri::BindUri, component::location::Locations, device::Devices},
    tls::AcceptAllClientAuther,
};
use qevent::telemetry::QLog;
use qinterface::{
    BindInterface,
    component::route::{QuicRouter, Way},
    io::ProductIO,
    manager::InterfaceManager,
};
use rustls::{
    ConfigBuilder, ServerConfig as TlsServerConfig, WantsVerifier,
    server::{NoClientAuth, ResolvesServerCert, danger::ClientCertVerifier},
    sign::CertifiedKey,
};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::Instrument;

use crate::{prelude::*, *};

/// Errors that can occur during server management operations.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The server with the specified name already exists.
    #[error("Server '{server}' already exists")]
    ServerAlreadyExists { server: String },

    /// The server with the specified name was not found.
    #[error("Server '{server}' not found")]
    ServerNotFound { server: String },

    /// Failed to load the private key for the server.
    #[error("Failed to load private key for server '{server}': {source}")]
    InvalidCertOrKey {
        server: String,
        #[source]
        source: rustls::Error,
    },
}

impl From<ServerError> for io::Error {
    fn from(error: ServerError) -> Self {
        let kind = match &error {
            ServerError::ServerAlreadyExists { .. } => io::ErrorKind::AlreadyExists,
            ServerError::ServerNotFound { .. } => io::ErrorKind::NotFound,
            ServerError::InvalidCertOrKey { .. } => io::ErrorKind::InvalidInput,
        };
        io::Error::new(kind, error)
    }
}

/// Errors that can occur during QuicListeners builder creation.
#[derive(Debug, thiserror::Error)]
pub enum ListenError {
    /// A QuicListeners instance is already running globally.
    #[error("A QuicListeners is already running on the router")]
    AlreadyRunning,
}

impl From<ListenError> for io::Error {
    fn from(error: ListenError) -> Self {
        match error {
            ListenError::AlreadyRunning => io::Error::new(io::ErrorKind::AlreadyExists, error),
        }
    }
}

type TlsServerConfigBuilder<T> = ConfigBuilder<TlsServerConfig, T>;

#[derive(Debug, Default)]
pub struct VirtualHosts(Arc<DashMap<String, Server>>);

impl ResolvesServerCert for VirtualHosts {
    fn resolve(&self, client_hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        self.0
            .get(client_hello.server_name()?)
            .map(|server| server.certified_key())
    }
}

pub struct Server {
    network: common::Network,
    bind_ifaces: DashMap<BindUri, BindInterface>,
    // todo: [update] change to LocalAuthority
    certified_key: ArcSwap<CertifiedKey>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("bind_ifaces", &self.bind_ifaces)
            .field("certified_key", &self.certified_key())
            .finish()
    }
}

impl Server {
    pub fn bind_interfaces(&self) -> HashMap<BindUri, BindInterface> {
        self.bind_ifaces
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    pub async fn bind(&self, bind_uris: impl IntoIterator<Item = impl Into<BindUri>>) {
        let mut bind_ifaces = pin!(self.network.bind_many(bind_uris).await);
        while let Some(bind_iface) = bind_ifaces.next().await {
            self.bind_ifaces.insert(bind_iface.bind_uri(), bind_iface);
        }
    }

    pub fn get_iface(&self, bind_uri: &BindUri) -> Option<BindInterface> {
        self.bind_ifaces
            .get(bind_uri)
            .map(|iface| iface.value().clone())
    }

    pub fn remove_iface(&self, bind_uri: &BindUri) -> Option<BindInterface> {
        self.bind_ifaces.remove(bind_uri).map(|entry| entry.1)
    }

    pub fn certified_key(&self) -> Arc<CertifiedKey> {
        self.certified_key.load_full()
    }

    pub fn update_ocsp(&self, ocsp: Option<Vec<u8>>) {
        self.certified_key.rcu(|current| CertifiedKey {
            cert: current.cert.clone(),
            key: current.key.clone(),
            ocsp: ocsp.clone(),
        });
    }
}

type Incomings = BoundQueue<(
    (Arc<Connection>, String, Pathway, Link),
    OwnedSemaphorePermit,
)>;

/// A QUIC listener that can serve multiple virtual servers, accepting incoming connections.
///
/// ## Creating Listeners
///
/// Use [`QuicListenersBuilder`] to configure the listener, then call [`QuicListenersBuilder::listen`]
/// to start accepting connections.
///
/// **Note**: Only one [`QuicListeners`] instance can run at a time globally.
/// To stop the listeners, call [`QuicListeners::shutdown`] or drop all references to the [`Arc<QuicListeners>`].
///
/// ## Managing Servers
///
/// Add multiple virtual servers by calling [`QuicListeners::add_server`] multiple times.
/// Each server is identified by its server name (SNI) and handles connections independently.
///
/// - Servers can share the same network interfaces
/// - Servers can be added without initially binding to any interface
///
/// ## Connection Handling
///
/// Call [`QuicListeners::accept`] to receive incoming connections. The listener automatically:
/// - Routes connections to the appropriate server based on SNI (Server Name Indication)
/// - Rejects connections if the target server isn't listening on the receiving interface
/// - Returns connections that may still be completing their QUIC handshake
#[derive(Clone)]
pub struct QuicListeners {
    network: common::Network,

    // server
    servers: Arc<DashMap<String, Server>>, // must be empty while building
    incomings: Arc<Incomings>,             // identify the building QuicListeners
    backlog: Arc<Semaphore>,               // limit the number of concurrent connections
    // server: quic config(in initialize order)
    _supported_versions: Vec<u32>,
    token_provider: Arc<dyn TokenProvider>,
    parameters: ServerParameters,
    anti_port_scan: bool,
    client_auther: Arc<dyn AuthClient>,
    tls_config: TlsServerConfig,
    stream_strategy_factory: Arc<dyn ProductStreamsConcurrencyController>,
    defer_idle_timeout: Duration,
    qlogger: Arc<dyn QLog + Send + Sync>,
}

impl QuicListeners {
    /// Add a virtual server with its certificate chain and private key.
    ///
    /// Creates a new virtual host identified by its server name (SNI). The server will use the
    /// certificate chain and private key that matches the SNI in the client's `ClientHello` message.
    /// If no matching server is found, the connection will be rejected.
    ///
    /// A server can be added without binding to any interface initially, but will not accept
    /// connections until interfaces are added via [`bind`]. This allows flexible
    /// server configuration and hot-swapping of network bindings.
    ///
    /// [`bind`]: Server::bind
    pub async fn add_server(
        &self,
        server_name: impl Into<String>,
        cert_chain: impl handy::ToCertificate,
        private_key: impl handy::ToPrivateKey,
        bind_uris: impl IntoIterator<Item = impl Into<BindUri>>,
        ocsp: impl Into<Option<Vec<u8>>>,
    ) -> Result<(), ServerError> {
        let server = server_name.into();

        let server_entry = match self.servers.entry(server.clone()) {
            dashmap::Entry::Vacant(entry) => entry,
            dashmap::Entry::Occupied(..) => {
                return Err(ServerError::ServerAlreadyExists { server });
            }
        };

        let cert = cert_chain.to_certificate();
        let key = self
            .tls_config
            .crypto_provider()
            .key_provider
            .load_private_key(private_key.to_private_key())
            .map_err(|e| ServerError::InvalidCertOrKey {
                server: server.clone(),
                source: e,
            })?;
        let ocsp = ocsp.into();
        let certified_key = CertifiedKey { cert, key, ocsp };

        certified_key
            .keys_match()
            .map_err(|source| ServerError::InvalidCertOrKey {
                server: server.clone(),
                source,
            })?;
        let certified_key = Arc::new(certified_key);

        let bind_uris = bind_uris.into_iter();

        let server = Server {
            network: self.network.clone(),
            bind_ifaces: DashMap::with_capacity(bind_uris.size_hint().0),
            certified_key: ArcSwap::new(certified_key),
        };
        server.bind(bind_uris).await;
        server_entry.insert(server);

        Ok(())
    }

    /// Remove a virtual server and all its associated interfaces.
    ///
    /// Completely removes a server from the listeners, including all network interfaces
    /// it was bound to (if the interface is not used by other servers).
    /// This is the inverse operation of [`add_server`] and provides a clean
    /// way to decommission a virtual host.
    ///
    /// Returns `true` if the server existed and was removed, `false` if no server with the
    /// specified name was found. You must remove an existing server before adding a new
    /// one with the same name.
    ///
    /// [`add_server`]: QuicListeners::add_server
    pub fn remove_server(&self, server_name: &str) -> bool {
        self.servers.remove(server_name).is_some()
    }

    /// Get the server by its name.
    pub fn get_server<'l>(&'l self, server_name: &str) -> Option<impl Deref<Target = Server> + 'l> {
        self.servers.get(server_name)
    }

    /// Get a mutable reference to the server by its name.
    pub fn get_server_mut<'l>(
        &'l self,
        server_name: &str,
    ) -> Option<impl DerefMut<Target = Server> + 'l> {
        self.servers.get_mut(server_name)
    }

    pub fn servers(&self) -> Vec<String> {
        self.servers
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }
}

#[derive(Debug, Error, Clone, Copy)]
#[error("Listeners shutdown")]
pub struct ListenersShutdown;

impl QuicListeners {
    /// Accept an incoming QUIC connection from the queue.
    ///
    /// Returns the connection, connected server name, and network path information.
    /// Connections are automatically routed based on SNI (Server Name Indication).
    ///
    /// The connection queue size is limited by the `backlog` parameter in [`QuicListenersBuilder::listen`].
    /// When the queue is full, new incoming packets may be dropped at the network level.
    pub async fn accept(
        &self,
    ) -> Result<(Arc<Connection>, String, Pathway, Link), ListenersShutdown> {
        self.incomings
            .recv()
            .await
            .ok_or(ListenersShutdown)
            .map(|(i, ..)| i)
    }

    /// Close the QuicListeners, stops accepting new connections.
    ///
    /// Unaccepted connections will be closed
    pub fn shutdown(&self) {
        self.incomings.close();
        self.backlog.close();
    }
}

impl Drop for QuicListeners {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct ServerAuther {
    anti_port_scan: bool,
    iface: BindUri,
    servers: Arc<DashMap<String, Server>>,
}

impl AuthClient for ServerAuther {
    fn verify_client_name(
        &self,
        server_authority: &LocalAuthority,
        _: Option<&str>,
    ) -> ClientNameVerifyResult {
        match self
            .servers
            .get(server_authority.name())
            .is_some_and(|server| server.bind_ifaces.contains_key(&self.iface))
        {
            true => ClientNameVerifyResult::Accept,
            false if self.anti_port_scan => ClientNameVerifyResult::SilentRefuse("".to_owned()),
            false => ClientNameVerifyResult::Refuse("".to_owned()),
        }
    }

    fn verify_client_authority(&self, _: &LocalAuthority, _: &RemoteAuthority) -> ClientAuthorityVerifyResult {
        ClientAuthorityVerifyResult::Accept
    }
}

// internal methods
impl QuicListeners {
    #[tracing::instrument(
        target = "quic_listeners", level = "debug", skip_all, 
        fields(%bind_uri, %pathway, %link, odcid=tracing::field::Empty, server_name=tracing::field::Empty)
    )]
    pub(crate) fn try_accept_connection(&self, packet: Packet, (bind_uri, pathway, link): Way) {
        let origin_dcid = match &packet {
            Packet::Data(data_packet) => match &data_packet.header {
                DataHeader::Long(LongHeader::Initial(hdr)) => *hdr.dcid(),
                DataHeader::Long(LongHeader::ZeroRtt(hdr)) => *hdr.dcid(),
                _ => return,
            },
            _ => return,
        };
        tracing::Span::current().record("odcid", origin_dcid.to_string());

        if origin_dcid.is_empty() {
            tracing::debug!(target: "quic_listeners", "Received an initial/0rtt packet with empty destination CID, ignoring it");
            return;
        }

        // Acquire a permit from the backlog semaphore to limit the number of concurrent connections.
        let Ok(premit) = self.backlog.clone().try_acquire_owned() else {
            tracing::debug!(target: "quic_listeners", "Backlog full, dropping incoming packet");
            return;
        };

        let server_auther = ServerAuther {
            anti_port_scan: self.anti_port_scan,
            iface: bind_uri.clone(),
            servers: self.servers.clone(),
        };

        let connection = Connection::new_server(self.token_provider.clone())
            .with_parameters(self.parameters.clone())
            .with_client_auther(Box::new((server_auther, self.client_auther.clone())))
            .with_tls_config(self.tls_config.clone())
            .with_streams_concurrency_strategy(self.stream_strategy_factory.as_ref())
            .with_zero_rtt(self.tls_config.max_early_data_size == 0xffffffff)
            .with_defer_idle_timeout(self.defer_idle_timeout)
            .with_iface_factory(self.network.iface_factory.clone())
            .with_iface_manager(self.network.iface_manager.clone())
            .with_quic_router(self.network.quic_router.clone())
            .with_locations(self.network.locations.clone())
            // todo
            // .with_stun_servers()
            .with_cids(origin_dcid)
            .with_qlog(self.qlogger.clone())
            .run();

        let incomings = self.incomings.clone();
        let quic_router = self.network.quic_router.clone();

        let try_accept_connection = async move {
            quic_router.deliver(packet, (bind_uri, pathway, link)).await;

            match connection.server_name().await {
                Ok(server_name) => {
                    tracing::Span::current().record("server_name", &server_name);
                    _ = connection.subscribe_local_address();
                    let incoming = (connection, server_name, pathway, link);
                    match incomings.send((incoming, premit)).await {
                        Ok(..) => {
                            tracing::debug!(target: "quic_listeners", "Accepted incoming connection")
                        }
                        Err(..) => {
                            tracing::debug!(target: "quic_listeners", "Listeners is shutdown, closing incoming connection")
                        }
                    }
                }
                Err(error) => {
                    tracing::debug!(
                        target: "quic_listeners",
                        "Failed to accept connection: {error}",
                    );
                }
            }
        };
        // Task completes after a single accept-notify cycle; no explicit join needed.
        tokio::spawn(try_accept_connection.in_current_span());
    }
}

/// The builder for the quic listeners.
#[derive(Clone)]
pub struct QuicListenersBuilder<T> {
    // network
    network: common::Network,

    // server
    servers: Arc<DashMap<String, Server>>, // must be empty while building
    incomings: Arc<Incomings>,             // identify the building QuicListeners
    // server: quic config(in initialize order)
    supported_versions: Vec<u32>,
    token_provider: Arc<dyn TokenProvider>,
    parameters: ServerParameters,
    anti_port_scan: bool,
    client_auther: Arc<dyn AuthClient>,
    tls_config: T,
    stream_strategy_factory: Arc<dyn ProductStreamsConcurrencyController>,
    defer_idle_timeout: Duration,
    qlogger: Arc<dyn QLog + Send + Sync>,
}

impl QuicListeners {
    /// Start to build a [`QuicListeners`].
    pub fn builder() -> QuicListenersBuilder<TlsServerConfigBuilder<WantsVerifier>> {
        Self::builder_with_tls(TlsServerConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS13,
        ]))
    }

    /// Start to build a QuicServer with the given tls crypto provider.
    pub fn builder_with_crypto_provider(
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<QuicListenersBuilder<TlsServerConfigBuilder<WantsVerifier>>, rustls::Error> {
        Ok(Self::builder_with_tls(
            TlsServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])?,
        ))
    }

    /// Start to build a [`QuicListeners`] with the given TLS configuration.
    ///
    /// This is useful when you want to customize the TLS configuration, or integrate qm-quic with other crates.
    pub fn builder_with_tls<T>(tls_config: T) -> QuicListenersBuilder<T> {
        QuicListenersBuilder {
            // network
            network: common::Network::default(),

            // server
            servers: Arc::new(DashMap::new()), // must be empty while building
            incomings: Arc::new(BoundQueue::new(8)), // identify the building QuicListeners
            // server: quic config(in initialize order)
            supported_versions: vec![1],
            token_provider: Arc::new(handy::NoopTokenRegistry),
            parameters: handy::server_parameters(),
            anti_port_scan: false,
            client_auther: Arc::new(AcceptAllClientAuther),
            tls_config,
            stream_strategy_factory: Arc::new(handy::ConsistentConcurrency::new),
            defer_idle_timeout: Duration::ZERO,
            qlogger: Arc::new(handy::NoopLogger),
        }
    }
}

impl<T> QuicListenersBuilder<T> {
    pub fn with_resolver(mut self, resolver: Arc<dyn Resolve + Send + Sync>) -> Self {
        self.network.resolver = resolver;
        self
    }

    pub fn with_physical_ifaces(mut self, physical_ifaces: &'static Devices) -> Self {
        self.network.devices = physical_ifaces;
        self
    }

    /// Specify how hosts bind to the interface.
    ///
    /// If you call this multiple times, only the last `factory` will be used.
    ///
    /// The default quic interface is provided by [`handy::DEFAULT_IO_FACTORY`].
    /// For Unix and Windows targets, this is a high performance UDP library supporting GSO and GRO
    /// provided by `qudp` crate. For other platforms, please specify you own factory.
    pub fn with_iface_factory(mut self, iface_factory: Arc<dyn ProductIO + 'static>) -> Self {
        self.network.iface_factory = iface_factory;
        self
    }

    pub fn with_iface_manager(mut self, iface_manager: Arc<InterfaceManager>) -> Self {
        self.network.iface_manager = iface_manager;
        self
    }

    /// Specify the router to use for the listeners.
    ///
    /// Packets received from the interface bound to the server will be deliver this router,
    /// connectless packets (maybe incoming client connection) will be delivered to QuicListeners.
    ///
    /// A router can only be listened to by one QuicListener,
    /// or the [`QuicListenersBuilder::listen`] will fail.
    pub fn with_router(mut self, router: Arc<QuicRouter>) -> Self {
        self.network.quic_router = router;
        self
    }

    pub fn with_stun(mut self, stun_server: impl Into<Arc<str>>) -> Self {
        self.network.stun_server = Some(stun_server.into());
        self
    }

    /// Specify the locations for interface sharing.
    ///
    /// The given locations is shared by all connections created by this listeners.
    pub fn with_locations(mut self, locations: Arc<Locations>) -> Self {
        self.network.locations = locations;
        self
    }

    /// (WIP)Specify the supported quic versions.
    ///
    /// If you call this multiple times, only the last call will take effect.
    pub fn with_supported_versions(mut self, versions: impl IntoIterator<Item = u32>) -> Self {
        self.supported_versions.clear();
        self.supported_versions.extend(versions);
        self
    }

    /// Specify how server to create and verify the client's Token in [address verification].
    ///
    /// If you call this multiple times, only the last `token_provider` will be used.
    ///
    /// [address verification](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation)
    pub fn with_token_provider(self, token_provider: Arc<dyn TokenProvider>) -> Self {
        Self {
            token_provider,
            ..self
        }
    }

    /// Specify the [transport parameters] for the server connections.
    ///
    /// If you call this multiple times, only the last `parameters` will be used.
    ///
    /// Usually, you don't need to call this method, because the server will use a set of default parameters.
    ///
    /// [transport parameters](https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit)
    pub fn with_parameters(mut self, parameters: ServerParameters) -> Self {
        self.parameters = parameters;
        self
    }

    /// Enable anti-port scanning protection.
    ///
    /// When anti-port scanning protection is enabled, the server will silently drop connections
    /// that fail validation (e.g., invalid ClientHello, authentication failures)
    /// without sending any response packets.
    ///
    /// This security feature provides the following benefits:
    /// - Prevents attackers from detecting server presence through port scanning
    /// - Reduces the attack surface by not revealing server configuration details
    /// - Protects against network reconnaissance and probing attacks
    /// - Makes the server appear "offline" to unauthorized connection attempts
    ///
    /// **Security Note:** This feature should be used carefully as it may make
    /// debugging connection issues more difficult. Consider using it in production
    /// environments where security is prioritized over observability.
    ///
    /// **Tip:** For enhanced security, combine this with [`with_client_auther`] to implement
    /// custom authentication logic while maintaining stealth behavior for failed connections.
    ///
    /// Default: disabled
    ///
    /// [`with_client_auther`]: QuicListenersBuilder::with_client_auther
    pub fn enable_anti_port_scan(mut self) -> Self {
        self.anti_port_scan = true;
        self
    }

    /// Specify custom client authentication handlers for the server.
    ///
    /// Client authers are used to perform additional validation beyond standard TLS
    /// certificate verification. They can verify server names, client parameters,
    /// and client certificates according to custom business logic.
    ///
    /// Each [`AuthClient`] implementation provides three verification methods:
    /// - `verify_server_name()`: Validates the requested server name (SNI)
    /// - `verify_client_params()`: Validates client QUIC transport parameters
    /// - `verify_client_certs()`: Validates client certificate chains
    ///
    /// All provided authers must approve the connection for it to be accepted.
    /// If any auther rejects the connection, it will be dropped.
    ///
    /// If you call this multiple times, only the last `client_auther` will be used.
    ///
    /// **Security Enhancement:** When combined with [`enable_anti_port_scan`],
    /// failed authentication attempts will be silently dropped without any response,
    /// providing enhanced security against reconnaissance attacks.
    ///
    /// **TLS Protocol Note:** Certificate verification failures during the TLS handshake
    /// will still send error responses to clients, as the server has already sent
    /// its `ServerHello` message at that point. The stealth behavior only applies to
    /// earlier validation failures that occur before the TLS handshake begins.
    ///
    /// **Built-in Validation:** The server automatically verifies that the interface
    /// receiving the client connection is configured to listen for the requested
    /// server name (SNI). This built-in validation ensures proper routing of
    /// connections to their intended hosts.
    ///
    /// Default: empty (only built-in host and interface validation)
    ///
    /// [`AuthClient`]: qconnection::tls::AuthClient
    /// [`enable_anti_port_scan`]: QuicListenersBuilder::enable_anti_port_scan
    pub fn with_client_auther(mut self, client_auther: impl AuthClient + 'static) -> Self {
        self.client_auther = Arc::new(client_auther);
        self
    }

    fn map_tls<T1>(self, f: impl FnOnce(T) -> T1) -> QuicListenersBuilder<T1> {
        QuicListenersBuilder {
            network: self.network,
            servers: self.servers,
            incomings: self.incomings,
            supported_versions: self.supported_versions,
            token_provider: self.token_provider,
            parameters: self.parameters,
            anti_port_scan: self.anti_port_scan,
            client_auther: self.client_auther,
            tls_config: f(self.tls_config),
            stream_strategy_factory: self.stream_strategy_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            qlogger: self.qlogger,
        }
    }

    /// Specify the factory which product the streams concurrency strategy controller for the server.
    ///
    /// The streams controller is used to control the concurrency of data streams.
    /// Take a look of [`ControlStreamsConcurrency`] for more information.
    ///
    /// If you call this multiple times, only the last `controller` will be used.
    pub fn with_streams_concurrency_strategy(
        self,
        stream_strategy_factory: Arc<dyn ProductStreamsConcurrencyController>,
    ) -> Self {
        Self {
            stream_strategy_factory,
            ..self
        }
    }

    /// Provide an option to defer an idle timeout.
    ///
    /// This facility could be used when the application wishes to avoid losing
    /// state that has been associated with an open connection but does not expect
    /// to exchange application data for some time.
    ///
    /// See [Deferring Idle Timeout](https://datatracker.ietf.org/doc/html/rfc9000#name-deferring-idle-timeout)
    /// of [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000)
    /// for more information.
    pub fn defer_idle_timeout(mut self, duration: Duration) -> Self {
        self.defer_idle_timeout = duration;
        self
    }

    /// Specify qlog collector for server connections.
    ///
    /// If you call this multiple times, only the last `logger` will be used.
    ///
    /// Pre-implemented loggers:
    /// - [`LegacySeqLogger`]: Generates qlog files compatible with [qvis] visualization.
    ///   - `LegacySeqLogger::new(PathBuf::from("/dir"))`: Write to files `{connection_id}_{role}.sqlog` in `dir`
    ///   - `LegacySeqLogger::new(tokio::io::stdout())`: Stream to stdout
    ///   - `LegacySeqLogger::new(tokio::io::stderr())`: Stream to stderr
    ///
    ///   Output format: JSON-SEQ ([RFC7464]), one JSON event per line.
    ///
    /// - [`handy::NoopLogger`] (default): Ignores all qlog events (default, recommended for production).
    ///
    /// [qvis]: https://qvis.quictools.info/
    /// [RFC7464]: https://www.rfc-editor.org/rfc/rfc7464
    /// [`LegacySeqLogger`]: qevent::telemetry::handy::LegacySeqLogger
    pub fn with_qlog(self, qlogger: Arc<dyn QLog + Send + Sync>) -> Self {
        Self { qlogger, ..self }
    }
}

impl QuicListenersBuilder<TlsServerConfigBuilder<WantsVerifier>> {
    /// Choose how to verify client certificates.
    pub fn with_client_cert_verifier(
        self,
        client_cert_verifier: Arc<dyn ClientCertVerifier>,
    ) -> QuicListenersBuilder<TlsServerConfig> {
        let virtual_servers = Arc::new(VirtualHosts(self.servers.clone()));
        self.map_tls(|tls_config_builder| {
            tls_config_builder
                .with_client_cert_verifier(client_cert_verifier)
                .with_cert_resolver(virtual_servers)
        })
    }

    /// Disable client authentication.
    pub fn without_client_cert_verifier(self) -> QuicListenersBuilder<TlsServerConfig> {
        let virtual_servers = Arc::new(VirtualHosts(self.servers.clone()));
        self.map_tls(|tls_config_builder| {
            tls_config_builder
                .with_client_cert_verifier(Arc::new(NoClientAuth))
                .with_cert_resolver(virtual_servers)
        })
    }
}

impl QuicListenersBuilder<TlsServerConfig> {
    /// Specify the [alpn-protocol-ids] that the server supports.
    ///
    /// If you call this multiple times, all the `alpn_protocol` will be used.
    ///
    /// If you never call this method, we will not do ALPN with the client.
    ///
    /// [alpn-protocol-ids](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids)
    pub fn with_alpns(mut self, alpn: impl IntoIterator<Item = impl Into<Vec<u8>>>) -> Self {
        self.tls_config
            .alpn_protocols
            .extend(alpn.into_iter().map(Into::into));
        self
    }

    pub fn enable_0rtt(mut self) -> Self {
        // The TLS early_data extension in the NewSessionTicket message is defined to convey (in the
        // max_early_data_size parameter) the amount of TLS 0-RTT data the server is willing to accept. QUIC does not
        // use TLS early data. QUIC uses 0-RTT packets to carry early data. Accordingly, the max_early_data_size
        // parameter is repurposed to hold a sentinel value 0xffffffff to indicate that the server is willing to accept QUIC
        // 0-RTT data. To indicate that the server does not accept 0-RTT data, the early_data extension is omitted from
        // the NewSessionTicket. The amount of data that the client can send in QUIC 0-RTT is controlled by the
        // initial_max_data transport parameter supplied by the server.
        self.tls_config.max_early_data_size = 0xffffffff;
        self
    }

    /// Start listening for incoming connections.
    ///
    /// The `backlog` parameter has the same meaning as the backlog parameter of the UNIX listen function,
    /// which is the maximum number of pending connections that can be queued.
    /// If the queue is full, new initial packets may be dropped.
    ///
    /// Panic if `backlog` is 0.
    pub fn listen(self, backlog: usize) -> Result<Arc<QuicListeners>, ListenError> {
        assert!(backlog > 0, "backlog must be greater than 0");
        debug_assert!(self.servers.is_empty());

        let quic_router = self.network.quic_router.clone();

        let quic_listeners = Arc::new(QuicListeners {
            network: self.network,
            servers: self.servers,
            incomings: self.incomings,
            backlog: Arc::new(Semaphore::new(backlog)),
            _supported_versions: self.supported_versions,
            token_provider: self.token_provider,
            parameters: self.parameters,
            anti_port_scan: self.anti_port_scan,
            client_auther: self.client_auther,
            tls_config: self.tls_config,
            stream_strategy_factory: self.stream_strategy_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            qlogger: self.qlogger,
        });

        // TODO: optimize init order
        let listeners = quic_listeners.clone();
        if !quic_router.on_connectless_packets(move |packet, way| {
            listeners.try_accept_connection(packet, way);
        }) {
            return Err(ListenError::AlreadyRunning);
        }

        Ok(quic_listeners)
    }
}
