use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use dashmap::DashMap;
use futures::StreamExt;
use qbase::{net::Family, param::ClientParameters, token::TokenSink};
use qconnection::{
    self,
    qbase::net::AddrFamily,
    qinterface::{
        component::local_endpoint::{InterfaceEndpointUpdate, LocalEndpoints},
        io::IO,
    },
};
use qevent::telemetry::QLog;
use qinterface::{
    BindInterface, Interface, bind_uri::BindUri, component::route::QuicRouter, device::Devices,
    io::ProductIO, manager::InterfaceManager,
};
use qresolve::Source;
use rustls::{
    ConfigBuilder, WantsVerifier,
    client::{ResolvesClientCert, WantsClientCert},
};
use thiserror::Error;
use tracing::Instrument as _;

use crate::{prelude::*, *};

type TlsClientConfig = rustls::ClientConfig;
type TlsClientConfigBuilder<T> = ConfigBuilder<TlsClientConfig, T>;

/// A QUIC client for initiating connections to servers.
///
/// ## Creating Clients
///
/// Use [`QuicClient::builder`] to configure and create a client instance.
/// Configure interfaces, TLS settings, and connection behavior before building.
///
/// ## Interface Management
///
/// - **Automatic binding**: If no interfaces are bound, the client automatically binds to system-assigned addresses
/// - **Manual binding**: Use [`QuicClientBuilder::bind`] to bind specific interfaces
///
/// ## Connection Handling
///
/// Call [`QuicClient::connect`] to establish connections. The client supports:
/// - **Automatic interface selection**: Matches interface with server endpoint address
#[derive(Clone)]
pub struct QuicClient {
    network: common::Network,
    bind_ifaces: DashMap<BindUri, BindInterface>,
    manual_bind: Arc<AtomicBool>,

    // quic config(in initialize order)
    _prefer_versions: Vec<u32>,
    token_sink: Arc<dyn TokenSink>,
    parameters: ClientParameters,
    tls_config: TlsClientConfig,
    stream_strategy_factory: Arc<dyn ProductStreamsConcurrencyController>,
    defer_idle_timeout: Duration,
    qlogger: Arc<dyn QLog + Send + Sync>,
}

#[derive(Debug, Error)]
pub enum ConnectServerError {
    #[error("DNS lookup failed")]
    Dns {
        #[from]
        source: io::Error,
    },
    #[error("Failed to bind interface for client connection")]
    BindInterface {
        #[from]
        source: BindInterfaceError,
    },
}

#[derive(Debug, Error)]
#[error(
    "Failed to bind interface `{}` for client connection",
    bind_uri.as_ref().map_or(String::from("<no bind uri generated>"), |bind_uri| bind_uri.to_string())
)]
pub struct BindInterfaceError {
    bind_uri: Option<BindUri>,
    #[source]
    bind_error: io::Error,
}

impl QuicClient {
    #[inline]
    pub fn bind_ifaces(&self) -> HashMap<BindUri, BindInterface> {
        self.bind_ifaces
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    pub async fn bind(&self, bind_uri: impl Into<BindUri>) -> BindInterface {
        let bind_interface = self.network.bind(bind_uri.into()).await;
        self.bind_ifaces
            .insert(bind_interface.bind_uri(), bind_interface.clone());
        self.manual_bind.store(true, Ordering::Relaxed);
        bind_interface
    }

    #[inline]
    pub fn unbind(&self, bind_uri: &BindUri) -> Option<BindInterface> {
        self.bind_ifaces.remove(bind_uri).map(|(_, iface)| iface)
    }

    /// Creates a new QUIC connection to the specified server without any initial paths.
    ///
    /// This method initializes the connection state but does not start the handshake
    /// because no network paths are established yet. You must manually add paths
    /// using [`Connection::add_path`] to initiate communication.
    ///
    /// This is useful for advanced scenarios where you need fine-grained control
    /// over which interfaces and paths are used for the connection.
    pub fn new_connection(&self, server_name: impl Into<String>) -> Arc<Connection> {
        let connection = Connection::new_client(server_name.into(), self.token_sink.clone())
            .with_parameters(self.parameters.clone())
            .with_tls_config(self.tls_config.clone())
            .with_streams_concurrency_strategy(self.stream_strategy_factory.as_ref())
            .with_zero_rtt(self.tls_config.enable_early_data)
            .with_iface_factory(self.network.iface_factory.clone())
            .with_iface_manager(self.network.iface_manager.clone())
            .with_quic_router(self.network.quic_router.clone())
            .with_defer_idle_timeout(self.defer_idle_timeout)
            .with_cids(ConnectionId::random_gen(8))
            .with_qlog(self.qlogger.clone())
            .run();
        self.subscribe_connection_local_endpoints(connection.clone());
        connection
    }

    fn subscribe_connection_local_endpoints(&self, connection: Arc<Connection>) {
        let mut subscriber = self.network.local_endpoints.subscribe();
        let weak = Arc::downgrade(&connection);

        // Inherent termination: this task exits when the connection drops,
        // the connection terminates, or the LocalEndpoints subscriber ends.
        tokio::spawn(
            async move {
                loop {
                    let Some(terminated) = weak.upgrade().map(|connection| connection.terminated())
                    else {
                        break;
                    };
                    tokio::select! {
                        biased;
                        _ = terminated => break,
                        update = subscriber.recv() => {
                            let Some((bind_uri, update)) = update else { break };
                            let Some(connection) = weak.upgrade() else { break };
                            Self::feed_connection_local_endpoint(&connection, bind_uri, update);
                        }
                    }
                }
            }
            .in_current_span(),
        );
    }

    fn feed_connection_local_endpoint(
        connection: &Connection,
        bind_uri: BindUri,
        update: InterfaceEndpointUpdate,
    ) {
        let result = match update {
            InterfaceEndpointUpdate::Upsert { key, endpoint } => {
                connection.upsert_local_endpoint(bind_uri, key, endpoint)
            }
            InterfaceEndpointUpdate::Remove { key } => {
                connection.remove_local_endpoint(&bind_uri, &key)
            }
            InterfaceEndpointUpdate::Close => connection.close_local_endpoints(&bind_uri),
        };

        if let Err(error) = result {
            tracing::trace!(target: "dquic", ?error, "failed to feed local endpoint update to client connection");
        }
    }

    /// Builds a [`BindUri`] from the DNS [`Source`] and endpoint address.
    ///
    /// - For [`Source::Mdns`]: binds to the discovering NIC (e.g., `iface://v4.en0:0`).
    /// - For other sources: binds to a wildcard address matching the endpoint family.
    fn bind_uri_for(source: &Source, ep: &EndpointAddr) -> BindUri {
        match source {
            Source::Mdns { nic, family } => {
                let f = match family {
                    Family::V4 => "v4",
                    Family::V6 => "v6",
                };
                BindUri::from_str(&format!("iface://{f}.{nic}:0"))
                    .expect("iface URI should be valid")
                    .alloc_port()
            }
            _ => match ep.family() {
                Family::V4 => BindUri::from_str("inet://0.0.0.0:0")
                    .expect("URL should be valid")
                    .alloc_port(),
                Family::V6 => BindUri::from_str("inet://[::]:0")
                    .expect("URL should be valid")
                    .alloc_port(),
            },
        }
    }

    /// Ensures at least one interface exists for the given endpoint.
    async fn ensure_iface_for(&self, source: &Source, ep: &EndpointAddr) {
        if self.manual_bind.load(Ordering::Relaxed) {
            return;
        }
        if self.bind_ifaces.is_empty() {
            let bind_uri = Self::bind_uri_for(source, ep);
            let iface = self.network.bind(bind_uri).await;
            self.bind_ifaces.insert(iface.bind_uri(), iface);
        }
    }

    /// Returns matching bound interfaces or auto-binds a new one.
    async fn select_or_bind_ifaces(
        &self,
        source: &Source,
        ep: &EndpointAddr,
    ) -> Result<Vec<(SocketAddr, Interface)>, BindInterfaceError> {
        let iface_matches_source =
            |iface: &Interface| match source {
                Source::Mdns { nic, family } => iface.bind_uri().as_iface_bind_uri().is_some_and(
                    |(iface_family, iface_name, _)| {
                        iface_family == *family && iface_name == nic.as_ref()
                    },
                ),
                _ => true,
            };

        if self.manual_bind.load(Ordering::Relaxed) {
            let ifaces = self
                .bind_ifaces
                .iter()
                .map(|entry| entry.value().borrow())
                .filter(|iface| iface_matches_source(iface))
                .filter_map(|iface| Some((iface.bound_addr().ok()?, iface)))
                .filter(|(addr, _)| addr.family() == ep.family())
                .collect::<Vec<_>>();
            Ok(ifaces)
        } else {
            let ifaces = self
                .bind_ifaces
                .iter()
                .map(|entry| entry.value().borrow())
                .filter(|iface| iface_matches_source(iface))
                .filter_map(|iface| Some((iface.bound_addr().ok()?, iface)))
                .filter(|(addr, _)| addr.family() == ep.family())
                .collect::<Vec<_>>();
            if !ifaces.is_empty() {
                return Ok(ifaces);
            }
            let bind_uri = Self::bind_uri_for(source, ep);
            let iface = self.network.bind(bind_uri.clone()).await.borrow();
            let bound_addr = iface.bound_addr().map_err(|source| BindInterfaceError {
                bind_uri: Some(bind_uri),
                bind_error: source,
            })?;
            Ok(vec![(bound_addr, iface)])
        }
    }

    /// Probes and generates potential network paths to the given server endpoints.
    ///
    /// Each endpoint is paired with its DNS [`Source`] so that the correct network
    /// interface can be selected:
    ///
    /// - **Direct endpoints**: selects matching bound interfaces or auto-binds a new one,
    ///   then constructs [`Link`] and [`Pathway`] for each.
    /// - **Agent endpoints**: ensures an interface exists but does **not** build a path —
    ///   the puncher system handles Agent paths after STUN discovery.
    ///
    /// Returns a list of `(Interface, Link, Pathway)` tuples for Direct endpoints only.
    ///
    /// ### Example
    ///
    /// ```no_run
    /// # use dquic::prelude::*;
    /// # use dquic::qresolve::Source;
    /// # async fn example(quic_client: &QuicClient) -> Result<(), Box<dyn std::error::Error>> {
    /// let server_addresses: Vec<_> = tokio::net::lookup_host("genmeta.net:443")
    ///     .await?
    ///     .map(|addr| (Source::System, addr.into()))
    ///     .collect();
    /// let paths = quic_client.probe(server_addresses).await?;
    /// let connection = quic_client.new_connection("genmeta.net");
    /// for (iface, link, pathway) in paths {
    ///     connection.add_path((iface.bind_uri(), pathway, link))?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn probe(
        &self,
        server_eps: impl IntoIterator<Item = (Source, EndpointAddr)>,
    ) -> Result<Vec<(Interface, Link, Pathway)>, BindInterfaceError> {
        let server_eps = server_eps.into_iter().collect::<Vec<_>>();

        let mut paths = vec![];
        for (source, server_ep) in server_eps {
            if matches!(server_ep, EndpointAddr::Agent { .. }) {
                self.ensure_iface_for(&source, &server_ep).await;
            } else {
                let ifaces = self.select_or_bind_ifaces(&source, &server_ep).await?;

                paths.extend(ifaces.into_iter().map(move |(bound_addr, iface)| {
                    let dst = *server_ep;
                    let link = Link::new(bound_addr, dst);
                    let pathway = Pathway::new(bound_addr.into(), server_ep);
                    (iface, link, pathway)
                }));
            }
        }

        Ok(paths)
    }

    /// Processes a single server endpoint for the given connection:
    /// 1. Registers the peer endpoint (with its DNS source) in the connection's address book.
    /// 2. Probes for immediate paths (Direct endpoints) or ensures an interface
    ///    is bound (Agent endpoints).  See [`Self::probe`] for details.
    /// 3. Adds any resulting Direct paths to the connection.
    ///
    /// Returns `true` if at least one Direct path was added.
    async fn setup_server_endpoint(
        &self,
        connection: &Connection,
        source: Source,
        server_ep: EndpointAddr,
    ) -> Result<bool, BindInterfaceError> {
        // Register the peer endpoint with its DNS source — the puncher will
        // only auto-create paths with local endpoints matching the source constraint
        // (e.g. mDNS endpoints are restricted to the discovering NIC).
        _ = connection.add_peer_endpoint(server_ep, source.clone());

        // probe() handles both Direct and Agent uniformly:
        //   Direct → select/bind interface, construct Link & Pathway, return paths.
        //   Agent  → ensure an interface is bound, return empty paths.
        let paths = self.probe([(source, server_ep)]).await?;
        let mut has_direct_path = false;
        for (iface, link, pathway) in paths {
            match connection.add_path((iface.bind_uri(), pathway, link)) {
                Ok(()) => has_direct_path = true,
                Err(error) => {
                    tracing::trace!(target: "dquic", %error, "skipping probed path candidate");
                }
            }
        }
        Ok(has_direct_path)
    }

    /// Connects to a server using specific endpoint addresses.
    ///
    /// This method combines [`QuicClient::probe`] and [`QuicClient::new_connection`].
    /// It creates a connection and automatically adds paths for all the provided
    /// server endpoints.
    ///
    /// The returned [`Connection`] may not have completed the handshake yet.
    /// However, any asynchronous operations on the connection (like opening streams)
    /// will automatically wait for the handshake to complete.
    ///
    /// If `server_eps` is empty, this is equivalent to calling [`QuicClient::new_connection`]
    /// and the connection will remain idle until paths are added.
    ///
    /// This variant preserves the DNS [`Source`] so that the correct network interface
    /// is selected for each endpoint (e.g., mDNS endpoints bind to the discovering NIC).
    pub async fn connected_to_with_source(
        &self,
        server_name: impl Into<String>,
        server_eps: impl IntoIterator<Item = (Source, EndpointAddr)>,
    ) -> Result<Arc<Connection>, ConnectServerError> {
        let connection = self.new_connection(server_name);
        for (source, server_ep) in server_eps {
            self.setup_server_endpoint(&connection, source, server_ep)
                .await
                .map_err(|source| ConnectServerError::BindInterface { source })?;
        }
        Ok(connection)
    }

    /// Connects to a server by its hostname and optional port.
    ///
    /// This is the most convenient way to establish a connection. It performs the following steps:
    /// 1. Parses the server string (e.g., "example.com" or "example.com:443").
    ///    Defaults to port 443 if not specified.
    /// 2. Performs an asynchronous DNS lookup to resolve the hostname to IP addresses.
    /// 3. Calls [`QuicClient::connected_to_with_source`] with the resolved addresses.
    ///
    /// The returned [`Connection`] may not have completed the handshake yet.
    /// Asynchronous operations on the connection will wait for the handshake.
    pub async fn connect(
        self: &Arc<Self>,
        server: &str,
    ) -> Result<Arc<Connection>, ConnectServerError> {
        let mut server_eps = self
            .network
            .resolver
            .lookup(server)
            .await
            .map_err(|source| ConnectServerError::Dns { source })?;

        let connection = self.new_connection(server);

        let mut last_error: Option<ConnectServerError> = None;

        // Consume the DNS stream until we get at least one Direct path,
        // or exhaust all endpoints (Agent-only is acceptable).
        //
        // `last_error` doubles as a "no viable endpoint yet" sentinel:
        // - On `Ok(false)` (Agent registered): clear it — we have a viable fallback.
        // - On `Err`: set/keep it — probe failure, keep looking.
        // - On stream exhaustion: if still `Some`, nothing viable → propagate error.
        while let Some((source, server_ep)) = server_eps.next().await {
            match self
                .setup_server_endpoint(&connection, source, server_ep)
                .await
            {
                Ok(true) => {
                    last_error = None; // Got a Direct path, proceed.
                    break;
                }
                Ok(false) => {
                    // Agent endpoint registered — even if later Direct probes fail,
                    // the puncher can still establish paths asynchronously.
                    last_error = None;
                }
                Err(error) => {
                    last_error.get_or_insert(error.into());
                }
            }
        }
        if let Some(error) = last_error {
            return Err(error);
        }

        // Background task: keep consuming the DNS stream for late-arriving endpoints.
        // Uses `Weak<Connection>` so this task does not keep the connection alive when
        // all external callers have dropped their `Arc<Connection>`. The task races
        // the DNS drain against `terminated()` so it exits promptly on shutdown.
        tokio::spawn({
            let weak_connection = Arc::downgrade(&connection);
            let terminated = connection.terminated();
            let client = self.clone();
            async move {
                tokio::pin!(terminated);
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut terminated => break,
                        next = server_eps.next() => {
                            let Some((source, server_ep)) = next else { break };
                            let Some(connection) = weak_connection.upgrade() else { break };
                            _ = client
                                .setup_server_endpoint(&connection, source, server_ep)
                                .await;
                        }
                    }
                }
            }
            .in_current_span()
        });

        Ok(connection)
    }
}

/// Builder for [`QuicClient`].
#[derive(Clone)]
pub struct QuicClientBuilder<T> {
    network: common::Network,

    // client
    bind_ifaces: DashMap<BindUri, BindInterface>,
    manual_bind: bool,
    // client: quic config(in initialize order)
    prefer_versions: Vec<u32>,
    token_sink: Arc<dyn TokenSink>,
    parameters: ClientParameters,
    tls_config: T,
    stream_strategy_factory: Arc<dyn ProductStreamsConcurrencyController>,
    defer_idle_timeout: Duration,
    qlogger: Arc<dyn QLog + Send + Sync>,
}

impl QuicClient {
    /// Create a new [`QuicClient`] builder.
    pub fn builder() -> QuicClientBuilder<TlsClientConfigBuilder<WantsVerifier>> {
        Self::builder_with_tls(TlsClientConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS13,
        ]))
    }

    /// Create a [`QuicClient`] builder with custom crypto provider.
    pub fn builder_with_crypto_provider(
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> QuicClientBuilder<TlsClientConfigBuilder<WantsVerifier>> {
        Self::builder_with_tls(
            TlsClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap(),
        )
    }

    /// Start to build a QuicClient with the given TLS configuration.
    ///
    /// This is useful when you want to customize the TLS configuration, or integrate qm-quic with other crates.
    pub fn builder_with_tls<T>(tls_config: T) -> QuicClientBuilder<T> {
        QuicClientBuilder {
            // network
            network: common::Network::default(),

            // client
            bind_ifaces: DashMap::new(),
            manual_bind: false,
            // client: quic config(in initialize order)
            prefer_versions: vec![1],
            token_sink: Arc::new(handy::NoopTokenRegistry),
            parameters: handy::client_parameters(),
            tls_config,
            stream_strategy_factory: Arc::new(handy::ConsistentConcurrency::new),
            defer_idle_timeout: Duration::ZERO,
            qlogger: Arc::new(handy::NoopLogger),
        }
    }
}

impl<T> QuicClientBuilder<T> {
    pub fn with_resolver(mut self, resolver: Arc<dyn Resolve + Send + Sync>) -> Self {
        self.network.resolver = resolver;
        self
    }

    pub fn physical_ifaces(mut self, physical_ifaces: &'static Devices) -> Self {
        self.network.devices = physical_ifaces;
        self
    }

    /// Specify how client bind interfaces.
    ///
    /// The given factory will be used by [`Self::bind`],
    /// and/or [`QuicClient::connect`] if no interface bound when client built.
    ///
    /// The default quic interface is provided by [`handy::DEFAULT_IO_FACTORY`].
    /// For Unix and Windows targets, this is a high performance UDP library supporting GSO and GRO
    /// provided by `qudp` crate. For other platforms, please specify you own factory.
    pub fn with_iface_factory(mut self, iface_factory: Arc<dyn ProductIO>) -> Self {
        self.network.iface_factory = iface_factory;
        self
    }

    /// Specify the interfaces manager for the client.
    pub fn with_iface_manager(mut self, iface_manager: Arc<InterfaceManager>) -> Self {
        self.network.iface_manager = iface_manager;
        self
    }

    pub fn with_router(mut self, router: Arc<QuicRouter>) -> Self {
        self.network.quic_router = router;
        self
    }

    pub fn with_stun(mut self, server: impl Into<Arc<str>>) -> Self {
        self.network.stun_server = Some(server.into());
        self
    }

    /// Specify the local endpoints for interface sharing.
    ///
    /// The given local endpoints hub is shared by all connections created by this client.
    pub fn with_local_endpoints(mut self, local_endpoints: Arc<LocalEndpoints>) -> Self {
        self.network.local_endpoints = local_endpoints;
        self
    }

    /// Create quic interfaces bound on given address.
    ///
    /// If the bind failed, the error will be returned immediately.
    ///
    /// The default quic interface is provided by [`handy::DEFAULT_IO_FACTORY`].
    /// For Unix and Windows targets, this is a high performance UDP library supporting GSO and GRO
    /// provided by `qudp` crate. For other platforms, please specify you own factory with
    /// [`QuicClientBuilder::with_iface_factory`].
    ///
    /// If you dont bind any address, each time the client initiates a new connection,
    /// the client will use bind a new interface on address and port that dynamic assigned by the system.
    ///
    /// To know more about how the client selects the interface when initiates a new connection,
    /// read [`QuicClient::connect`].
    ///
    /// If you call this multiple times, only the last set of interface will be used,
    /// previous bound interface will be freed immediately.
    ///
    /// If all interfaces are closed, clients will no longer be able to initiate new connections.
    pub async fn bind(mut self, bind_uris: impl IntoIterator<Item = impl Into<BindUri>>) -> Self {
        self.bind_ifaces = self
            .network
            .bind_many(bind_uris)
            .await
            .map(|bind_iface| (bind_iface.bind_uri(), bind_iface))
            .collect()
            .await;
        self.manual_bind = true;
        self
    }

    /// (WIP)Specify the quic versions that the client prefers.
    ///
    /// If you call this multiple times, only the last call will take effect.
    pub fn prefer_versions(mut self, versions: impl IntoIterator<Item = u32>) -> Self {
        self.prefer_versions.clear();
        self.prefer_versions.extend(versions);
        self
    }

    /// Specify the token sink for the client.
    ///
    /// The token sink is used to storage the tokens that the client received from the server. The client will use the
    /// tokens to prove it self to the server when it reconnects to the server. read [address verification] in quic rfc
    /// for more information.
    ///
    /// [address verification](https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation)
    pub fn with_token_sink(self, token_sink: Arc<dyn TokenSink>) -> Self {
        Self { token_sink, ..self }
    }

    /// Specify the [transport parameters] for the client.
    ///
    /// If you call this multiple times, only the last `parameters` will be used.
    ///
    /// Usually, you don't need to call this method, because the client will use a set of default parameters.
    ///
    /// [transport parameters](https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit)
    pub fn with_parameters(self, parameters: ClientParameters) -> Self {
        Self { parameters, ..self }
    }

    fn map_tls<T1>(self, f: impl FnOnce(T) -> T1) -> QuicClientBuilder<T1> {
        QuicClientBuilder {
            network: self.network,
            bind_ifaces: self.bind_ifaces,
            manual_bind: self.manual_bind,
            prefer_versions: self.prefer_versions,
            token_sink: self.token_sink,
            parameters: self.parameters,
            tls_config: f(self.tls_config),
            stream_strategy_factory: self.stream_strategy_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            qlogger: self.qlogger,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.parameters
            .set(ParameterId::ClientName, name.into())
            .expect("parameter 0xffee belong_to client and has type String");
        self
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

    /// Specify the streams concurrency strategy controller for the client.
    ///
    /// The streams controller is used to control the concurrency of data streams. `controller` is a closure that accept
    /// (initial maximum number of bidirectional streams, initial maximum number of unidirectional streams) configured in
    /// [transport parameters] and return a `ControlConcurrency` object.
    ///
    /// If you call this multiple times, only the last `controller` will be used.
    ///
    /// [transport parameters](https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit)
    pub fn with_streams_concurrency_strategy(
        self,
        stream_strategy_factory: Arc<dyn ProductStreamsConcurrencyController>,
    ) -> Self {
        Self {
            stream_strategy_factory,
            ..self
        }
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

impl QuicClientBuilder<TlsClientConfigBuilder<WantsVerifier>> {
    /// Choose how to verify server certificates.
    ///
    /// Read [TlsClientConfigBuilder::with_root_certificates] for more information.
    pub fn with_root_certificates(
        self,
        root_store: impl Into<Arc<rustls::RootCertStore>>,
    ) -> QuicClientBuilder<TlsClientConfigBuilder<WantsClientCert>> {
        self.map_tls(|tls_config_builder| tls_config_builder.with_root_certificates(root_store))
    }

    /// Choose how to verify server certificates using a webpki verifier.
    ///
    /// Read [TlsClientConfigBuilder::with_webpki_verifier] for more information.
    pub fn with_webpki_verifier(
        self,
        verifier: Arc<rustls::client::WebPkiServerVerifier>,
    ) -> QuicClientBuilder<TlsClientConfigBuilder<WantsClientCert>> {
        self.map_tls(|tls_config_builder| tls_config_builder.with_webpki_verifier(verifier))
    }

    /// Replace the default server certificate verifier with a custom one.
    ///
    /// This exposes rustls' low-level custom verifier hook. The provided
    /// verifier becomes fully responsible for server certificate validation,
    /// including any WebPKI, OCSP, pinning, or private PKI checks you require.
    pub fn with_custom_server_cert_verifier(
        self,
        verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    ) -> QuicClientBuilder<TlsClientConfigBuilder<WantsClientCert>> {
        self.map_tls(|tls_config_builder| {
            tls_config_builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
        })
    }

    /// Dangerously disable server certificate verification.
    pub fn without_verifier(self) -> QuicClientBuilder<TlsClientConfigBuilder<WantsClientCert>> {
        #[derive(Debug)]
        struct DangerousServerCertVerifier;

        impl rustls::client::danger::ServerCertVerifier for DangerousServerCertVerifier {
            fn verify_server_cert(
                &self,
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &[rustls::pki_types::CertificateDer<'_>],
                _: &rustls::pki_types::ServerName<'_>,
                _: &[u8],
                _: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::RSA_PKCS1_SHA1,
                    rustls::SignatureScheme::ECDSA_SHA1_Legacy,
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::RSA_PKCS1_SHA384,
                    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                    rustls::SignatureScheme::RSA_PKCS1_SHA512,
                    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA384,
                    rustls::SignatureScheme::RSA_PSS_SHA512,
                    rustls::SignatureScheme::ED25519,
                    rustls::SignatureScheme::ED448,
                ]
            }
        }

        self.map_tls(|tls_config_builder| {
            tls_config_builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerousServerCertVerifier))
        })
    }
}

impl QuicClientBuilder<TlsClientConfigBuilder<WantsClientCert>> {
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// Read [TlsClientConfigBuilder::with_single_cert] for more information.
    pub fn with_cert(
        self,
        cert: impl handy::ToCertificate,
        key: impl handy::ToPrivateKey,
    ) -> QuicClientBuilder<TlsClientConfig> {
        self.map_tls(|tls_config_builder| {
            tls_config_builder
                .with_client_auth_cert(cert.to_certificate(), key.to_private_key())
                .expect("The private key was wrong encoded or failed validation")
        })
    }

    /// Do not support client auth.
    pub fn without_cert(self) -> QuicClientBuilder<TlsClientConfig> {
        self.map_tls(|tls_config_builder| tls_config_builder.with_no_client_auth())
    }
    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_cert_resolver(
        self,
        cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> QuicClientBuilder<TlsClientConfig> {
        self.map_tls(|tls_config_builder| {
            tls_config_builder.with_client_cert_resolver(cert_resolver)
        })
    }
}

impl QuicClientBuilder<TlsClientConfig> {
    /// Specify the [alpn-protocol-ids] that will be sent in `ClientHello`.
    ///
    /// By default, its empty and the APLN extension wont be sent.
    ///
    /// If you call this multiple times, all the `alpn_protocol` will be used.
    ///
    /// [alpn-protocol-ids](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids)
    pub fn with_alpns(mut self, alpns: impl IntoIterator<Item = impl Into<Vec<u8>>>) -> Self {
        self.tls_config
            .alpn_protocols
            .extend(alpns.into_iter().map(Into::into));
        self
    }

    /// Enable the `keylog` feature.
    ///
    /// This is useful when you want to debug the TLS connection.
    ///
    /// The keylog file will be in the file that environment veriable `SSLKEYLOGFILE` pointed to.
    ///
    /// Read [`rustls::KeyLogFile`] for more information.
    pub fn enable_sslkeylog(mut self) -> Self {
        self.tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        self
    }

    pub fn enable_0rtt(mut self) -> Self {
        self.tls_config.enable_early_data = true;
        self
    }

    /// Build the QuicClient, ready to initiates connect to the servers.
    pub fn build(self) -> QuicClient {
        QuicClient {
            network: self.network,
            bind_ifaces: self.bind_ifaces,
            manual_bind: Arc::new(AtomicBool::new(self.manual_bind)),
            _prefer_versions: self.prefer_versions,
            token_sink: self.token_sink,
            parameters: self.parameters,
            tls_config: self.tls_config,
            stream_strategy_factory: self.stream_strategy_factory,
            defer_idle_timeout: self.defer_idle_timeout,
            qlogger: self.qlogger,
        }
    }
}

#[cfg(test)]
mod local_endpoint_subscription_tests {
    #[test]
    fn quic_client_subscribes_per_connection_without_qconnection_subscription_api() {
        let source = include_str!("client.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module boundary");
        assert!(production.contains(concat!("fn subscribe_connection_", "local_endpoints")));
        assert!(production.contains(concat!("local_endpoints", ".subscribe()")));
        assert!(production.contains(concat!("InterfaceEndpoint", "Update::Upsert")));
        assert!(!production.contains(concat!("subscribe_local_", "address_events")));
    }
}
