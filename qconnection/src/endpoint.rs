use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, OnceLock, RwLock},
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    cid::{ArcRemoteCids, ConnectionId, GenUniqueCid},
    endpoint::Endpoint,
    error::{ErrorKind, QuicError},
    net::route::Scopes,
    packet::{GetDcid, GetScid},
    param::{ClientParameters, ParameterId, ServerParameters, WriteParameters},
    role::Role,
    time::{ArcConnIdle, DEFAULT_HEARTBEAT_INTERVAL},
    token::{ArcTokenRegistry, handy::NoopTokenRegistry},
};
use qtransport::{packet::channel, router::QuicRouter};
use tokio::sync::oneshot;

use crate::{
    Accepted, ArcConnPhase, ArcLocalCids, ArcReliableFrames, CidRegistry, Connected, Error,
    InitialPhase, Paths, TlsContext, client_growing,
};

static DEFAULT_ALPN: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| vec![b"h3".to_vec()]);

pub struct QuicEndpoint {
    pub identity: Arc<Endpoint>,
    pub client_parameters: ClientParameters,
    pub server_parameters: ServerParameters,
}

impl QuicEndpoint {
    pub fn new(identity: Arc<Endpoint>) -> Self {
        Self {
            identity,
            client_parameters: ClientParameters::new(),
            server_parameters: ServerParameters::new(),
        }
    }

    pub fn set_server_parameters(
        &mut self,
        id: ParameterId,
        value: impl Into<qbase::param::ParameterValue>,
    ) -> Result<(), qbase::param::error::Error> {
        self.server_parameters.set(id, value)
    }

    /// Atomically publish or replace this server name for future connections.
    pub fn listen(
        &self,
        scopes: impl Into<Scopes>,
        accept_cb: impl Fn(Result<Accepted, Error>) + Send + Sync + 'static,
    ) -> Result<(), Error> {
        ServerRegistry::global().insert(
            self.identity.name().to_owned(),
            Server {
                tls_server: self.tls_server()?,
                server_parameters: self.server_parameters.clone(),
                scopes: scopes.into(),
                accept_cb: Arc::new(accept_cb),
            },
        );
        Ok(())
    }

    fn tls_server(&self) -> Result<qtls::TlsServer, Error> {
        qtls::TlsServer::new(qtls::ServerTlsConfig {
            provider: Arc::new(qtls::default_provider()),
            alpn: DEFAULT_ALPN.clone(),
            local: self.local_authority()?,
            resumption: qtls::ServerResumptionConfig::Disabled,
            limits: Default::default(),
        })
        .map_err(|error| internal_error(error.to_string()))
    }

    /// Resolve the peer in the background and add every usable AddressBook pairing.
    /// Uses the sources registered with [`qresolve::Resolver::add`].
    /// The client lifecycle owns discovery and stops it when the connection closes.
    pub async fn connect(&self, server_name: String) -> Result<Connected, Error> {
        let tls_name = qresolve::split_host_port(&server_name).0.to_owned();
        let identity = qtls::TlsClient::new(qtls::ClientTlsConfig {
            provider: Arc::new(qtls::default_provider()),
            alpn: DEFAULT_ALPN.clone(),
            local: Some(self.local_authority()?),
            resumption: qtls::ClientResumptionConfig::Disabled,
            limits: Default::default(),
        })
        .map_err(|error| internal_error(error.to_string()))?;
        let origin_dcid = ConnectionId::random_gen(8);
        let initial_keys = identity
            .initial_keys(qtls::QuicVersion::V1, origin_dcid.as_ref())
            .map_err(|error| internal_error(error.to_string()))?;
        let reliable_frames = ArcReliableFrames::with_capacity(0);
        let (inbox, rcvd_pkt) = channel::new();
        let router_registry =
            QuicRouter::global().registry_on_issuing_scid(inbox, reliable_frames.clone());
        let initial_scid = router_registry.gen_unique_cid();
        let mut client_params = self.client_parameters.clone();
        client_params
            .set(ParameterId::InitialSourceConnectionId, initial_scid)
            .map_err(|error| internal_error(error.to_string()))?;
        let tls = TlsContext::client(
            &identity,
            tls_name
                .clone()
                .try_into()
                .map_err(|error| internal_error(format!("invalid server name: {error}")))?,
            &client_params,
        )?;
        let cid_registry = CidRegistry::new(
            Role::Client,
            origin_dcid,
            ArcLocalCids::new(initial_scid, router_registry),
            ArcRemoteCids::new(
                client_params.get::<u64>(ParameterId::ActiveConnectionIdLimit),
                reliable_frames.clone(),
            ),
        );
        let phase = ArcConnPhase::initial(InitialPhase::new(
            (initial_scid, origin_dcid),
            initial_keys,
            reliable_frames,
            cid_registry,
        ));
        let idle = ArcConnIdle::new(
            client_params.get::<Duration>(ParameterId::MaxIdleTimeout),
            Duration::ZERO,
            DEFAULT_HEARTBEAT_INTERVAL,
        );
        let paths = Paths::new(Role::Client, phase, idle);
        let token = ArcTokenRegistry::with_sink(tls_name, Arc::new(NoopTokenRegistry));
        let (deliver, connected) = oneshot::channel();

        let tick = crate::recv::tick(paths.clone());
        let growing = client_growing(
            server_name,
            client_params,
            paths,
            rcvd_pkt,
            tls,
            token,
            move |result| {
                let _ = deliver.send(result);
            },
        );
        tokio::spawn(async move { tokio::join!(growing, tick).0 });

        connected
            .await
            .map_err(|error| internal_error(error.to_string()))?
    }

    fn local_authority(&self) -> Result<qtls::LocalAuthority, Error> {
        qtls::LocalAuthority::from_signing_key(
            Arc::from(self.identity.name()),
            self.identity.cert_chain().to_vec(),
            self.identity.signing_key().clone(),
            self.identity.ocsp().to_vec(),
        )
        .map_err(|error| internal_error(error.to_string()))
    }
}

pub type AcceptCallback = dyn Fn(Result<Accepted, Error>) + Send + Sync;

pub struct Server {
    pub tls_server: qtls::TlsServer,
    pub server_parameters: ServerParameters,
    pub scopes: Scopes,
    pub accept_cb: Arc<AcceptCallback>,
}

impl Server {
    pub fn spawn_connection_with(
        &self,
        version: qtls::QuicVersion,
        hello: qtls::incoming::ClientHello,
        scid: ConnectionId,
        odcid: ConnectionId,
    ) -> Result<(TlsContext, Arc<ClientParameters>, Arc<ServerParameters>), Error> {
        let mut server_parameters = self.server_parameters.clone();
        server_parameters
            .set(ParameterId::InitialSourceConnectionId, scid)
            .map_err(|error| internal_error(error.to_string()))?;
        server_parameters
            .set(ParameterId::OriginalDestinationConnectionId, odcid)
            .map_err(|error| internal_error(error.to_string()))?;
        let server_parameters = Arc::new(server_parameters);
        let mut encoded_server_parameters = BytesMut::new();
        encoded_server_parameters.put_parameters(&server_parameters);
        let (tls, client_parameters) = TlsContext::server(
            &self.tls_server,
            version,
            encoded_server_parameters.freeze(),
            hello,
        )?;
        Ok((tls, client_parameters, server_parameters))
    }
}

/// The process-wide SNI registry. Each lookup returns one immutable server snapshot.
pub struct ServerRegistry(RwLock<HashMap<String, Arc<Server>>>);

impl ServerRegistry {
    pub fn global() -> &'static Self {
        static GLOBAL: OnceLock<ServerRegistry> = OnceLock::new();
        GLOBAL.get_or_init(|| {
            QuicRouter::global().on_incoming(|packet, pathway, link| {
                let odcid = *packet.dcid();
                let client_scid = *packet.scid();
                let (inbox, rcvd_pkt) = channel::new();
                let router = QuicRouter::global();
                let route = router.insert(odcid.into(), inbox.clone());
                let Some(initial_keys) = ServerRegistry::global().initial_keys(odcid) else {
                    return;
                };

                let reliable_frames = ArcReliableFrames::with_capacity(0);
                let router_registry =
                    router.registry_on_issuing_scid(inbox.clone(), reliable_frames.clone());
                let initial_scid = router_registry.gen_unique_cid();
                let cid_registry = CidRegistry::new(
                    Role::Server,
                    odcid,
                    ArcLocalCids::new(initial_scid, router_registry),
                    ArcRemoteCids::new(2, reliable_frames.clone()),
                );
                let phase = ArcConnPhase::initial(InitialPhase::new(
                    (initial_scid, client_scid),
                    initial_keys,
                    reliable_frames,
                    cid_registry,
                ));
                let idle =
                    ArcConnIdle::new(Duration::ZERO, Duration::ZERO, DEFAULT_HEARTBEAT_INTERVAL);
                let paths = Paths::new(Role::Server, phase, idle);
                if !inbox.try_send_initial(packet, pathway, link) {
                    return;
                }

                let tick = crate::recv::tick(paths.clone());
                let growing = crate::server_growing(
                    rcvd_pkt,
                    paths,
                    ArcTokenRegistry::with_provider(Arc::new(NoopTokenRegistry)),
                );
                tokio::spawn(async move {
                    // Keep late Initial packets on this route through Closing/Draining.
                    let reason = tokio::join!(growing, tick).0;
                    // Dropping the guard removes the ODCID entry from the router.
                    drop(route);
                    reason
                });
            });
            Self(RwLock::new(HashMap::new()))
        })
    }

    fn initial_keys(&self, odcid: ConnectionId) -> Option<qtls::BidirectionalKeys> {
        let server = self.0.read().unwrap().values().next()?.clone();
        server
            .tls_server
            .initial_keys(qtls::QuicVersion::V1, odcid.as_ref())
            .ok()
    }

    fn insert(&self, server_name: String, server: Server) -> Option<Arc<Server>> {
        self.0
            .write()
            .unwrap()
            .insert(server_name, Arc::new(server))
    }

    pub fn remove(&self, server_name: &str) -> Option<Arc<Server>> {
        self.0.write().unwrap().remove(server_name)
    }

    pub fn get(&self, server_name: &str) -> Option<Arc<Server>> {
        self.0.read().unwrap().get(server_name).cloned()
    }
}

fn internal_error(reason: impl Into<String>) -> Error {
    QuicError::with_default_fty(ErrorKind::Internal, reason.into()).into()
}
