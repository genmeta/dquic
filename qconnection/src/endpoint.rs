use std::{
    collections::HashMap,
    sync::{Arc, OnceLock, RwLock},
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    cid::{ConnectionId, GenUniqueCid},
    endpoint::{Anonymous, Endpoint},
    error::{AppError, ErrorKind, QuicError},
    net::route::Scopes,
    packet::{GetDcid, GetScid},
    param::{ClientParameters, ParameterId, ParameterValue, ServerParameters, WriteParameters},
    role::Role,
    token::{ArcTokenRegistry, handy::NoopTokenRegistry},
};
use qtransport::{packet::channel, router::QuicRouter};
use tokio::sync::oneshot;

use crate::{
    Accepted, ArcLocalCids, ArcReliableFrames, Connected, Error, Paths, TlsContext, client_growing,
};

/// A QUIC endpoint with optional local credentials.
/// Anonymous endpoints can connect; listening requires an identity.
pub struct QuicEndpoint {
    identity: Option<Arc<Endpoint>>,
    /// Protocols offered by clients and accepted by servers, in preference order.
    alpn: Vec<Vec<u8>>,
    client_parameters: ClientParameters,
    server_parameters: ServerParameters,
}

impl From<Endpoint> for QuicEndpoint {
    fn from(identity: Endpoint) -> Self {
        Self::from(Arc::new(identity))
    }
}

impl From<Option<Endpoint>> for QuicEndpoint {
    fn from(identity: Option<Endpoint>) -> Self {
        Self::from(identity.map(Arc::new))
    }
}

impl From<Arc<Endpoint>> for QuicEndpoint {
    fn from(identity: Arc<Endpoint>) -> Self {
        Self::from(identity)
    }
}

impl From<Option<Arc<Endpoint>>> for QuicEndpoint {
    fn from(identity: Option<Arc<Endpoint>>) -> Self {
        Self::from(identity)
    }
}

impl From<Anonymous> for QuicEndpoint {
    fn from(_: Anonymous) -> Self {
        Self::from(None)
    }
}

impl QuicEndpoint {
    pub fn from(identity: impl Into<Option<Arc<Endpoint>>>) -> Self {
        Self {
            identity: identity.into(),
            alpn: vec![b"h3".to_vec()],
            client_parameters: ClientParameters::default(),
            server_parameters: ServerParameters::default(),
        }
    }

    pub fn anonymous() -> Self {
        Self::from(None)
    }

    /// Sets ALPN protocols in preference order for subsequent connect and listen calls.
    pub fn set_alpn(&mut self, alpn: Vec<Vec<u8>>) {
        self.alpn = alpn;
    }

    pub fn set_parameters(
        &mut self,
        role: Role,
        id: ParameterId,
        value: impl Into<ParameterValue>,
    ) -> Result<(), qbase::param::error::Error> {
        match role {
            Role::Client => self.client_parameters.set(id, value),
            Role::Server => self.server_parameters.set(id, value),
        }
    }

    /// Atomically publish or replace this server name for future connections.
    /// Anonymous endpoints log a warning and return without listening.
    /// The callback receives only successfully handshaken connections.
    pub fn listen(
        &self,
        scopes: impl Into<Scopes>,
        accept_cb: impl Fn(Accepted) + Send + Sync + 'static,
    ) -> Result<(), Error> {
        let Some(identity) = self.identity.as_deref() else {
            tracing::warn!("anonymous QUIC endpoint cannot listen");
            return Ok(());
        };
        // Validate credentials before initializing the global incoming registry.
        let tls_server = self.tls_server(identity)?;
        ServerRegistry::global().insert(
            identity.name().to_owned(),
            Server {
                tls_server,
                server_parameters: self.server_parameters.clone(),
                scopes: scopes.into(),
                accept_cb: Arc::new(accept_cb),
            },
        );
        Ok(())
    }

    fn tls_server(&self, identity: &Endpoint) -> Result<qtls::TlsServer, Error> {
        let authority = Self::authority(identity)?;
        qtls::TlsServer::new(qtls::ServerTlsConfig {
            provider: Arc::new(qtls::default_provider()),
            alpn: self.alpn.clone(),
            authority,
            resumption: qtls::ServerResumptionConfig::Disabled,
            limits: Default::default(),
        })
        .map_err(|error| internal_error(error.to_string()))
    }

    /// Resolve the peer in the background and add every usable AddressBook pairing.
    /// Uses the sources registered with [`qresolve::Resolver::add`].
    /// The client lifecycle owns discovery and stops it when the connection closes.
    /// Dropping this future before delivery closes the pending connection and discovery.
    pub async fn connect(&self, server_name: String) -> Result<Connected, Error> {
        let local = self.identity.as_deref().map(Self::authority).transpose()?;
        let tls_name = qresolve::split_host_port(&server_name).0.to_owned();
        // Deployed peers bind the TLS client certificate to this transport name.
        // Derive it from the same authority; anonymous clients do not advertise one.
        let mut client_parameters = self.client_parameters.clone();
        if let Some(authority) = local.as_ref() {
            client_parameters
                .set(ParameterId::ClientName, authority.name().to_owned())
                .map_err(|error| internal_error(error.to_string()))?;
        }
        let identity = qtls::TlsClient::new(qtls::ClientTlsConfig {
            provider: Arc::new(qtls::default_provider()),
            alpn: self.alpn.clone(),
            authority: local,
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
        let mut client_params = client_parameters;
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
        let local_cids =
            ArcLocalCids::new(Role::Client, origin_dcid, initial_scid, router_registry);
        let paths = Paths::new(
            Role::Client,
            (initial_scid, origin_dcid),
            initial_keys,
            reliable_frames,
            local_cids,
            client_params.get::<Duration>(ParameterId::MaxIdleTimeout),
            Duration::ZERO,
        );
        let token = ArcTokenRegistry::with_sink(tls_name, Arc::new(NoopTokenRegistry));
        let (deliver, connected) = oneshot::channel();
        let (claim, claimed) = oneshot::channel::<()>();
        let pending_paths = paths.clone();

        let tick = crate::recv::tick(paths.clone());
        let growing = client_growing(
            server_name,
            client_params,
            paths,
            rcvd_pkt,
            tls,
            token,
            move |result| {
                if let Err(Ok((_, _, connection))) = deliver.send(result) {
                    connection.close(0u32.into(), "connection request cancelled");
                }
            },
        );
        tokio::spawn(async move {
            let driving = async { tokio::join!(growing, tick).0 };
            tokio::pin!(driving);
            tokio::select! {
                reason = &mut driving => reason,
                result = claimed => {
                    if result.is_err() {
                        pending_paths.terminator.close(
                            crate::CloseReason::App(AppError::new(
                                0u32.into(),
                                "connection request cancelled",
                            )),
                            pending_paths.closing_pto(),
                        );
                    }
                    // Keep driving Closing/Draining, or the successfully claimed connection.
                    driving.await
                }
            }
        });

        let result = connected
            .await
            .map_err(|error| internal_error(error.to_string()))?;
        // There is no await between receiving the connection and transferring ownership.
        let _ = claim.send(());
        result
    }

    fn authority(identity: &Endpoint) -> Result<qtls::LocalAuthority, Error> {
        qtls::LocalAuthority::from_signing_key(
            Arc::from(identity.name()),
            identity.cert_chain().to_vec(),
            identity.signing_key().clone(),
            identity.ocsp().to_vec(),
        )
        .map_err(|error| internal_error(error.to_string()))
    }
}

pub type AcceptCallback = dyn Fn(Accepted) + Send + Sync;

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
                let reliable_frames = ArcReliableFrames::with_capacity(0);
                let router_registry =
                    router.insert(odcid.into(), inbox.clone(), reliable_frames.clone());
                let initial_scid = router_registry.gen_unique_cid();
                let local_cids =
                    ArcLocalCids::new(Role::Server, odcid, initial_scid, router_registry);
                let Some(initial_keys) = ServerRegistry::global().initial_keys(odcid) else {
                    return;
                };
                let paths = Paths::new(
                    Role::Server,
                    (initial_scid, client_scid),
                    initial_keys,
                    reliable_frames,
                    local_cids,
                    Duration::ZERO,
                    Duration::ZERO,
                );
                if !inbox.try_send_initial(packet, pathway, link) {
                    return;
                }

                let tick = crate::recv::tick(paths.clone());
                let growing = crate::server_growing(
                    rcvd_pkt,
                    paths,
                    ArcTokenRegistry::with_provider(Arc::new(NoopTokenRegistry)),
                );
                tokio::spawn(async move { tokio::join!(growing, tick).0 });
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
