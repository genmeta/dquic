use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    ops::BitOr,
    sync::{Arc, OnceLock, RwLock},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use qbase::{
    cid::{ConnectionId, GenUniqueCid},
    endpoint::Endpoint,
    error::{ErrorKind, QuicError},
    net::tx::ArcSendWakers,
    packet::{GetDcid, GetScid},
    param::{ClientParameters, ParameterId, ServerParameters, WriteParameters},
    time::{ArcConnIdle, DEFAULT_HEARTBEAT_INTERVAL},
    token::{ArcTokenRegistry, handy::NoopTokenRegistry},
};
use qtransport::{packet::channel, path::Path, router::QuicRouter, space::ArcFeedback};
use tokio::sync::oneshot;

use crate::{
    Accepted, ArcConnPhase, Connected, Error, InitialPhase, Paths, ReliableFrames, TlsContext,
    client_growing,
};

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
        let server_parameters = Arc::new(self.server_parameters.clone());
        let mut encoded_server_parameters = BytesMut::new();
        encoded_server_parameters.put_parameters(&server_parameters);
        ServerRegistry::global().insert(
            self.identity.name().to_owned(),
            Server {
                tls_server: self.tls_server()?,
                server_parameters,
                encoded_server_parameters: encoded_server_parameters.freeze(),
                scopes: scopes.into(),
                accept_cb: Arc::new(accept_cb),
            },
        );
        Ok(())
    }

    fn tls_server(&self) -> Result<qtls::TlsServer, Error> {
        qtls::TlsServer::new(qtls::ServerTlsConfig {
            provider: Arc::new(qtls::default_provider()),
            alpn: Vec::new(),
            local: self.local_authority()?,
            resumption: qtls::ServerResumptionConfig::Disabled,
            limits: Default::default(),
        })
        .map_err(|error| internal_error(error.to_string()))
    }

    /// Starts the client connection skeleton. Path discovery and insertion are wired later.
    pub async fn connect(&self, server_name: String) -> Result<Connected, Error> {
        let identity = qtls::TlsClient::new(qtls::ClientTlsConfig {
            provider: Arc::new(qtls::default_provider()),
            alpn: Vec::new(),
            local: Some(self.local_authority()?),
            resumption: qtls::ClientResumptionConfig::Disabled,
            limits: Default::default(),
        })
        .map_err(|error| internal_error(error.to_string()))?;
        let odcid = ConnectionId::random_gen(8);
        let initial_keys = identity
            .initial_keys(qtls::QuicVersion::V1, odcid.as_ref())
            .map_err(|error| internal_error(error.to_string()))?;
        let wakers = ArcSendWakers::new();
        let reliable_frames = ReliableFrames::with_capacity_and_wakers(0, wakers.clone());
        let (inbox, rcvd_pkt) = channel::new();
        let cid_registry =
            QuicRouter::global().registry_on_issuing_scid(inbox, reliable_frames.clone());
        let scid = cid_registry.gen_unique_cid();
        let mut client_parameters = self.client_parameters.clone();
        client_parameters
            .set(ParameterId::InitialSourceConnectionId, scid)
            .map_err(|error| internal_error(error.to_string()))?;
        let tls = TlsContext::client(
            &identity,
            server_name
                .clone()
                .try_into()
                .map_err(|error| internal_error(format!("invalid server name: {error}")))?,
            &client_parameters,
        )?;
        let phase = ArcConnPhase::new(InitialPhase::with_components(
            scid,
            odcid,
            initial_keys,
            wakers,
            reliable_frames,
        ));
        let paths = Arc::new(Paths::new(phase.clone()));
        let idle = ArcConnIdle::new(
            client_parameters.get(ParameterId::MaxIdleTimeout).unwrap(),
            Duration::ZERO,
            DEFAULT_HEARTBEAT_INTERVAL,
        );
        let token = ArcTokenRegistry::with_sink(server_name, Arc::new(NoopTokenRegistry));
        let (deliver, connected) = oneshot::channel();

        tokio::spawn(client_growing(
            phase,
            tls,
            client_parameters,
            cid_registry,
            rcvd_pkt,
            paths,
            idle,
            token,
            move |result| {
                let _ = deliver.send(result);
            },
        ));

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Scope {
    Loopback = 0b001,
    Internal = 0b010,
    External = 0b100,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scopes(u8);

impl Scopes {
    pub const ALL: Self =
        Self(Scope::Loopback as u8 | Scope::Internal as u8 | Scope::External as u8);

    pub fn contains(self, scope: Scope) -> bool {
        self.0 & scope as u8 != 0
    }
}

impl From<Scope> for Scopes {
    fn from(scope: Scope) -> Self {
        Self(scope as u8)
    }
}

impl BitOr for Scope {
    type Output = Scopes;

    fn bitor(self, rhs: Self) -> Self::Output {
        Scopes(self as u8 | rhs as u8)
    }
}

impl BitOr<Scope> for Scopes {
    type Output = Self;

    fn bitor(self, rhs: Scope) -> Self::Output {
        Self(self.0 | rhs as u8)
    }
}

impl BitOr for Scopes {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

pub trait BelongsTo {
    fn belongs_to(&self, scopes: Scopes) -> bool;
}

impl BelongsTo for SocketAddr {
    fn belongs_to(&self, scopes: Scopes) -> bool {
        let scope = if is_loopback(self.ip()) {
            Scope::Loopback
        } else if is_internal(self.ip()) {
            Scope::Internal
        } else if qbase::net::addr::EndpointAddr::direct(*self).is_globally_routable() {
            Scope::External
        } else {
            return false;
        };
        scopes.contains(scope)
    }
}

pub type AcceptCallback = dyn Fn(Result<Accepted, Error>) + Send + Sync;

pub struct Server {
    pub tls_server: qtls::TlsServer,
    pub server_parameters: Arc<ServerParameters>,
    pub encoded_server_parameters: Bytes,
    pub scopes: Scopes,
    pub accept_cb: Arc<AcceptCallback>,
}

impl Server {
    pub fn start(
        &self,
        version: qtls::QuicVersion,
        hello: qtls::incoming::ClientHello,
        scid: ConnectionId,
        odcid: ConnectionId,
    ) -> Result<(TlsContext, Arc<ClientParameters>, Arc<ServerParameters>), Error> {
        let mut server_parameters = (*self.server_parameters).clone();
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
                let peer_cid = *packet.scid();
                let (inbox, rcvd_pkt) = channel::new();
                let router = QuicRouter::global();
                let route = router.insert(odcid.into(), inbox.clone());
                let Some(initial_keys) = ServerRegistry::global().initial_keys(odcid) else {
                    return;
                };

                let send_wakers = ArcSendWakers::new();
                let reliable_frames =
                    ReliableFrames::with_capacity_and_wakers(0, send_wakers.clone());
                let cid_registry =
                    router.registry_on_issuing_scid(inbox.clone(), reliable_frames.clone());
                let scid = cid_registry.gen_unique_cid();
                let phase = ArcConnPhase::new(InitialPhase::with_components(
                    scid,
                    odcid,
                    initial_keys,
                    send_wakers,
                    reliable_frames,
                ));
                let idle =
                    ArcConnIdle::new(Duration::ZERO, Duration::ZERO, DEFAULT_HEARTBEAT_INTERVAL);
                let paths = Arc::new(Paths::new(phase.clone()));
                let path = Arc::new(Path::new(
                    pathway,
                    peer_cid,
                    Arc::new(qcongestion::HandshakeStatus::new(true)),
                    Duration::from_millis(25),
                    idle.timer(),
                    std::array::from_fn(|_| {
                        Arc::new(ArcFeedback::default()) as Arc<dyn qcongestion::Feedback>
                    }),
                ));
                phase
                    .get()
                    .initial()
                    .send_wakers
                    .replace(pathway, &path.send_waker);
                paths
                    .get_or_try_insert_with(pathway, || Ok::<_, Error>(path))
                    .expect("fresh server path");
                if !inbox.try_send_initial(packet, pathway, link) {
                    return;
                }

                tokio::spawn(crate::server_growing(
                    phase,
                    route,
                    rcvd_pkt,
                    paths,
                    idle,
                    ArcTokenRegistry::with_provider(Arc::new(NoopTokenRegistry)),
                    link,
                ));
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

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    }
}

fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|ip| ip.is_private() || ip.is_link_local())
        }
    }
}
