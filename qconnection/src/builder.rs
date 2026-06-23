use std::{
    net::SocketAddr,
    sync::{Arc, Weak, atomic::AtomicBool},
    time::Duration,
};

use qbase::{
    cid::{ConnectionId, GenUniqueCid},
    error::Error,
    net::tx::{ArcSendWakers, Signals},
    packet::keys::ArcZeroRttKeys,
    param::{ArcParameters, ClientParameters, ParameterId, Parameters, ServerParameters},
    role::{IntoRole, Role},
    sid::{
        ControlStreamsConcurrency, ProductStreamsConcurrencyController, handy::DemandConcurrency,
    },
    time::ArcIdleConfig,
    token::{ArcTokenRegistry, TokenProvider, TokenSink},
};
use qcongestion::HandshakeStatus;
use qdatagram::DatagramFlow;
use qevent::{
    GroupID,
    quic::{
        Owner,
        transport::{ParametersRestored, ParametersSet},
    },
    telemetry::{Instrument, QLog, handy::NoopLogger},
};
use qinterface::{
    component::{
        location::Locations,
        route::{QuicRouter, RcvdPacketQueue},
    },
    io::{ProductIO, handy::DEFAULT_IO_FACTORY},
    manager::InterfaceManager,
};
use qrecovery::crypto::CryptoStream;
use qtraversal::punch::puncher::ArcPuncher;
use rustls::{
    ClientConfig as TlsClientConfig, ServerConfig as TlsServerConfig, crypto::CryptoProvider,
};
use tokio::sync::mpsc;
use tracing::Instrument as _;

use crate::{
    ArcLocalCids, ArcReliableFrameDeque, ArcRemoteCids, CidRegistry, Components, Connection,
    DataJournal, DataStreams, FlowController, Handshake, QuicRouterRegistry, RawHandshake,
    SpecificComponents,
    events::{ArcEventBroker, EmitEvent, Event},
    path::ArcPathContexts,
    space::{
        Spaces, data::DataSpace, handshake::HandshakeSpace, initial::InitialSpace,
        spawn_deliver_and_parse,
    },
    state::ArcConnState,
    tls::{
        AcceptAllClientAuther, ArcSendLock, ArcTlsHandshake, AuthClient, ClientTlsSession,
        ServerTlsSession, TlsHandshakeInfo, TlsSession,
    },
    traversal::PunchTransaction,
};

impl Connection {
    pub fn new_client(server_name: String, token_sink: Arc<dyn TokenSink>) -> ClientFoundation {
        ClientFoundation {
            server_name: server_name.clone(),
            token_registry: ArcTokenRegistry::with_sink(server_name, token_sink),
            client_params: ClientParameters::default(),
        }
    }

    pub fn new_server(token_provider: Arc<dyn TokenProvider>) -> ServerFoundation {
        ServerFoundation {
            token_registry: ArcTokenRegistry::with_provider(token_provider),
            server_params: ServerParameters::default(),
            client_auther: Box::new(AcceptAllClientAuther),
        }
    }
}

pub struct ClientFoundation {
    server_name: String,
    token_registry: ArcTokenRegistry,
    client_params: ClientParameters,
}

impl ClientFoundation {
    pub fn with_parameters(mut self, params: ClientParameters) -> Self {
        self.client_params = params;
        self
    }
}

pub struct ServerFoundation {
    token_registry: ArcTokenRegistry,
    server_params: ServerParameters,
    client_auther: Box<dyn AuthClient>,
}

impl ServerFoundation {
    pub fn with_parameters(mut self, params: ServerParameters) -> Self {
        self.server_params = params;
        self
    }

    pub fn with_client_auther(mut self, authers: Box<dyn AuthClient>) -> Self {
        self.client_auther = authers;
        self
    }
}

pub struct ConnectionFoundation<Foundation, TlsConfig> {
    foundation: Foundation,
    tls_config: TlsConfig,

    ifaces: Arc<InterfaceManager>,
    iface_factory: Arc<dyn ProductIO>,
    quic_router: Arc<QuicRouter>,
    locations: Arc<Locations>,
    stun_servers: Arc<[SocketAddr]>,
    streams_ctrl: Box<dyn ControlStreamsConcurrency>,
    defer_idle_timeout: Duration,
}

pub type ClientConnectionFoundation = ConnectionFoundation<ClientFoundation, TlsClientConfig>;
pub type ServerConnectionFoundation = ConnectionFoundation<ServerFoundation, TlsServerConfig>;

impl ClientFoundation {
    pub fn with_tls_config(
        self,
        tls_config: TlsClientConfig,
    ) -> ConnectionFoundation<Self, TlsClientConfig> {
        ConnectionFoundation {
            foundation: self,
            tls_config,
            ifaces: InterfaceManager::global().clone(),
            iface_factory: Arc::new(DEFAULT_IO_FACTORY),
            quic_router: QuicRouter::global().clone(),
            locations: Arc::new(Locations::new()),
            stun_servers: Arc::new([]),
            streams_ctrl: Box::new(DemandConcurrency), // ZST cause no alloc
            defer_idle_timeout: Duration::ZERO,
        }
    }
}

impl ConnectionFoundation<ClientFoundation, TlsClientConfig> {
    pub fn with_streams_concurrency_strategy<F>(self, strategy_factory: &F) -> Self
    where
        F: ProductStreamsConcurrencyController + ?Sized,
    {
        let client_params = &self.foundation.client_params;
        let init_max_bidi_streams = client_params
            .get(ParameterId::InitialMaxStreamsBidi)
            .expect("unreachable: default value will be got if the value unset");
        let init_max_uni_streams = client_params
            .get(ParameterId::InitialMaxStreamsUni)
            .expect("unreachable: default value will be got if the value unset");
        ConnectionFoundation {
            streams_ctrl: strategy_factory.init(init_max_bidi_streams, init_max_uni_streams),
            ..self
        }
    }

    pub fn with_zero_rtt(mut self, enabled: bool) -> Self {
        self.tls_config.enable_early_data = enabled;
        self
    }
}

impl ServerFoundation {
    pub fn with_tls_config(
        self,
        tls_config: TlsServerConfig,
    ) -> ConnectionFoundation<Self, TlsServerConfig> {
        ConnectionFoundation {
            foundation: self,
            tls_config,
            ifaces: InterfaceManager::global().clone(),
            iface_factory: Arc::new(DEFAULT_IO_FACTORY),
            quic_router: QuicRouter::global().clone(),
            locations: Arc::new(Locations::new()),
            stun_servers: Arc::new([]),
            streams_ctrl: Box::new(DemandConcurrency), // ZST cause no alloc
            defer_idle_timeout: Duration::ZERO,
        }
    }
}

impl ConnectionFoundation<ServerFoundation, TlsServerConfig> {
    pub fn with_streams_concurrency_strategy<F>(self, strategy_factory: &F) -> Self
    where
        F: ProductStreamsConcurrencyController + ?Sized,
    {
        let server_params = &self.foundation.server_params;
        let init_max_bidi_streams = server_params
            .get(ParameterId::InitialMaxStreamsBidi)
            .expect("unreachable: default value will be got if the value unset");
        let init_max_uni_streams = server_params
            .get(ParameterId::InitialMaxStreamsUni)
            .expect("unreachable: default value will be got if the value unset");
        ConnectionFoundation {
            streams_ctrl: strategy_factory.init(init_max_bidi_streams, init_max_uni_streams),
            ..self
        }
    }

    pub fn with_zero_rtt(mut self, enabled: bool) -> Self {
        match enabled {
            true => self.tls_config.max_early_data_size = 0xffffffff,
            false => self.tls_config.max_early_data_size = 0,
        }
        self
    }
}

impl<Foundation, TlsConfig> ConnectionFoundation<Foundation, TlsConfig> {
    pub fn with_iface_factory(mut self, factory: Arc<dyn ProductIO>) -> Self {
        self.iface_factory = factory;
        self
    }

    pub fn with_iface_manager(mut self, ifaces: Arc<InterfaceManager>) -> Self {
        self.ifaces = ifaces;
        self
    }

    pub fn with_quic_router(mut self, quic_router: Arc<QuicRouter>) -> Self {
        self.quic_router = quic_router;
        self
    }

    pub fn with_locations(mut self, locations: Arc<Locations>) -> Self {
        self.locations = locations;
        self
    }

    pub fn with_stun_servers(mut self, stun_servers: Arc<[SocketAddr]>) -> Self {
        self.stun_servers = stun_servers;
        self
    }

    pub fn with_defer_idle_timeout(mut self, timeout: Duration) -> Self {
        self.defer_idle_timeout = timeout;
        self
    }
}

fn initial_keys_with(
    crypto_provider: &Arc<CryptoProvider>,
    origin_dcid: &ConnectionId,
    side: rustls::Side,
    version: rustls::quic::Version,
) -> rustls::quic::Keys {
    crypto_provider
        .cipher_suites
        .iter()
        .find_map(|cs| match (cs.suite(), cs.tls13()) {
            (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => {
                Some(suite.quic_suite())
            }
            _ => None,
        })
        .flatten()
        .expect("crypto provider does not provide supported cipher suite")
        .keys(origin_dcid, side, version)
}

impl ConnectionFoundation<ClientFoundation, TlsClientConfig> {
    pub fn with_cids(self, origin_dcid: ConnectionId) -> PendingConnection {
        let initial_keys = initial_keys_with(
            self.tls_config.crypto_provider(),
            &origin_dcid,
            rustls::Side::Client,
            crate::tls::QUIC_VERSION,
        );

        let rcvd_pkt_q = Arc::new(RcvdPacketQueue::new());

        let tx_wakers = ArcSendWakers::default();
        let reliable_frames = ArcReliableFrameDeque::with_capacity_and_wakers(8, tx_wakers.clone());
        let quic_router_registry = self
            .quic_router
            .registry_on_issuing_scid(rcvd_pkt_q.clone(), reliable_frames.clone());
        let initial_scid = quic_router_registry.gen_unique_cid();

        let mut client_params = self.foundation.client_params;
        _ = client_params.set(ParameterId::InitialSourceConnectionId, initial_scid);

        let host = self
            .foundation
            .server_name
            .split_once(':')
            .map(|(h, _)| h)
            .unwrap_or(&self.foundation.server_name)
            .to_string();
        let tls_session = ClientTlsSession::init(host, Arc::new(self.tls_config), &client_params)
            .expect("Failed to initialize TLS handshake");

        let zero_rtt_keys = ArcZeroRttKeys::new_pending(Role::Client);

        // if zero rtt enabled && loadede remembered parameters && zero rtt keys is available
        let parameters = match tls_session.load_zero_rtt() {
            Some((remembered_parameters, avaliable_zero_rtt_keys)) => {
                qevent::event!(ParametersRestored {
                    client_parameters: &remembered_parameters,
                });
                zero_rtt_keys.set_keys(avaliable_zero_rtt_keys);
                Parameters::new_client(client_params, Some(remembered_parameters), origin_dcid)
            }
            None => Parameters::new_client(client_params, None, origin_dcid),
        };

        PendingConnection {
            interfaces: self.ifaces,
            iface_factory: self.iface_factory,
            quic_router: self.quic_router,
            locations: self.locations,
            stun_servers: self.stun_servers,
            rcvd_pkt_q,
            defer_idle_timeout: self.defer_idle_timeout,
            role: Role::Client,
            origin_dcid,
            initial_scid,
            tx_wakers,
            send_lock: ArcSendLock::unrestricted(),
            reliable_frames,
            quicrouter_registry: quic_router_registry,
            parameters,
            token_registry: self.foundation.token_registry,
            tls_session: TlsSession::Client(tls_session),
            initial_keys,
            zero_rtt_keys,
            streams_ctrl: self.streams_ctrl,
            specific: SpecificComponents::Client {},
            qlogger: Arc::new(NoopLogger),
        }
    }
}

impl ConnectionFoundation<ServerFoundation, TlsServerConfig> {
    pub fn with_cids(self, origin_dcid: ConnectionId) -> PendingConnection {
        let initial_keys = initial_keys_with(
            self.tls_config.crypto_provider(),
            &origin_dcid,
            rustls::Side::Server,
            crate::tls::QUIC_VERSION,
        );

        let rcvd_pkt_q = Arc::new(RcvdPacketQueue::new());

        let tx_wakers = ArcSendWakers::default();
        let reliable_frames = ArcReliableFrameDeque::with_capacity_and_wakers(8, tx_wakers.clone());
        let quic_router_registry = self
            .quic_router
            .registry_on_issuing_scid(rcvd_pkt_q.clone(), reliable_frames.clone());
        let initial_scid = quic_router_registry.gen_unique_cid();
        let odcid_router_entry = self
            .quic_router
            .insert(origin_dcid.into(), rcvd_pkt_q.clone());

        let mut server_params = self.foundation.server_params;
        _ = server_params.set(ParameterId::InitialSourceConnectionId, initial_scid);
        _ = server_params.set(ParameterId::OriginalDestinationConnectionId, origin_dcid);

        let tls_session = ServerTlsSession::init(
            Arc::new(self.tls_config),
            &server_params,
            self.foundation.client_auther,
        )
        .expect("Failed to initialize TLS handshake"); // TODO: tls创建的错误处理

        PendingConnection {
            interfaces: self.ifaces,
            iface_factory: self.iface_factory,
            quic_router: self.quic_router,
            locations: self.locations,
            stun_servers: self.stun_servers,
            rcvd_pkt_q,
            defer_idle_timeout: self.defer_idle_timeout,
            role: Role::Server,
            origin_dcid,
            initial_scid,
            tx_wakers,
            send_lock: tls_session.send_lock().clone(),
            reliable_frames,
            quicrouter_registry: quic_router_registry,
            parameters: Parameters::new_server(server_params),
            token_registry: self.foundation.token_registry,
            tls_session: TlsSession::Server(tls_session),
            initial_keys,
            zero_rtt_keys: ArcZeroRttKeys::new_pending(Role::Server),
            streams_ctrl: self.streams_ctrl,
            specific: SpecificComponents::Server {
                odcid_router_entry: Arc::new(odcid_router_entry),
                using_odcid: Arc::new(AtomicBool::new(true)),
            },
            qlogger: Arc::new(NoopLogger),
        }
    }
}

pub struct PendingConnection {
    interfaces: Arc<InterfaceManager>,
    iface_factory: Arc<dyn ProductIO>,
    quic_router: Arc<QuicRouter>,
    locations: Arc<Locations>,
    stun_servers: Arc<[SocketAddr]>,
    rcvd_pkt_q: Arc<RcvdPacketQueue>,
    defer_idle_timeout: Duration,
    role: Role,
    origin_dcid: ConnectionId,
    initial_scid: ConnectionId,
    send_lock: ArcSendLock,
    tx_wakers: ArcSendWakers,
    reliable_frames: ArcReliableFrameDeque,
    quicrouter_registry: QuicRouterRegistry,
    parameters: Parameters,
    token_registry: ArcTokenRegistry,
    tls_session: TlsSession,
    initial_keys: rustls::quic::Keys,
    zero_rtt_keys: ArcZeroRttKeys,
    streams_ctrl: Box<dyn ControlStreamsConcurrency>,
    specific: SpecificComponents,
    qlogger: Arc<dyn QLog>,
}

fn init_stream_and_datagram<LR: IntoRole, RR: IntoRole>(
    local_params: &qbase::param::core::Parameters<LR>,
    remote_params: &qbase::param::core::Parameters<RR>,
    reliable_frames: ArcReliableFrameDeque,
    streams_ctrl: Box<dyn ControlStreamsConcurrency>,
    tx_wakers: ArcSendWakers,
    metrics: qbase::metric::ArcConnectionMetrics,
) -> (DataStreams, FlowController, DatagramFlow) {
    assert_ne!(LR::into_role(), RR::into_role());
    let flow_ctrl = FlowController::new(
        remote_params
            .get(ParameterId::InitialMaxData)
            .expect("unreachable: default value will be got if the value unset"),
        local_params
            .get(ParameterId::InitialMaxData)
            .expect("unreachable: default value will be got if the value unset"),
        reliable_frames.clone(),
        tx_wakers.clone(),
    );
    let data_streams = DataStreams::new(
        LR::into_role(),
        local_params,
        remote_params,
        streams_ctrl,
        reliable_frames.clone(),
        tx_wakers.clone(),
        Some(metrics),
    );
    let datagram_flow = DatagramFlow::new(
        local_params
            .get(ParameterId::MaxDatagramFrameSize)
            .expect("unreachable: default value will be got if the value unset"),
        tx_wakers.clone(),
    );
    (data_streams, flow_ctrl, datagram_flow)
}

impl PendingConnection {
    pub fn with_qlog(mut self, qlogger: Arc<dyn QLog>) -> Self {
        self.qlogger = qlogger;
        self
    }

    pub fn run(self) -> Arc<Connection> {
        let (event_broker, events) = mpsc::unbounded_channel();

        let group_id = GroupID::from(self.origin_dcid);
        let qlog_span = self.qlogger.new_trace(self.role.into(), group_id.clone());
        let tracing_span =
            tracing::debug_span!(parent: None, "connection", role = %self.role, odcid = %group_id);
        let _span = (qlog_span.enter(), tracing_span.clone().entered());

        tracing::trace!(parameters=?self.parameters, "starting new connection");

        let conn_state = ArcConnState::new();
        let event_broker = ArcEventBroker::new(conn_state.clone(), event_broker);

        let quic_handshake = Handshake::new(
            RawHandshake::new(self.role, self.reliable_frames.clone()),
            Arc::new(HandshakeStatus::new(self.role == Role::Server)),
            event_broker.clone(),
        );

        let local_cids = ArcLocalCids::new(self.initial_scid, self.quicrouter_registry);
        let remote_cids = ArcRemoteCids::new(
            self.parameters
                .get_local(ParameterId::ActiveConnectionIdLimit)
                .expect("unreachable: default value will be got if the value unset"),
            self.reliable_frames.clone(),
        );
        let cid_registry = CidRegistry::new(self.role, self.origin_dcid, local_cids, remote_cids);

        let spaces = Spaces::new(
            InitialSpace::new(self.initial_keys.into()),
            HandshakeSpace::new(),
            DataSpace::new(self.zero_rtt_keys),
        );

        let crypto_streams = [
            CryptoStream::new(self.tx_wakers.clone()),
            CryptoStream::new(self.tx_wakers.clone()),
            CryptoStream::new(self.tx_wakers.clone()),
        ];

        let metrics = Arc::new(qbase::metric::ConnectionMetrics::default());

        let (data_streams, flow_ctrl, datagram_flow) = match self.role {
            Role::Client => init_stream_and_datagram(
                self.parameters.client().unwrap(),
                self.parameters
                    .remembered()
                    .map(|p| p.as_ref())
                    .unwrap_or(&ServerParameters::default()),
                self.reliable_frames.clone(),
                self.streams_ctrl,
                self.tx_wakers.clone(),
                metrics.clone(),
            ),
            Role::Server => init_stream_and_datagram(
                self.parameters.server().unwrap(),
                &ClientParameters::default(),
                self.reliable_frames.clone(),
                self.streams_ctrl,
                self.tx_wakers.clone(),
                metrics.clone(),
            ),
        };
        let puncher = ArcPuncher::new(
            self.reliable_frames.clone(),
            PunchTransaction::new(cid_registry.clone()),
            spaces.data().clone(),
            self.interfaces.clone(),
            self.iface_factory,
            self.quic_router.clone(),
            self.stun_servers.clone(),
        );

        let max_idle_timeout = self
            .parameters
            .get_local(ParameterId::MaxIdleTimeout)
            .expect("Duration::ZERO if not specified");
        let components = Components {
            interfaces: self.interfaces,
            locations: self.locations,
            rcvd_pkt_q: self.rcvd_pkt_q,
            conn_state: conn_state.clone(),
            idle_config: ArcIdleConfig::new(max_idle_timeout, self.defer_idle_timeout),
            paths: ArcPathContexts::new(self.tx_wakers.clone(), event_broker.clone()),
            send_lock: self.send_lock,
            tls_handshake: ArcTlsHandshake::new(self.tls_session),
            quic_handshake,
            parameters: ArcParameters::from(self.parameters),
            token_registry: self.token_registry,
            cid_registry,
            spaces,
            crypto_streams,
            reliable_frames: self.reliable_frames,
            data_streams,
            flow_ctrl,
            datagram_flow,
            event_broker,
            metrics,
            specific: self.specific,
            puncher,
        };

        spawn_tls_handshake(&components, self.tx_wakers.clone());
        spawn_deliver_and_parse(&components);

        let connection = Arc::new_cyclic(|weak_self| Connection {
            state: Ok(components).into(),
            conn_state: conn_state.clone(),
            weak_self: weak_self.clone(),
            qlog_span,
            tracing_span,
        });

        spawn_drive_connection(events, Arc::downgrade(&connection));

        connection
    }
}

fn spawn_tls_handshake(components: &Components, tx_wakers: ArcSendWakers) {
    let task = components.tls_handshake.clone().start(
        components.parameters.clone(),
        components.quic_handshake.clone(),
        components.crypto_streams.clone(),
        (
            components.spaces.handshake().keys(),
            components.spaces.data().zero_rtt_keys(),
            components.spaces.data().one_rtt_keys(),
        ),
        tls_fin_handler(
            components.parameters.clone(),
            components.data_streams.clone(),
            components.flow_ctrl.clone(),
            components.spaces.data().journal().clone(),
            components.cid_registry.local.clone(),
            components.idle_config.clone(),
            tx_wakers,
        ),
    );

    let event_broker = components.event_broker.clone();
    let task = async move {
        if let Err(Error::Quic(e)) = task.await {
            event_broker.emit(Event::Failed(e));
        }
    };

    // Terminates when the QUIC connection closes and the event broker shuts down.
    tokio::spawn(task.instrument_in_current().in_current_span());
}

fn tls_fin_handler(
    parameters: ArcParameters,
    data_streams: DataStreams,
    flow_ctrl: FlowController,
    data_journal: DataJournal,
    local_cids: ArcLocalCids,
    idle_config: ArcIdleConfig,
    tx_wakers: ArcSendWakers,
) -> impl FnOnce(&TlsHandshakeInfo) -> Result<(), Error> + Send {
    fn apply_parameters<Role: IntoRole>(
        data_streams: &DataStreams,
        flow_ctrl: &FlowController,
        // datagram_flow
        data_journal: &DataJournal,
        local_cids: &ArcLocalCids,
        idle_config: &ArcIdleConfig,
        zero_rtt_rejected: bool,
        remote_parameters: Arc<qbase::param::core::Parameters<Role>>,
    ) -> Result<(), Error> {
        // accept InitialMaxStreamsBidi, InitialMaxStreamUni,
        // InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote, InitialMaxStreamDataUni,
        data_streams.revise_params(zero_rtt_rejected, remote_parameters.as_ref());
        // accept InitialMaxData:
        flow_ctrl.sender.revise_max_data(
            zero_rtt_rejected,
            remote_parameters
                .get(ParameterId::InitialMaxData)
                .expect("unreachable: default value will be got if the value unset"),
        );
        // accept ActiveConnectionIdLimit
        local_cids.set_limit(
            remote_parameters
                .get(ParameterId::ActiveConnectionIdLimit)
                .expect("unreachable: default value will be got if the value unset"),
        )?;
        data_journal.of_rcvd_packets().revise_max_ack_delay(
            remote_parameters
                .get(ParameterId::MaxAckDelay)
                .expect("unreachable: default value will be got if the value unset"),
        );
        idle_config.negotiate_max_idle_timeout(
            remote_parameters
                .get(ParameterId::MaxIdleTimeout)
                .expect("Duration::ZERO if not specified"),
        );

        Ok(())
    }

    move |info| {
        let zero_rtt_rejected = info
            .zero_rtt_accepted()
            .map(|accepted| !accepted)
            .unwrap_or(false);

        let parameters = parameters.lock_guard()?;

        if parameters.role() == Role::Client {
            if zero_rtt_rejected {
                debug_assert_eq!(parameters.role(), Role::Client);
                tracing::trace!(target: "quic", "0-RTT is not enabled, or not accepted by the server.");
            } else {
                tracing::trace!(target: "quic", "0-RTT is enabled and accepted by the server.");
            }
        }

        match parameters.role() {
            Role::Client => {
                let remote_parameters = parameters
                    .server()
                    .expect("client and server parameters has been ready")
                    .clone();
                drop(parameters);
                qevent::event!(ParametersSet {
                    owner: Owner::Remote,
                    server_parameters: &remote_parameters,
                });
                apply_parameters(
                    &data_streams,
                    &flow_ctrl,
                    &data_journal,
                    &local_cids,
                    &idle_config,
                    zero_rtt_rejected,
                    remote_parameters,
                )?;
            }
            Role::Server => {
                let remote_parameters = parameters
                    .client()
                    .expect("client and server parameters has been ready")
                    .clone();
                drop(parameters);
                qevent::event!(ParametersSet {
                    owner: Owner::Remote,
                    client_parameters: &remote_parameters,
                });
                apply_parameters(
                    &data_streams,
                    &flow_ctrl,
                    &data_journal,
                    &local_cids,
                    &idle_config,
                    zero_rtt_rejected,
                    remote_parameters,
                )?;
            }
        }
        tx_wakers.wake_all_by(Signals::TLS_FIN);

        Result::<_, Error>::Ok(())
    }
}

fn spawn_drive_connection(
    mut events: mpsc::UnboundedReceiver<Event>,
    weak_connection: Weak<Connection>,
) {
    tokio::spawn(
        async move {
            let mut retained_connection: Option<Arc<Connection>> = None;
            while let Some(event) = events.recv().await {
                let Some(connection) = retained_connection
                    .as_ref()
                    .cloned()
                    .or_else(|| weak_connection.upgrade())
                else {
                    break;
                };

                match event {
                    Event::Handshaked => {}
                    Event::Failed(quic_error) => {
                        retained_connection.get_or_insert_with(|| connection.clone());
                        _ = connection.enter_closing(quic_error);
                    }
                    Event::ApplicationClose(_app_error) => {
                        retained_connection.get_or_insert_with(|| connection.clone());
                    }
                    Event::Closed(ccf) => {
                        retained_connection.get_or_insert_with(|| connection.clone());
                        _ = connection.enter_draining(ccf);
                    }
                    Event::StatelessReset => {}
                    Event::Terminated => {
                        retained_connection.take();
                        break;
                    }
                }
            }
        }
        .instrument_in_current()
        .in_current_span(),
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use qbase::{error::AppError, varint::VarInt};
    use tokio::sync::mpsc;

    use super::*;
    use crate::termination::Termination;

    fn test_connection(conn_state: ArcConnState) -> Arc<Connection> {
        Arc::new_cyclic(|weak_self| Connection {
            state: Err(Termination::draining(
                AppError::new(VarInt::from_u32(0), "").into(),
            ))
            .into(),
            conn_state,
            weak_self: weak_self.clone(),
            qlog_span: qevent::telemetry::Span::default(),
            tracing_span: tracing::Span::none(),
        })
    }

    #[tokio::test]
    async fn application_close_event_retains_connection_until_terminated() {
        let (tx, rx) = mpsc::unbounded_channel();
        let conn_state = ArcConnState::new();
        let connection = test_connection(conn_state);
        let weak_connection = Arc::downgrade(&connection);

        spawn_drive_connection(rx, weak_connection.clone());

        tx.send(Event::ApplicationClose(AppError::new(
            VarInt::from_u32(0),
            "",
        )))
        .unwrap();
        tokio::task::yield_now().await;

        drop(connection);
        tokio::task::yield_now().await;

        assert!(
            weak_connection.upgrade().is_some(),
            "drive loop should retain application-closed connections until termination"
        );

        tx.send(Event::Terminated).unwrap();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(
            weak_connection.upgrade().is_none(),
            "retained connection should drop after termination"
        );
    }
}
