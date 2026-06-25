pub mod builder;
pub mod events;
pub mod handshake;
pub mod path;
pub mod space;
pub mod state;
pub mod termination;
pub mod tls;
mod traversal;
pub mod tx;
pub mod prelude {
    pub use qbase::{
        cid::ConnectionId,
        error::{AppError, Error, ErrorKind, QuicError},
        frame::ConnectionCloseFrame,
        net::{addr::*, route::*},
        param::ParameterId,
        role::{Client, IntoRole, Role, Server},
        sid::{ControlStreamsConcurrency, ProductStreamsConcurrencyController, StreamId},
        varint::VarInt,
    };
    #[cfg(feature = "datagram")]
    pub use qdatagram::{DatagramReader, DatagramWriter};
    pub use qinterface::{
        bind_uri::BindUri,
        io::{IO, IoExt},
    };
    pub use qrecovery::{recv::StopSending, send::CancelStream, streams::error::StreamError};

    pub mod handy {
        pub use qbase::{param::handy::*, sid::handy::*, token::handy::*};
        pub use qevent::telemetry::handy::*;
        pub use qinterface::io::handy::*;
    }

    pub use crate::{
        Connection, StreamReader, StreamWriter,
        tls::{
            AuthClient, ClientAuthorityVerifyResult, ClientNameVerifyResult, LocalAuthority,
            RemoteAuthority, SignError, VerifyError,
        },
    };
}

// Re-export dependencies
use std::{
    borrow::Cow,
    fmt::Debug,
    future::Future,
    io,
    sync::{Arc, RwLock, Weak, atomic::AtomicBool},
};

pub use ::{qbase, qdatagram, qevent, qinterface, qrecovery, qtraversal};
use derive_more::From;
use enum_dispatch::enum_dispatch;
use events::{ArcEventBroker, EmitEvent, Event};
use futures::{FutureExt, TryFutureExt};
use path::ArcPathContexts;
use qbase::{
    cid,
    error::{AppError, Error, ErrorKind, QuicError},
    flow,
    frame::{ConnectionCloseFrame, CryptoFrame, Frame, ReliableFrame, StreamFrame},
    metric::ArcConnectionMetrics,
    net::{addr::EndpointAddr, route::Pathway},
    param::{ArcParameters, ParameterId},
    role::Role,
    sid::StreamId,
    time::ArcIdleConfig,
    token::ArcTokenRegistry,
};
use qdatagram::DatagramFlow;
#[cfg(feature = "datagram")]
use qdatagram::{DatagramReader, DatagramWriter};
use qevent::{
    quic::{Owner, connectivity::ConnectionClosed},
    telemetry::Instrument,
};
use qinterface::{
    bind_uri::BindUri,
    component::{
        local_endpoint::InterfaceEndpointKey,
        route::{self, QuicRouterEntry, RcvdPacketQueue, Way},
    },
    manager::InterfaceManager,
};
use qrecovery::{
    crypto::CryptoStream,
    journal, recv, reliable, send,
    streams::{self, Ext},
};
use space::Spaces;
use state::ArcConnState;
use termination::Termination;
use tls::ArcSendLock;
use tracing::Instrument as _;

use crate::{
    path::{CreatePathFailure, PathDeactivated},
    space::data::DataSpace,
    termination::Terminator,
    tls::{ArcTlsHandshake, LocalAuthority, RemoteAuthority},
    traversal::PunchTransaction,
};

/// The kind of frame which guaratend to be received by peer.
///
/// The bundle of [`StreamFrame`], [`CryptoFrame`], and [`ReliableFrame`].
#[derive(Debug, Clone, From, Eq, PartialEq)]
#[enum_dispatch(EncodeSize, FrameFeture)]
pub enum GuaranteedFrame {
    Stream(StreamFrame),
    Crypto(CryptoFrame),
    Reliable(ReliableFrame),
}

impl<'f, D> TryFrom<&'f Frame<D>> for GuaranteedFrame {
    type Error = &'f Frame<D>;

    fn try_from(frame: &'f Frame<D>) -> Result<Self, Self::Error> {
        Ok(match ReliableFrame::try_from(frame) {
            Ok(reliable) => Self::Reliable(reliable),
            Err(Frame::Crypto(crypto, _data)) => Self::Crypto(*crypto),
            Err(Frame::Stream(stream, _data)) => Self::Stream(*stream),
            Err(frame) => return Err(frame),
        })
    }
}

/// For initial space, only reliable transmission of crypto frames is required.
pub type InitialJournal = journal::Journal<CryptoFrame>;
/// For handshake space, only reliable transmission of crypto frames is required.
pub type HandshakeJournal = journal::Journal<CryptoFrame>;
/// For data space, reliable transmission of [`GuaranteedFrame`] (crypto frames, stream frames and reliable frames) is required.
pub type DataJournal = journal::Journal<GuaranteedFrame>;

pub type ArcReliableFrameDeque = reliable::ArcReliableFrameDeque<ReliableFrame>;
pub type QuicRouterRegistry = route::QuicRouterRegistry<ArcReliableFrameDeque>;
pub type ArcLocalCids = cid::ArcLocalCids<QuicRouterRegistry>;
pub type ArcRemoteCids = cid::ArcRemoteCids<ArcReliableFrameDeque>;
pub type CidRegistry = cid::Registry<ArcLocalCids, ArcRemoteCids>;
pub type ArcDcidCell = cid::ArcCidCell<ArcReliableFrameDeque>;

pub type FlowController = flow::FlowController<ArcReliableFrameDeque>;
pub type Credit<'a> = flow::Credit<'a, ArcReliableFrameDeque>;

pub type Handshake = handshake::Handshake<ArcReliableFrameDeque>;
pub type RawHandshake = handshake::RawHandshake<ArcReliableFrameDeque>;

pub type DataStreams = streams::DataStreams<ArcReliableFrameDeque>;
pub type StreamReader = recv::Reader<Ext<ArcReliableFrameDeque>>;
pub type StreamWriter = send::Writer<Ext<ArcReliableFrameDeque>>;
pub type ArcPuncher =
    qtraversal::punch::puncher::ArcPuncher<ArcReliableFrameDeque, PunchTransaction, DataSpace>;

#[derive(Clone)]
pub struct Components {
    // TODO: delete this
    interfaces: Arc<InterfaceManager>,
    rcvd_pkt_q: Arc<RcvdPacketQueue>,
    conn_state: ArcConnState,
    idle_config: ArcIdleConfig,
    paths: ArcPathContexts,
    send_lock: ArcSendLock,
    tls_handshake: ArcTlsHandshake,
    quic_handshake: Handshake,
    parameters: ArcParameters,
    token_registry: ArcTokenRegistry,
    cid_registry: CidRegistry,
    spaces: Spaces,
    crypto_streams: [CryptoStream; 3],
    reliable_frames: ArcReliableFrameDeque,
    data_streams: DataStreams,
    flow_ctrl: FlowController,
    datagram_flow: DatagramFlow,
    event_broker: ArcEventBroker,
    metrics: ArcConnectionMetrics,
    specific: SpecificComponents,
    puncher: ArcPuncher,
}

#[derive(Clone)]
pub enum SpecificComponents {
    Client {},
    Server {
        using_odcid: Arc<AtomicBool>,
        odcid_router_entry: Arc<QuicRouterEntry>,
    },
}

/// expand Impl_Future![Type] to `impl Future<Output = Type> + Send + use<>`
macro_rules! Impl_Future {
    [$ty:ty] => {
        impl Future<Output = $ty> + Send + use<>
    };
}

impl Components {
    pub fn role(&self) -> Role {
        match self.specific {
            SpecificComponents::Client { .. } => Role::Client,
            SpecificComponents::Server { .. } => Role::Server,
        }
    }

    /// Gets the connection metrics for tracking data volumes.
    pub fn metrics(&self) -> &ArcConnectionMetrics {
        &self.metrics
    }

    #[allow(clippy::type_complexity)]
    pub fn open_bi_stream(
        &self,
    ) -> Impl_Future![Result<Option<(StreamId, (StreamReader, StreamWriter))>, Error>] {
        let zero_rtt_avaliable = self.spaces.data().is_zero_rtt_avaliable();
        let tls_handshake = self.tls_handshake.clone();
        let data_streams = self.data_streams.clone();
        let parameters = self.parameters.clone();
        async move {
            if !zero_rtt_avaliable {
                tls_handshake.info().await?;
            }
            data_streams.open_bi(&parameters).await
        }
        .instrument_in_current()
        .in_current_span()
    }

    pub fn open_uni_stream(&self) -> Impl_Future![Result<Option<(StreamId, StreamWriter)>, Error>] {
        let zero_rtt_avaliable = self.spaces.data().is_zero_rtt_avaliable();
        let tls_handshake = self.tls_handshake.clone();
        let data_streams = self.data_streams.clone();
        let parameters = self.parameters.clone();
        async move {
            if !zero_rtt_avaliable {
                tls_handshake.info().await?;
            }
            data_streams.open_uni(&parameters).await
        }
        .instrument_in_current()
        .in_current_span()
    }

    #[allow(clippy::type_complexity)]
    pub fn accept_bi_stream(
        &self,
    ) -> Impl_Future![Result<(StreamId, (StreamReader, StreamWriter)), Error>] {
        let data_streams = self.data_streams.clone();
        let parameters = self.parameters.clone();
        async move { data_streams.accept_bi(&parameters).await }
            .instrument_in_current()
            .in_current_span()
    }

    pub fn accept_uni_stream(&self) -> Impl_Future![Result<(StreamId, StreamReader), Error>] {
        let data_streams = self.data_streams.clone();
        async move { data_streams.accept_uni().await }
            .instrument_in_current()
            .in_current_span()
    }

    #[cfg(feature = "datagram")]
    #[deprecated]
    pub fn datagram_reader(&self) -> io::Result<DatagramReader> {
        self.datagram_flow.reader()
    }

    #[cfg(feature = "datagram")]
    #[deprecated]
    pub fn datagram_writer(&self) -> Impl_Future![io::Result<DatagramWriter>] {
        let params = self.parameters.clone();
        let datagram_flow = self.datagram_flow.clone();
        async move {
            let max_datagram_frame_size = params
                .remote_ready()
                .await?
                .get_remote(ParameterId::MaxDatagramFrameSize)
                .expect("unreachable: default value will be got if the value unset");
            datagram_flow.writer(max_datagram_frame_size)
        }
        .instrument_in_current()
        .in_current_span()
    }

    pub fn add_path(&self, way: Way) -> Result<(), CreatePathFailure> {
        self.get_or_try_create_path(way, false).map(|_| ())
    }

    pub fn del_path(&self, pathway: &Pathway) {
        self.paths.remove(pathway, &PathDeactivated::App);
    }

    pub fn local_authority(&self) -> Impl_Future![Result<Option<LocalAuthority>, Error>] {
        let tls_handshake = self.tls_handshake.clone();
        async move {
            match tls_handshake.info().await?.as_ref() {
                tls::TlsHandshakeInfo::Client {
                    local_authority, ..
                } => Ok(local_authority.clone()),
                tls::TlsHandshakeInfo::Server {
                    local_authority, ..
                } => Ok(Some(local_authority.clone())),
            }
        }
        .instrument_in_current()
        .in_current_span()
    }

    pub fn remote_authority(&self) -> Impl_Future![Result<Option<RemoteAuthority>, Error>] {
        let tls_handshake = self.tls_handshake.clone();
        async move {
            match tls_handshake.info().await?.as_ref() {
                tls::TlsHandshakeInfo::Client {
                    remote_authority, ..
                } => Ok(Some(remote_authority.clone())),
                tls::TlsHandshakeInfo::Server {
                    remote_authority, ..
                } => Ok(remote_authority.clone()),
            }
        }
        .instrument_in_current()
        .in_current_span()
    }
}

impl Components {
    fn server_odcid_router_entry(&self) -> Option<Arc<QuicRouterEntry>> {
        match &self.specific {
            SpecificComponents::Client {} => None,
            SpecificComponents::Server {
                odcid_router_entry, ..
            } => Some(odcid_router_entry.clone()),
        }
    }

    fn spawn_deferred_termination(&self, close_receive_on_timeout: bool) {
        let pto_duration = self.paths.max_pto_duration().unwrap_or_default();
        let event_broker = self.event_broker.clone();
        let local_cids = self.cid_registry.local.clone();
        // Server ODCID is route-equivalent to an unplanned SCID: it was not
        // issued by local_cids, but it must remain routable for exactly the
        // same deferred period. The router entry itself is the RAII owner.
        let odcid_router_entry = self.server_odcid_router_entry();
        let receive_cleanup =
            close_receive_on_timeout.then(|| (self.rcvd_pkt_q.clone(), self.paths.clone()));

        tokio::spawn(
            async move {
                tokio::time::sleep(pto_duration * 3).await;
                if let Some((rcvd_pkt_q, paths)) = receive_cleanup {
                    rcvd_pkt_q.close_all();
                    paths.close();
                }
                local_cids.clear();
                drop(odcid_router_entry);
                event_broker.emit(Event::Terminated);
            }
            .instrument_in_current()
            .in_current_span(),
        );
    }

    fn enter_silent_draining(self, error: Error) -> Termination {
        qevent::event!(ConnectionClosed {
            owner: Owner::Local,
            error: &error, // TODO: trigger
        });

        self.data_streams.on_conn_error(&error);
        self.datagram_flow.on_conn_error(&error);
        self.tls_handshake.on_conn_error(&error);
        self.parameters.on_conn_error(&error);

        self.spawn_deferred_termination(false);

        // Silent refusal sends no connection close frame. Semantically this
        // connection only drains/drops incoming packets until the routing
        // tombstones expire.
        self.rcvd_pkt_q.close_all();
        self.paths.close();
        Termination::draining(error)
    }

    pub fn enter_closing(self, error: Error) -> Termination {
        if !self.send_lock.is_permitted() {
            return self.enter_silent_draining(error);
        }

        qevent::event!(ConnectionClosed {
            owner: Owner::Local,
            error: &error, // TODO: trigger
        });

        self.data_streams.on_conn_error(&error);
        self.datagram_flow.on_conn_error(&error);
        self.tls_handshake.on_conn_error(&error);
        self.parameters.on_conn_error(&error);

        self.spawn_deferred_termination(true);

        let terminator = Arc::new(Terminator::new(error.clone().into(), &self));
        tokio::spawn(
            async move { self.spaces.send_ccf_packets(terminator.as_ref()).await }
                .instrument_in_current()
                .in_current_span(),
        );

        Termination::closing(error, self.rcvd_pkt_q, self.paths)
    }

    pub fn enter_draining(self, ccf: ConnectionCloseFrame) -> Termination {
        qevent::event!(ConnectionClosed {
            owner: Owner::Local,
            ccf: &ccf // TODO: trigger
        });

        let error = ccf.clone().into();
        self.data_streams.on_conn_error(&error);
        self.datagram_flow.on_conn_error(&error);
        self.tls_handshake.on_conn_error(&error);
        self.parameters.on_conn_error(&error);

        self.spawn_deferred_termination(false);

        // No need to receive packets, just close all queues.
        self.rcvd_pkt_q.close_all();
        self.paths.close();
        Termination::draining(error)
    }

    fn has_viable_path(&self) -> bool {
        self.paths
            .paths::<Vec<_>>()
            .into_iter()
            .any(|(pathway, _)| Self::pathway_is_viable(pathway))
    }

    fn pathway_is_viable(pathway: Pathway) -> bool {
        if let (EndpointAddr::Direct { addr: local }, EndpointAddr::Direct { addr: remote }) =
            (pathway.local(), pathway.remote())
        {
            local.ip().is_loopback() == remote.ip().is_loopback()
        } else {
            true
        }
    }
}

pub struct Connection {
    state: RwLock<Result<Components, Termination>>,
    conn_state: ArcConnState,
    weak_self: Weak<Connection>,
    qlog_span: qevent::telemetry::Span,
    tracing_span: tracing::Span,
}

impl Connection {
    fn commit_transport_failure_locked(
        conn_state: &ArcConnState,
        conn: &mut Result<Components, Termination>,
        error: QuicError,
    ) -> Error {
        let core_conn = match conn {
            Ok(core_conn) => core_conn.clone(),
            Err(termination) => return termination.error(),
        };

        let termination = if core_conn.send_lock.is_permitted() {
            if conn_state.enter_closing(&error).is_none() {
                return error.into();
            }
            core_conn.enter_closing(error.into())
        } else {
            if conn_state.enter_draining_with_error(&error).is_none() {
                return error.into();
            }
            core_conn.enter_silent_draining(error.into())
        };
        let error = termination.error();
        *conn = Err(termination);
        error
    }

    fn keep_alive_until_closed(&self) {
        let Some(connection) = self.weak_self.upgrade() else {
            return;
        };
        let span = connection.tracing_span.clone();
        tokio::spawn(tracing::Instrument::instrument(
            async move {
                connection.conn_state.closed().await;
            },
            span,
        ));
    }

    fn application_close(&self, error: AppError, keep_alive: bool) -> Result<(), Error> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());
        let event_broker = {
            let mut conn = self.state.write().unwrap();
            match conn.as_ref() {
                Ok(core_conn) => {
                    let event_broker = core_conn.event_broker.clone();
                    let termination = if core_conn.send_lock.is_permitted() {
                        if self.conn_state.enter_closing(&error).is_none() {
                            return Err(error.into());
                        }
                        core_conn.clone().enter_closing(error.clone().into())
                    } else {
                        if self.conn_state.enter_draining_with_error(&error).is_none() {
                            return Err(error.into());
                        }
                        core_conn
                            .clone()
                            .enter_silent_draining(error.clone().into())
                    };
                    *conn = Err(termination);
                    event_broker
                }
                Err(termination) => return Err(termination.error()),
            }
        };

        if keep_alive {
            self.keep_alive_until_closed();
        }
        event_broker.emit(Event::ApplicationClose(error));
        Ok(())
    }

    // called by event
    pub fn enter_closing(&self, error: QuicError) -> Result<(), Error> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());
        let mut conn = self.state.write().unwrap();
        if let Err(termination) = conn.as_ref() {
            return Err(termination.error());
        }
        let _ = Self::commit_transport_failure_locked(&self.conn_state, &mut conn, error);
        Ok(())
    }

    /// Close the connection with application close frame.
    ///
    /// Return error if the connection is already closed.
    #[doc(alias = "application_close")]
    pub fn close(&self, reason: impl Into<Cow<'static, str>>, code: u64) -> Result<(), Error> {
        let error_code = code.try_into().expect("application error code overflow");
        let error = AppError::new(error_code, reason);
        self.application_close(error, true)
    }

    pub(crate) fn enter_draining(&self, ccf: ConnectionCloseFrame) -> bool {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());
        let mut conn = self.state.write().unwrap();
        if self.conn_state.enter_draining(&ccf).is_none() {
            return false;
        }
        match conn.as_mut() {
            Ok(core_conn) => {
                *conn = Err(core_conn.clone().enter_draining(ccf));
                true
            }
            Err(termination) => termination.enter_draining(),
        }
    }

    fn try_map_components<T>(&self, op: impl FnOnce(&Components) -> T) -> Result<T, Error> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());
        self.state
            .read()
            .unwrap()
            .as_ref()
            .map(op)
            .map_err(|termination| termination.error())
    }

    fn try_map_components_future<F, M>(
        &self,
        op: M,
    ) -> impl Future<Output = Result<F::Output, Error>> + Send + use<F, M>
    where
        F: Future + Send,
        M: FnOnce(&Components) -> F,
    {
        match self.try_map_components(op) {
            Ok(future) => future.map(Ok).left_future(),
            Err(error) => std::future::ready(error).map(Err).right_future(),
        }
    }

    /// Check if the connection is still valid.
    ///
    /// Return error if no viable path exists, or the connection is closed.
    #[doc(alias = "check")]
    pub fn validate(&self) -> Result<(), Error> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());
        let mut conn = self.state.write().unwrap();
        let no_viable_path = match conn.as_ref() {
            Ok(core_conn) => core_conn.paths.is_empty(),
            Err(termination) => return Err(termination.error()),
        };
        if no_viable_path {
            let error =
                QuicError::with_default_fty(ErrorKind::NoViablePath, "No viable path exist");
            return Err(Self::commit_transport_failure_locked(
                &self.conn_state,
                &mut conn,
                error,
            ));
        }
        Ok(())
    }

    pub fn has_viable_path(&self) -> Result<bool, Error> {
        self.try_map_components(Components::has_viable_path)
    }

    pub fn role(&self) -> Result<Role, Error> {
        self.try_map_components(|core_conn| core_conn.role())
    }

    /// Gets the connection metrics for tracking data volumes.
    ///
    /// Returns the metrics that track:
    /// - pending_send_bytes: Data written by application but not yet sent
    /// - sent_unacked_bytes: Data sent but not yet acknowledged
    /// - sent_acked_bytes: Data sent and acknowledged
    pub fn metrics(&self) -> Result<ArcConnectionMetrics, Error> {
        self.try_map_components(|core_conn| core_conn.metrics().clone())
    }

    #[allow(clippy::type_complexity)]
    pub fn open_bi_stream(
        &self,
    ) -> Impl_Future![Result<Option<(StreamId, (StreamReader, StreamWriter))>, Error>] {
        self.try_map_components_future(|core_conn| core_conn.open_bi_stream())
            .map(|result| result?)
    }

    pub fn open_uni_stream(&self) -> Impl_Future![Result<Option<(StreamId, StreamWriter)>, Error>] {
        self.try_map_components_future(|core_conn| core_conn.open_uni_stream())
            .map(|result| result?)
    }

    #[allow(clippy::type_complexity)]
    pub fn accept_bi_stream(
        &self,
    ) -> Impl_Future![Result<(StreamId, (StreamReader, StreamWriter)), Error>] {
        self.try_map_components_future(|core_conn| core_conn.accept_bi_stream())
            .map(|result| result?)
    }

    pub fn accept_uni_stream(&self) -> Impl_Future![Result<(StreamId, StreamReader), Error>] {
        self.try_map_components_future(|core_conn| core_conn.accept_uni_stream())
            .map(|result| result?)
    }

    #[cfg(feature = "datagram")]
    #[deprecated]
    #[allow(deprecated)]
    pub fn datagram_reader(&self) -> Result<io::Result<DatagramReader>, Error> {
        self.try_map_components(|core_conn| core_conn.datagram_reader())
    }

    #[cfg(feature = "datagram")]
    #[deprecated]
    #[allow(deprecated)]
    pub async fn datagram_writer(&self) -> Result<io::Result<DatagramWriter>, Error> {
        Ok(self
            .try_map_components(|core_conn| core_conn.datagram_writer())?
            .await)
    }

    pub fn add_path(&self, way: Way) -> Result<(), CreatePathFailure> {
        self.try_map_components(|core_conn| core_conn.add_path(way))
            .unwrap_or_else(|cc| Err(CreatePathFailure::ConnectionClosed(cc)))
    }

    pub fn del_path(&self, pathway: &Pathway) -> Result<(), Error> {
        self.try_map_components(|core_conn| core_conn.del_path(pathway))
    }

    pub fn origin_dcid(&self) -> Result<cid::ConnectionId, Error> {
        self.try_map_components(|core_conn| core_conn.cid_registry.origin_dcid())
    }

    pub fn handshaked(&self) -> Impl_Future![Result<(), Error>] {
        self.try_map_components_future(|core_conn| core_conn.conn_state.handshaked())
            .map(|result| result?)
    }

    pub fn terminated(&self) -> Impl_Future![Error] {
        self.try_map_components_future(|core_conn| core_conn.conn_state.terminated())
            .map(|(Ok(error) | Err(error))| error)
    }

    pub fn local_authority(&self) -> Impl_Future![Result<Option<LocalAuthority>, Error>] {
        self.try_map_components_future(|core_conn| core_conn.local_authority())
            .map(|result| result?)
    }

    pub fn remote_authority(&self) -> Impl_Future![Result<Option<RemoteAuthority>, Error>] {
        self.try_map_components_future(|core_conn| core_conn.remote_authority())
            .map(|result| result?)
    }

    pub fn server_name(&self) -> Impl_Future![Result<String, Error>] {
        self.try_map_components_future(|core_conn| match core_conn.role() {
            Role::Client => core_conn
                .remote_authority()
                .map_ok(|agent| agent.unwrap().name().to_owned())
                .left_future(),
            Role::Server => core_conn
                .local_authority()
                .map_ok(|agent| agent.unwrap().name().to_owned())
                .right_future(),
        })
        .map(|result| result?)
    }

    pub fn add_peer_endpoint(
        &self,
        addr: EndpointAddr,
        source: qresolve::Source,
    ) -> Result<(), Error> {
        self.try_map_components(|core_conn| core_conn.add_peer_endpoint(addr, source))
    }

    pub fn upsert_local_endpoint(
        &self,
        bind: BindUri,
        key: InterfaceEndpointKey,
        endpoint: EndpointAddr,
    ) -> Result<(), Error> {
        self.try_map_components(|core_conn| core_conn.upsert_local_endpoint(bind, key, endpoint))
    }

    pub fn remove_local_endpoint(
        &self,
        bind: &BindUri,
        key: &InterfaceEndpointKey,
    ) -> Result<(), Error> {
        self.try_map_components(|core_conn| core_conn.remove_local_endpoint(bind, key))
    }

    pub fn close_local_endpoints(&self, bind: &BindUri) -> Result<(), Error> {
        self.try_map_components(|core_conn| core_conn.close_local_endpoints(bind))
    }

    pub fn path_context(&self) -> Result<ArcPathContexts, Error> {
        self.try_map_components(|core_conn| core_conn.paths.clone())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _span = self.tracing_span.enter();
        let error = AppError::new(0_u64.try_into().expect("zero app error code"), "");
        if self.application_close(error, false).is_ok() {
            #[cfg(debug_assertions)]
            tracing::warn!(target: "quic", "connection is still active when dropped, close it automatically.");
            #[cfg(not(debug_assertions))]
            tracing::debug!(target: "quic", "connection is still active when dropped, close it automatically.");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use qbase::{error::ErrorKind, token::handy::NoopTokenRegistry};
    use rustls::{
        RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
        version::TLS13,
    };

    use super::*;
    use crate::state;

    const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
    const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
    const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

    fn install_crypto_provider() {
        static CRYPTO_PROVIDER: Once = Once::new();
        CRYPTO_PROVIDER.call_once(|| {
            _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn test_client_tls_config() -> rustls::ClientConfig {
        install_crypto_provider();
        let mut roots = RootCertStore::empty();
        roots
            .add_parsable_certificates(CertificateDer::pem_slice_iter(CA_CERT).map(Result::unwrap));
        rustls::ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    fn test_server_tls_config() -> rustls::ServerConfig {
        install_crypto_provider();
        let certs = CertificateDer::pem_slice_iter(SERVER_CERT)
            .collect::<Result<Vec<_>, _>>()
            .expect("server cert should parse");
        let key = PrivateKeyDer::from_pem_slice(SERVER_KEY).expect("server key should parse");
        rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server cert/key should be valid")
    }

    fn test_client_connection() -> Arc<Connection> {
        Connection::new_client("localhost".to_owned(), Arc::new(NoopTokenRegistry))
            .with_tls_config(test_client_tls_config())
            .with_cids(cid::ConnectionId::from_slice(b"validate-client"))
            .run()
    }

    fn test_server_connection() -> Arc<Connection> {
        Connection::new_server(Arc::new(NoopTokenRegistry))
            .with_tls_config(test_server_tls_config())
            .with_cids(cid::ConnectionId::from_slice(b"validate-server"))
            .run()
    }

    #[tokio::test]
    async fn validate_without_paths_latches_client_error_and_enters_closing() {
        let connection = test_client_connection();

        let first = connection
            .validate()
            .expect_err("pathless client connection should fail validation");
        assert_eq!(first.kind(), ErrorKind::NoViablePath);
        assert_eq!(connection.conn_state.current(), Some(state::CLOSING));

        let second = connection
            .validate()
            .expect_err("terminal client error should be sticky");
        assert_eq!(second, first);

        let terminated = connection.terminated().await;
        assert_eq!(terminated, first);
    }

    #[tokio::test]
    async fn validate_without_send_permit_latches_server_error_and_enters_draining() {
        let connection = test_server_connection();

        let first = connection
            .validate()
            .expect_err("pathless server connection should fail validation");
        assert_eq!(first.kind(), ErrorKind::NoViablePath);
        assert_eq!(connection.conn_state.current(), Some(state::DRAINING));

        let second = connection
            .validate()
            .expect_err("terminal server error should be sticky");
        assert_eq!(second, first);

        let terminated = connection.terminated().await;
        assert_eq!(terminated, first);
    }
}
