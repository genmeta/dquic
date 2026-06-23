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
    net::SocketAddr,
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
    net::{
        addr::EndpointAddr,
        route::{Link, Pathway},
    },
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
        location::Locations,
        route::{self, QuicRouterEntry, RcvdPacketQueue},
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
    locations: Arc<Locations>,
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

    pub fn add_path(
        &self,
        bind_uri: BindUri,
        link: Link,
        pathway: Pathway,
    ) -> Result<(), CreatePathFailure> {
        self.get_or_try_create_path(bind_uri, link, pathway, false)
            .map(|_| ())
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
    pub fn enter_closing(self, error: Error) -> Termination {
        qevent::event!(ConnectionClosed {
            owner: Owner::Local,
            error: &error, // TODO: trigger
        });

        self.data_streams.on_conn_error(&error);
        self.datagram_flow.on_conn_error(&error);
        self.tls_handshake.on_conn_error(&error);
        self.parameters.on_conn_error(&error);

        tokio::spawn(
            {
                let pto_duration = self.paths.max_pto_duration().unwrap_or_default();
                let event_broker = self.event_broker.clone();
                let rcvd_pkt_q = self.rcvd_pkt_q.clone();
                let paths = self.paths.clone();
                let local_cids = self.cid_registry.local.clone();
                async move {
                    tokio::time::sleep(pto_duration).await;
                    rcvd_pkt_q.close_all();
                    paths.clear();
                    local_cids.clear();
                    event_broker.emit(Event::Terminated);
                }
            }
            .instrument_in_current()
            .in_current_span(),
        );

        match self.send_lock.is_permitted() {
            // If permitted, we can send ccf packets.
            true => {
                let terminator = Arc::new(Terminator::new(error.clone().into(), &self));
                tokio::spawn(
                    async move { self.spaces.send_ccf_packets(terminator.as_ref()).await }
                        .instrument_in_current()
                        .in_current_span(),
                );
            }
            // The send lock denies close packets for silent refusal paths.
            false => self.paths.clear(),
        }

        Termination::closing(error, self.cid_registry.local, self.rcvd_pkt_q, self.paths)
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

        tokio::spawn(
            {
                let pto_duration = self.paths.max_pto_duration().unwrap_or_default();
                let event_broker = self.event_broker.clone();
                let local_cids = self.cid_registry.local.clone();
                async move {
                    tokio::time::sleep(pto_duration).await;
                    local_cids.clear();
                    event_broker.emit(Event::Terminated);
                }
            }
            .instrument_in_current()
            .in_current_span(),
        );

        // No need to receive packets, just close all queues.
        self.rcvd_pkt_q.close_all();
        self.paths.clear();
        Termination::draining(error, self.cid_registry.local)
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

    fn close_by_application(&self, error: AppError, keep_alive: bool) -> Result<(), Error> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());
        let event_broker = {
            let mut conn = self.state.write().unwrap();
            match conn.as_ref() {
                Ok(core_conn) => {
                    if self.conn_state.enter_closing(&error).is_none() {
                        return Err(error.into());
                    }

                    let event_broker = core_conn.event_broker.clone();
                    *conn = Err(core_conn.clone().enter_closing(error.clone().into()));
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
        match conn.as_ref() {
            Ok(core_conn) => {
                if self.conn_state.enter_closing(&error).is_none() {
                    return Err(error.into());
                }

                *conn = Err(core_conn.clone().enter_closing(error.into()));
                Ok(())
            }
            Err(termination) => Err(termination.error()),
        }
    }

    /// Close the connection with application close frame.
    ///
    /// Return error if the connection is already closed.
    #[doc(alias = "application_close")]
    pub fn close(&self, reason: impl Into<Cow<'static, str>>, code: u64) -> Result<(), Error> {
        let error_code = code.try_into().expect("application error code overflow");
        let error = AppError::new(error_code, reason);
        self.close_by_application(error, true)
    }

    pub fn enter_draining(&self, ccf: ConnectionCloseFrame) -> bool {
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
        let core_conn = conn.as_ref().map_err(|e| e.error())?;
        let validate = 'validate: {
            if core_conn.paths.is_empty() {
                let error =
                    QuicError::with_default_fty(ErrorKind::NoViablePath, "No viable path exist");
                break 'validate Err(error);
            }
            Ok(())
        };
        if let Err(error) = validate {
            core_conn.event_broker.emit(Event::Failed(error.clone()));
            let termination = core_conn.clone().enter_closing(error.into());
            let error = termination.error();
            *conn = Err(termination);
            return Err(error);
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

    pub fn add_path(
        &self,
        bind_uri: BindUri,
        link: Link,
        pathway: Pathway,
    ) -> Result<(), CreatePathFailure> {
        self.try_map_components(|core_conn| core_conn.add_path(bind_uri, link, pathway))
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

    #[deprecated(
        note = "use upsert_local_endpoints for observed interface endpoints; this method only adds an explicit local endpoint"
    )]
    pub fn add_local_endpoint(&self, bind: BindUri, addr: EndpointAddr) -> Result<(), Error> {
        self.try_map_components(|core_conn| core_conn.add_local_endpoint(bind, addr))
    }

    #[deprecated(
        note = "use remove_local_endpoints for observed interface endpoints; this method only removes an explicit local endpoint"
    )]
    pub fn remove_local_endpoint(&self, bind: &BindUri, addr: EndpointAddr) -> Result<(), Error> {
        self.try_map_components(|core_conn| core_conn.remove_local_endpoint(bind, addr))
    }

    pub fn add_peer_endpoint(
        &self,
        addr: EndpointAddr,
        source: qresolve::Source,
    ) -> Result<(), Error> {
        self.try_map_components(|core_conn| core_conn.add_peer_endpoint(addr, source))
    }

    pub fn upsert_local_endpoints(
        &self,
        bind: BindUri,
        endpoints: impl IntoIterator<Item = EndpointAddr>,
    ) -> Result<(), Error> {
        self.try_map_components(|core_conn| {
            core_conn.upsert_observed_local_endpoints(bind, endpoints)
        })
    }

    pub fn remove_local_endpoints(&self, bind: &BindUri) -> Result<(), Error> {
        self.try_map_components(|core_conn| core_conn.remove_observed_local_endpoints(bind))
    }

    pub fn add_local_punch_address(
        &self,
        bind: BindUri,
        addr: EndpointAddr,
    ) -> Result<io::Result<()>, Error> {
        self.try_map_components(|core_conn| core_conn.add_local_punch_address(bind, addr))
    }

    pub fn remove_address(&self, addr: SocketAddr) -> Result<(), Error> {
        self.try_map_components(|core_conn| core_conn.remove_address(addr))
    }

    pub fn subscribe_local_address(&self) -> Result<(), Error> {
        self.try_map_components(|core_conn| core_conn.subscribe_local_address())
    }

    pub fn path_context(&self) -> Result<ArcPathContexts, Error> {
        self.try_map_components(|core_conn| core_conn.paths.clone())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _span = self.tracing_span.enter();
        let error = AppError::new(0_u64.try_into().expect("zero app error code"), "");
        if self.close_by_application(error, false).is_ok() {
            #[cfg(debug_assertions)]
            tracing::warn!(target: "quic", "connection is still active when dropped, close it automatically.");
            #[cfg(not(debug_assertions))]
            tracing::debug!(target: "quic", "connection is still active when dropped, close it automatically.");
        }
    }
}
