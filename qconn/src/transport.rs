use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use qbase::{
    Epoch, cid::ConnectionId, frame::ReliableFrame, net::tx::ArcSendWakers, role::Role,
    time::ArcConnIdle,
};
use qrecovery::reliable::ArcReliableFrameDeque;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    control::{Command, Control},
    data::DataPlane,
    lifecycle::CloseState,
    path::Paths,
    recv::Topology,
    space::Spaces,
};

/// Shared protocol handles survive promotion. TLS, packet inbox ownership and
/// task joins remain local to run_client/run_server and shutdown.
pub(crate) struct Transport {
    pub(crate) control: Control,
    pub(crate) spaces: Arc<Spaces>,
    pub(crate) paths: Paths,
    pub(crate) original_dcid: ConnectionId,
    pub(crate) local_cid: ConnectionId,
    pub(crate) peer_cid: OnceLock<ConnectionId>,
    pub(crate) received_route: OnceLock<(qbase::net::route::Pathway, qbase::net::route::Link)>,
    pub(crate) scope: OnceLock<crate::Scope>,
    pub(crate) data: Arc<OnceLock<Arc<DataPlane>>>,
    pub(crate) reliable: ArcReliableFrameDeque<ReliableFrame>,
    pub(crate) wakers: ArcSendWakers,
    pub(crate) idle: ArcConnIdle,
    pub(crate) close: Arc<CloseState>,
    pub(crate) stop: CancellationToken,
    pub(crate) protocol: Arc<qprotocol::QuicProtocol>,
    pub(crate) crypto: mpsc::Sender<(qtls::CryptoLevel, bytes::Bytes)>,
}

impl Transport {
    #[expect(clippy::type_complexity, reason = "return runtime components directly to the owning task")]
    pub(crate) fn new(
        role: Role,
        keys: qtls::BidirectionalKeys,
        original_dcid: ConnectionId,
        local_cid: ConnectionId,
        protocol: Arc<qprotocol::QuicProtocol>,
        idle_timeout: Duration,
        received_at: tokio::time::Instant,
    ) -> (
        Arc<Self>,
        Topology,
        mpsc::Receiver<Command>,
        mpsc::Receiver<(qtls::CryptoLevel, bytes::Bytes)>,
    ) {
        let wakers = ArcSendWakers::new();
        let data = Arc::new(OnceLock::new());
        let reliable = ArcReliableFrameDeque::with_capacity_and_wakers(0, wakers.clone());
        let spaces = Spaces::new(data.clone(), reliable.clone());
        let topology = Topology::new(keys.opening);
        spaces
            .initial
            .install(
                Arc::new(keys.sealing.header),
                keys.sealing.packet,
                topology.journal(Epoch::Initial).unwrap().clone(),
                wakers.clone(),
            )
            .expect("new Initial space");
        let (control, commands) = Control::new(role);
        let (crypto, received_crypto) = mpsc::channel(32);
        (
            Arc::new(Self {
                control,
                spaces,
                paths: Paths::new(),
                original_dcid,
                local_cid,
                peer_cid: OnceLock::new(),
                received_route: OnceLock::new(),
                scope: OnceLock::new(),
                data,
                reliable,
                wakers,
                idle: ArcConnIdle::new_at(
                    idle_timeout,
                    Duration::ZERO,
                    Duration::ZERO,
                    received_at,
                ),
                close: Arc::new(CloseState::new()),
                stop: CancellationToken::new(),
                protocol,
                crypto,
            }),
            topology,
            commands,
            received_crypto,
        )
    }
}
