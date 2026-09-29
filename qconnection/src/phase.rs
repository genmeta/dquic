//! Shared sending material. Each path reads the current phase for every burst.
use std::sync::{Arc, Mutex, MutexGuard};

use qbase::{
    Epoch,
    cid::{ArcCidCell, ConnectionId},
    error::{ErrorKind, QuicError},
    frame::io::SendFrame,
    net::tx::ArcSendWakers,
    param::ParameterId,
    role::Role,
    sid::handy::ConsistentConcurrency,
};
use qtransport::{
    GuaranteedFrame,
    keys::{ArcKeys, ArcOneRttKeys},
    space::{Space, Spaces},
    transport::Transport,
};

use crate::{
    ArcParameters, ArcReliableFrames, CidRegistry, DataStreams, Error, FlowController,
    terminate::ArcTerminator,
};

/// Frame sources available before peer transport parameters arrive.
pub struct InitialPhase {
    pub initial: Arc<Space<ArcKeys>>,
    pub scid: ConnectionId,
    pub odcid: ConnectionId,
    dcid: Mutex<ConnectionId>,
    pub reliable_frames: ArcReliableFrames,
    pub(crate) terminator: ArcTerminator,
}

impl InitialPhase {
    pub fn new(scid: ConnectionId, odcid: ConnectionId, keys: qtls::BidirectionalKeys) -> Self {
        let reliable_frames = ArcReliableFrames::with_capacity(0);
        Self::with_components(scid, odcid, keys, reliable_frames)
    }

    pub fn with_components(
        scid: ConnectionId,
        odcid: ConnectionId,
        keys: qtls::BidirectionalKeys,
        reliable_frames: ArcReliableFrames,
    ) -> Self {
        let initial = Arc::new(Space::new(
            Epoch::Initial,
            ArcKeys::new(Arc::new(keys)),
            |_| {},
        ));
        let terminator = ArcTerminator::no_error();
        Self {
            initial,
            scid,
            odcid,
            dcid: Mutex::new(odcid),
            reliable_frames,
            terminator,
        }
    }

    pub fn dcid(&self) -> ConnectionId {
        *self.dcid.lock().unwrap()
    }
}

/// Complete frame sources. Identity verification remains the growing coroutine's job.
pub struct MaturePhase {
    pub spaces: Spaces,
    pub scid: ConnectionId,
    pub streams: DataStreams,
    pub flow: FlowController,
    pub reliable_frames: ArcReliableFrames,
    pub cid_registry: CidRegistry,
    pub initial_dcid: ArcCidCell<ArcReliableFrames>,
    pub peer_cid: ConnectionId,
    pub parameters: ArcParameters,
    pub(crate) terminator: ArcTerminator,
}

impl MaturePhase {
    pub(crate) fn new(
        early: &InitialPhase,
        handshake: Arc<Space<ArcKeys>>,
        parameters: ArcParameters,
        peer_cid: ConnectionId,
        reliable_frames: ArcReliableFrames,
        cid_registry: CidRegistry,
        initial_dcid: ArcCidCell<ArcReliableFrames>,
        keys: ArcOneRttKeys,
    ) -> Result<(Arc<Self>, Arc<Transport>), Error> {
        if parameters.remote::<ConnectionId>(ParameterId::InitialSourceConnectionId) != peer_cid {
            return Err(QuicError::with_default_fty(
                ErrorKind::TransportParameter,
                "peer Initial source CID mismatch",
            )
            .into());
        }
        if parameters.role() == Role::Client
            && (parameters.remote::<ConnectionId>(ParameterId::OriginalDestinationConnectionId)
                != early.odcid
                || parameters
                    .server()
                    .contains(ParameterId::RetrySourceConnectionId))
        {
            return Err(QuicError::with_default_fty(
                ErrorKind::TransportParameter,
                "server original/retry CID mismatch",
            )
            .into());
        }
        let concurrency = Box::new(ConsistentConcurrency::new(
            parameters.local(ParameterId::InitialMaxStreamsBidi),
            parameters.local(ParameterId::InitialMaxStreamsUni),
        ));
        let streams = match parameters.role() {
            Role::Client => DataStreams::new(
                parameters.role(),
                parameters.client(),
                parameters.server(),
                concurrency,
                reliable_frames.clone(),
                None,
            ),
            Role::Server => DataStreams::new(
                parameters.role(),
                parameters.server(),
                parameters.client(),
                concurrency,
                reliable_frames.clone(),
                None,
            ),
        };
        let flow = FlowController::new(
            parameters.remote(ParameterId::InitialMaxData),
            parameters.local(ParameterId::InitialMaxData),
            reliable_frames.clone(),
        );
        let recover_streams = streams.clone();
        let reliable = reliable_frames.clone();
        let data = Arc::new(Space::<ArcOneRttKeys>::new(
            Epoch::Data,
            keys,
            move |frame| match frame {
                GuaranteedFrame::Stream(frame) => recover_streams.may_loss_data(frame),
                GuaranteedFrame::Reliable(frame) => reliable.send_frame([frame.clone()]),
                GuaranteedFrame::Crypto(_) => unreachable!("Space recovers CRYPTO internally"),
            },
        ));
        let sender = Arc::new(Self {
            spaces: Spaces {
                initial: early.initial.clone(),
                handshake,
                data: data.clone(),
            },
            scid: early.scid,
            streams: streams.clone(),
            flow: flow.clone(),
            reliable_frames: reliable_frames.clone(),
            cid_registry,
            initial_dcid,
            peer_cid,
            parameters: parameters.clone(),
            terminator: early.terminator.clone(),
        });
        let transport = Arc::new(Transport::new(
            data,
            parameters,
            streams,
            flow,
            reliable_frames,
        ));
        Ok((sender, transport))
    }
}

/// Initial and Handshake packet sources available before peer parameters complete Data.
pub struct HandshakePhase {
    pub initial: Arc<InitialPhase>,
    pub handshake: Arc<Space<ArcKeys>>,
    pub(crate) terminator: ArcTerminator,
}

#[derive(Clone)]
pub enum ConnPhase {
    Initial(Arc<InitialPhase>),
    Handshake(Arc<HandshakePhase>),
    Mature(Arc<MaturePhase>),
}

impl ConnPhase {
    pub fn dcid(&self) -> ConnectionId {
        match self {
            Self::Initial(p) => p.dcid(),
            Self::Handshake(p) => p.initial.dcid(),
            Self::Mature(p) => p.peer_cid,
        }
    }
}

#[derive(Clone)]
pub struct ArcConnPhase {
    phase: Arc<Mutex<ConnPhase>>,
    send_wakers: ArcSendWakers,
}

impl ArcConnPhase {
    pub fn initial(sender: InitialPhase) -> Self {
        Self {
            phase: Arc::new(Mutex::new(ConnPhase::Initial(Arc::new(sender)))),
            send_wakers: ArcSendWakers::default(),
        }
    }

    pub fn lock_guard(&self) -> MutexGuard<'_, ConnPhase> {
        self.phase.lock().unwrap()
    }

    pub fn get(&self) -> ConnPhase {
        self.phase.lock().unwrap().clone()
    }

    pub(crate) fn set_dcid(&self, dcid: ConnectionId) {
        match &*self.phase.lock().unwrap() {
            ConnPhase::Initial(p) => *p.dcid.lock().unwrap() = dcid,
            ConnPhase::Handshake(p) => *p.initial.dcid.lock().unwrap() = dcid,
            ConnPhase::Mature(_) => return,
        }
        self.send_wakers.wake_all();
    }

    pub(crate) fn poll_phase(&self, cx: &mut std::task::Context<'_>) -> MutexGuard<'_, ConnPhase> {
        self.send_wakers.register(cx.waker());
        self.lock_guard()
    }

    pub(crate) fn cancel(&self, waker: &std::task::Waker) {
        self.send_wakers.cancel(waker);
    }

    pub(crate) fn terminator(&self) -> ArcTerminator {
        match &*self.phase.lock().unwrap() {
            ConnPhase::Initial(phase) => phase.terminator.clone(),
            ConnPhase::Handshake(phase) => phase.terminator.clone(),
            ConnPhase::Mature(phase) => phase.terminator.clone(),
        }
    }

    pub(crate) fn enter_handshake(
        &self,
        initial: Arc<InitialPhase>,
        handshake: Arc<Space<ArcKeys>>,
    ) {
        let terminator = initial.terminator.clone();
        *self.phase.lock().unwrap() = ConnPhase::Handshake(Arc::new(HandshakePhase {
            initial,
            handshake,
            terminator,
        }));
        self.send_wakers.wake_all();
    }

    pub(crate) fn enter_mature(&self, sender: Arc<MaturePhase>) {
        *self.phase.lock().unwrap() = ConnPhase::Mature(sender);
        self.send_wakers.wake_all();
    }
}
