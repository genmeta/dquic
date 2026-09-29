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
    upgrade_wakers: ArcSendWakers,
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
            upgrade_wakers: ArcSendWakers::default(),
        }
    }

    pub fn dcid(&self) -> ConnectionId {
        *self.dcid.lock().unwrap()
    }
}

/// Initial and Handshake packet sources available before peer parameters complete Data.
pub struct HandshakePhase {
    pub initial: Arc<Space<ArcKeys>>,
    pub handshake: Arc<Space<ArcKeys>>,
    pub scid: ConnectionId,
    dcid: Mutex<ConnectionId>,
    pub reliable_frames: ArcReliableFrames,
    pub(crate) terminator: ArcTerminator,
    upgrade_wakers: ArcSendWakers,
}

impl HandshakePhase {
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

#[derive(Clone)]
pub enum ConnPhase {
    Initial(Arc<InitialPhase>),
    Handshake(Arc<HandshakePhase>),
    Mature(Arc<MaturePhase>),
}

impl ConnPhase {
    fn upgrade_wakers(&self) -> Option<&ArcSendWakers> {
        match self {
            Self::Initial(p) => Some(&p.upgrade_wakers),
            Self::Handshake(p) => Some(&p.upgrade_wakers),
            Self::Mature(_) => None,
        }
    }

    pub fn dcid(&self) -> ConnectionId {
        match self {
            Self::Initial(p) => p.dcid(),
            Self::Handshake(p) => p.dcid(),
            Self::Mature(p) => p.peer_cid,
        }
    }
}

#[derive(Clone)]
pub struct ArcConnPhase(Arc<Mutex<ConnPhase>>);

impl ArcConnPhase {
    pub fn initial(sender: InitialPhase) -> Self {
        Self(Arc::new(Mutex::new(ConnPhase::Initial(Arc::new(sender)))))
    }

    pub fn lock_guard(&self) -> MutexGuard<'_, ConnPhase> {
        self.0.lock().unwrap()
    }

    pub fn get(&self) -> ConnPhase {
        self.0.lock().unwrap().clone()
    }

    pub(crate) fn set_dcid(&self, dcid: ConnectionId) {
        let phase = self.lock_guard();
        let upgrade_wakers = match &*phase {
            ConnPhase::Initial(p) => {
                *p.dcid.lock().unwrap() = dcid;
                p.upgrade_wakers.clone()
            }
            ConnPhase::Handshake(p) => {
                *p.dcid.lock().unwrap() = dcid;
                p.upgrade_wakers.clone()
            }
            ConnPhase::Mature(_) => return,
        };
        drop(phase);
        upgrade_wakers.wake_all();
    }

    pub(crate) fn poll_phase(&self, cx: &mut std::task::Context<'_>) -> MutexGuard<'_, ConnPhase> {
        let phase = self.lock_guard();
        if let Some(wakers) = phase.upgrade_wakers() {
            wakers.register(cx.waker());
        }
        phase
    }

    pub(crate) fn cancel(&self, waker: &std::task::Waker) {
        if let Some(wakers) = self.lock_guard().upgrade_wakers() {
            wakers.cancel(waker);
        }
    }

    pub(crate) fn terminator(&self) -> ArcTerminator {
        match &*self.0.lock().unwrap() {
            ConnPhase::Initial(phase) => phase.terminator.clone(),
            ConnPhase::Handshake(phase) => phase.terminator.clone(),
            ConnPhase::Mature(phase) => phase.terminator.clone(),
        }
    }

    pub(crate) fn enter_handshake(&self, handshake: Arc<Space<ArcKeys>>) {
        let mut phase = self.lock_guard();
        let ConnPhase::Initial(initial) = &*phase else {
            unreachable!("enter_handshake starts with InitialPhase")
        };
        let upgrade_wakers = initial.upgrade_wakers.clone();
        *phase = ConnPhase::Handshake(Arc::new(HandshakePhase {
            initial: initial.initial.clone(),
            handshake,
            scid: initial.scid,
            dcid: Mutex::new(initial.dcid()),
            reliable_frames: initial.reliable_frames.clone(),
            terminator: initial.terminator.clone(),
            upgrade_wakers: upgrade_wakers.clone(),
        }));
        drop(phase);
        upgrade_wakers.wake_all();
    }

    pub(crate) fn enter_mature(&self, phase: Arc<MaturePhase>) {
        let previous = std::mem::replace(&mut *self.lock_guard(), ConnPhase::Mature(phase));
        if let Some(wakers) = previous.upgrade_wakers() {
            for waker in wakers.drain() {
                waker.wake();
            }
        }
    }
}
