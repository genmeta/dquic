//! Shared sending material. Each path reads the current phase for every burst.
use std::{
    sync::{Arc, Mutex, MutexGuard, RwLock},
    time::Duration,
};

use qbase::{
    Epoch,
    cid::{ArcCidCell, ConnectionId},
    error::{ErrorKind, QuicError},
    net::tx::ArcSendWakers,
    param::ParameterId,
    role::Role,
    sid::handy::ConsistentConcurrency,
    util::IndexDeque,
};
use qtransport::{
    keys::{ArcKeys, ArcOneRttKeys},
    space::{DataSpace, Space, Spaces},
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
    trackers: Arc<RwLock<IndexDeque<Arc<dyn qcongestion::Resend>, 2>>>,
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
        ));
        let mut trackers = IndexDeque::<Arc<dyn qcongestion::Resend>, 2>::with_capacity(3);
        trackers.push_back(initial.clone()).expect("Initial epoch");
        let terminator = ArcTerminator::no_error();
        Self {
            initial,
            scid,
            odcid,
            dcid: Mutex::new(odcid),
            reliable_frames,
            trackers: Arc::new(RwLock::new(trackers)),
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
    trackers: Arc<RwLock<IndexDeque<Arc<dyn qcongestion::Resend>, 2>>>,
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
    pub flow: FlowController,
    pub cid_registry: CidRegistry,
    pub initial_dcid: ArcCidCell<ArcReliableFrames>,
    pub peer_cid: ConnectionId,
    pub parameters: ArcParameters,
    trackers: Arc<RwLock<IndexDeque<Arc<dyn qcongestion::Resend>, 2>>>,
    pub(crate) terminator: ArcTerminator,
}

impl MaturePhase {
    pub(crate) fn retire_handshake_spaces(&self) {
        self.spaces.initial.retire();
        self.spaces.handshake.retire();
        self.trackers
            .write()
            .unwrap()
            .drain_to(Epoch::Data as u64)
            .for_each(drop);
    }

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
        let data = Arc::new(DataSpace::new(keys, streams, reliable_frames));
        let sender = Arc::new(Self {
            spaces: Spaces {
                initial: early.initial.clone(),
                handshake,
                data: data.clone(),
            },
            scid: early.scid,
            flow: flow.clone(),
            cid_registry,
            initial_dcid,
            peer_cid,
            parameters: parameters.clone(),
            trackers: early.trackers.clone(),
            terminator: early.terminator.clone(),
        });
        let transport = Arc::new(Transport::new(data, parameters, flow));
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

    pub(crate) fn trackers(&self) -> Arc<RwLock<IndexDeque<Arc<dyn qcongestion::Resend>, 2>>> {
        match self {
            Self::Initial(phase) => phase.trackers.clone(),
            Self::Handshake(phase) => phase.trackers.clone(),
            Self::Mature(phase) => phase.trackers.clone(),
        }
    }

    pub(crate) fn on_sent(
        &self,
        epoch: Epoch,
        packets: impl IntoIterator<Item = (u64, bool)>,
        retransmit_after: Duration,
        retention: Duration,
    ) {
        let space = match self {
            Self::Initial(phase) => &phase.initial,
            Self::Handshake(phase) => match epoch {
                Epoch::Initial => &phase.initial,
                Epoch::Handshake => &phase.handshake,
                Epoch::Data => unreachable!("Handshake has no Data space"),
            },
            Self::Mature(phase) => match epoch {
                Epoch::Initial => &phase.spaces.initial,
                Epoch::Handshake => &phase.spaces.handshake,
                Epoch::Data => {
                    phase
                        .spaces
                        .data
                        .on_sent(packets, retransmit_after, retention);
                    return;
                }
            },
        };
        space.on_sent(packets, retransmit_after, retention);
    }

    pub(crate) fn cancel(&self, epoch: Epoch, pn: u64) {
        match self {
            Self::Initial(phase) => phase.initial.cancel(pn),
            Self::Handshake(phase) => match epoch {
                Epoch::Initial => phase.initial.cancel(pn),
                Epoch::Handshake => phase.handshake.cancel(pn),
                Epoch::Data => unreachable!("Handshake has no Data space"),
            },
            Self::Mature(phase) => match epoch {
                Epoch::Initial => phase.spaces.initial.cancel(pn),
                Epoch::Handshake => phase.spaces.handshake.cancel(pn),
                Epoch::Data => phase.spaces.data.cancel(pn),
            },
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
        initial
            .trackers
            .write()
            .unwrap()
            .push_back(handshake.clone())
            .expect("Handshake epoch");
        *phase = ConnPhase::Handshake(Arc::new(HandshakePhase {
            initial: initial.initial.clone(),
            handshake,
            scid: initial.scid,
            dcid: Mutex::new(initial.dcid()),
            reliable_frames: initial.reliable_frames.clone(),
            trackers: initial.trackers.clone(),
            terminator: initial.terminator.clone(),
            upgrade_wakers: upgrade_wakers.clone(),
        }));
        drop(phase);
        upgrade_wakers.wake_all();
    }

    pub(crate) fn enter_mature(&self, phase: Arc<MaturePhase>) {
        let mut current = self.lock_guard();
        {
            let mut trackers = phase.trackers.write().unwrap();
            if matches!(*current, ConnPhase::Initial(_)) {
                trackers
                    .push_back(phase.spaces.handshake.clone())
                    .expect("Handshake epoch");
            }
            trackers
                .push_back(phase.spaces.data.clone())
                .expect("Data epoch");
        }
        let previous = std::mem::replace(&mut *current, ConnPhase::Mature(phase));
        drop(current);
        if let Some(wakers) = previous.upgrade_wakers() {
            for waker in wakers.drain() {
                waker.wake();
            }
        }
    }
}
