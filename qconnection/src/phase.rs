//! Shared sending material. Each path reads the current phase for every burst.
use std::{
    sync::{Arc, Mutex, MutexGuard, RwLock},
    task::Waker,
    time::Duration,
};

use qbase::{Epoch, cid::ConnectionId, net::tx::ArcSendWakers, util::IndexDeque};
use qtransport::{
    keys::ArcKeys,
    space::{Space, Spaces},
};
use qtraversal::punch::{ArcPuncher, ProbeEncoder};

use crate::{
    ArcParameters, ArcReliableFrames, ArcTracker, CidRegistry, FlowController,
    terminate::ArcTerminator,
};

/// Frame sources available before peer transport parameters arrive.
pub struct InitialPhase {
    pub initial_space: Arc<Space<ArcKeys>>,
    pub scid: ConnectionId,
    dcid: Mutex<ConnectionId>,
    pub odcid: ConnectionId,
    pub reliable_frames: ArcReliableFrames,
    pub cid_registry: CidRegistry,
    pub(crate) trackers: ArcTracker,
    pub(crate) terminator: ArcTerminator,
    upgrade_wakers: ArcSendWakers,
}

impl InitialPhase {
    pub fn new(
        (scid, dcid): (ConnectionId, ConnectionId),
        keys: qtls::BidirectionalKeys,
        reliable_frames: ArcReliableFrames,
        cid_registry: CidRegistry,
    ) -> Self {
        let odcid = cid_registry.origin_dcid();
        let initial_space = Arc::new(Space::new(Epoch::Initial, ArcKeys::new(Arc::new(keys))));
        let mut trackers = IndexDeque::<Arc<dyn qcongestion::Resend>, 2>::with_capacity(3);
        trackers
            .push_back(initial_space.clone())
            .expect("Initial epoch");
        let terminator = ArcTerminator::no_error();
        Self {
            initial_space,
            scid,
            dcid: Mutex::new(dcid),
            odcid,
            reliable_frames,
            cid_registry,
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
    pub initial_space: Arc<Space<ArcKeys>>,
    pub handshake_space: Arc<Space<ArcKeys>>,
    pub scid: ConnectionId,
    dcid: ConnectionId,
    pub reliable_frames: ArcReliableFrames,
    pub cid_registry: CidRegistry,
    trackers: ArcTracker,
    pub(crate) terminator: ArcTerminator,
    upgrade_wakers: ArcSendWakers,
}

impl HandshakePhase {
    pub fn dcid(&self) -> ConnectionId {
        self.dcid
    }
}

/// Complete frame sources. Identity verification remains the growing coroutine's job.
pub struct MaturePhase {
    pub spaces: Spaces,
    pub scid: ConnectionId,
    pub dcid: ConnectionId,
    pub parameters: ArcParameters,
    pub flow_ctrl: FlowController,
    pub cid_registry: CidRegistry,
    pub puncher: ArcPuncher<ArcReliableFrames, ProbeEncoder>,
    pub(crate) trackers: Arc<RwLock<IndexDeque<Arc<dyn qcongestion::Resend>, 2>>>,
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
}

#[derive(Clone)]
pub enum ConnPhase {
    Initial(Arc<InitialPhase>),
    Handshake(Arc<HandshakePhase>),
    Mature(Arc<MaturePhase>),
}

impl ConnPhase {
    pub(crate) fn retire_initial(&self) {
        match self {
            Self::Initial(phase) => phase.initial_space.retire(),
            Self::Handshake(phase) => phase.initial_space.retire(),
            Self::Mature(phase) => phase.spaces.initial.retire(),
        }
    }

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
            Self::Initial(phase) => &phase.initial_space,
            Self::Handshake(phase) => match epoch {
                Epoch::Initial => &phase.initial_space,
                Epoch::Handshake => &phase.handshake_space,
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
            Self::Initial(phase) => phase.initial_space.cancel(pn),
            Self::Handshake(phase) => match epoch {
                Epoch::Initial => phase.initial_space.cancel(pn),
                Epoch::Handshake => phase.handshake_space.cancel(pn),
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
            Self::Mature(p) => p.dcid,
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
            ConnPhase::Handshake(_) | ConnPhase::Mature(_) => return,
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

    pub(crate) fn unregister(&self, waker: &Waker) {
        if let Some(wakers) = self.lock_guard().upgrade_wakers() {
            wakers.unregister(waker);
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
            initial_space: initial.initial_space.clone(),
            handshake_space: handshake,
            scid: initial.scid,
            dcid: initial.dcid(),
            reliable_frames: initial.reliable_frames.clone(),
            cid_registry: initial.cid_registry.clone(),
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
