//! Shared sending material. Each path reads the current phase for every burst.
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use qbase::{Epoch, cid::ConnectionId, net::tx::ArcSendWakers, util::IndexDeque};
use qtransport::{
    keys::ArcKeys,
    space::{Space, Spaces},
    terminate::ArcTerminator,
};
use qtraversal::punch::{ArcPuncher, ProbeEncoder};

use crate::{ArcParameters, ArcReliableFrames, ArcTrackers, CidRegistry, FlowController};

/// Frame sources available before peer transport parameters arrive.
pub struct InitialPhase {
    pub initial_space: Arc<Space<ArcKeys>>,
    pub scid: ConnectionId,
    dcid: Mutex<ConnectionId>,
    pub odcid: ConnectionId,
    pub reliable_frames: ArcReliableFrames,
    pub cid_registry: CidRegistry,
    pub(crate) trackers: ArcTrackers,
    pub(crate) terminator: ArcTerminator,
    pub(crate) upgrade_wakers: ArcSendWakers,
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
        terminator.register(Arc::new(initial_space.crypto.clone()));
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
    pub dcid: ConnectionId,
    pub reliable_frames: ArcReliableFrames,
    pub cid_registry: CidRegistry,
    pub(crate) trackers: ArcTrackers,
    pub(crate) terminator: ArcTerminator,
    pub(crate) upgrade_wakers: ArcSendWakers,
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
    pub(crate) trackers: ArcTrackers,
    pub(crate) terminator: ArcTerminator,
}

#[derive(Clone)]
pub enum ConnPhase {
    Initial(Arc<InitialPhase>),
    Handshake(Arc<HandshakePhase>),
    Mature(Arc<MaturePhase>),
}

impl ConnPhase {
    pub(crate) fn retire_initial(&self) {
        let (initial, trackers) = match self {
            Self::Initial(phase) => (&phase.initial_space, &phase.trackers),
            Self::Handshake(phase) => (&phase.initial_space, &phase.trackers),
            Self::Mature(phase) => (&phase.spaces.initial, &phase.trackers),
        };
        initial.retire();
        let mut trackers = trackers.write().unwrap();
        if trackers.offset() == Epoch::Initial as u64 {
            trackers.pop_front();
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
        match &*phase {
            ConnPhase::Initial(p) => p.upgrade_wakers.register(cx.waker()),
            ConnPhase::Handshake(p) => p.upgrade_wakers.register(cx.waker()),
            ConnPhase::Mature(_) => {}
        }
        phase
    }

    pub fn terminator(&self) -> ArcTerminator {
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
        let wakers = match &previous {
            ConnPhase::Initial(p) => &p.upgrade_wakers,
            ConnPhase::Handshake(p) => &p.upgrade_wakers,
            ConnPhase::Mature(_) => return,
        };
        for waker in wakers.drain() {
            waker.wake();
        }
    }
}
