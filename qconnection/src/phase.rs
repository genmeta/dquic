//! Shared sending material. Each path reads the current phase for every burst.
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use qbase::{cid::ConnectionId, net::tx::ArcSendWakers, util::IndexDeque};
use qtransport::{
    keys::ArcKeys,
    space::{ArcSpaces, InitialSpace, Spaces},
    terminate::ArcTerminator,
};
use qtraversal::punch::{ArcPuncher, ProbeEncoder};

use crate::{ArcParameters, ArcReliableFrames, ArcResend, CidRegistry, FlowController};

/// Frame sources available before peer transport parameters arrive.
pub struct InitialPhase {
    pub spaces: ArcSpaces,
    pub scid: ConnectionId,
    dcid: Mutex<ConnectionId>,
    pub odcid: ConnectionId,
    pub reliable_frames: ArcReliableFrames,
    pub cid_registry: CidRegistry,
    pub(crate) resender: ArcResend,
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
        let initial_space = Arc::new(InitialSpace::new(scid, ArcKeys::new(Arc::new(keys)), None));
        let mut resender = IndexDeque::<Arc<dyn qcongestion::Resend>, 2>::with_capacity(3);
        resender
            .push_back(initial_space.clone())
            .expect("Initial epoch");
        let terminator = ArcTerminator::no_error();
        terminator.register(Arc::new(initial_space.crypto.clone()));
        let mut spaces = Spaces(IndexDeque::with_capacity(3));
        spaces.0.push_back(initial_space).expect("Initial epoch");
        Self {
            spaces: Arc::new(RwLock::new(spaces)),
            scid,
            dcid: Mutex::new(dcid),
            odcid,
            reliable_frames,
            cid_registry,
            resender: Arc::new(RwLock::new(resender)),
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
    pub spaces: ArcSpaces,
    pub scid: ConnectionId,
    pub dcid: ConnectionId,
    pub reliable_frames: ArcReliableFrames,
    pub cid_registry: CidRegistry,
    pub(crate) resender: ArcResend,
    pub(crate) terminator: ArcTerminator,
    pub(crate) upgrade_wakers: ArcSendWakers,
}

/// Complete frame sources. Identity verification remains the growing coroutine's job.
pub struct MaturePhase {
    pub spaces: ArcSpaces,
    pub scid: ConnectionId,
    pub dcid: ConnectionId,
    pub parameters: ArcParameters,
    pub flow_ctrl: FlowController,
    pub cid_registry: CidRegistry,
    pub puncher: ArcPuncher<ArcReliableFrames, ProbeEncoder>,
    pub(crate) resender: ArcResend,
    pub(crate) terminator: ArcTerminator,
}

#[derive(Clone)]
pub enum ConnPhase {
    Initial(Arc<InitialPhase>),
    Handshake(Arc<HandshakePhase>),
    Mature(Arc<MaturePhase>),
}

impl ConnPhase {
    pub fn spaces(&self) -> &ArcSpaces {
        match self {
            Self::Initial(p) => &p.spaces,
            Self::Handshake(p) => &p.spaces,
            Self::Mature(p) => &p.spaces,
        }
    }

    pub(crate) fn resender(&self) -> &ArcResend {
        match self {
            Self::Initial(p) => &p.resender,
            Self::Handshake(p) => &p.resender,
            Self::Mature(p) => &p.resender,
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

    pub(crate) fn enter_handshake(&self) {
        let mut phase = self.lock_guard();
        let ConnPhase::Initial(initial) = &*phase else {
            unreachable!("enter_handshake starts with InitialPhase")
        };
        let upgrade_wakers = initial.upgrade_wakers.clone();
        *phase = ConnPhase::Handshake(Arc::new(HandshakePhase {
            spaces: initial.spaces.clone(),
            scid: initial.scid,
            dcid: initial.dcid(),
            reliable_frames: initial.reliable_frames.clone(),
            cid_registry: initial.cid_registry.clone(),
            resender: initial.resender.clone(),
            terminator: initial.terminator.clone(),
            upgrade_wakers: upgrade_wakers.clone(),
        }));
        drop(phase);
        upgrade_wakers.wake_all();
    }

    pub(crate) fn enter_mature(&self, phase: Arc<MaturePhase>) {
        let mut current = self.lock_guard();
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
