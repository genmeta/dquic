//! Stage-specific connection state. Each path reads the current phase for every burst.
use std::sync::{Arc, RwLock, RwLockReadGuard};

use qbase::net::tx::ArcSendWakers;
use qtraversal::punch::{ArcPuncher, ProbeEncoder};

use crate::{ArcParameters, ArcReliableFrames, FlowController};

/// Initial connection state, before Handshake keys are installed.
#[derive(Default)]
pub struct InitialPhase {
    pub(crate) upgrade_wakers: ArcSendWakers,
}

/// Peer CID established, waiting for parameters and Data keys.
pub struct HandshakePhase {
    pub(crate) upgrade_wakers: ArcSendWakers,
}

/// Negotiated connection state. Identity verification remains the growing coroutine's job.
pub struct MaturePhase {
    pub parameters: ArcParameters,
    pub flow_ctrl: FlowController,
    pub puncher: ArcPuncher<ArcReliableFrames, ProbeEncoder>,
}

#[derive(Clone)]
pub enum ConnPhase {
    Initial(Arc<InitialPhase>),
    Handshake(Arc<HandshakePhase>),
    Mature(Arc<MaturePhase>),
}

#[derive(Clone)]
pub struct ArcConnPhase(Arc<RwLock<ConnPhase>>);

impl ArcConnPhase {
    pub fn initial(sender: InitialPhase) -> Self {
        Self(Arc::new(RwLock::new(ConnPhase::Initial(Arc::new(sender)))))
    }

    pub fn get(&self) -> ConnPhase {
        self.0.read().unwrap().clone()
    }

    pub(crate) fn poll_phase(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> RwLockReadGuard<'_, ConnPhase> {
        let phase = self.0.read().unwrap();
        match &*phase {
            ConnPhase::Initial(p) => p.upgrade_wakers.register(cx.waker()),
            ConnPhase::Handshake(p) => p.upgrade_wakers.register(cx.waker()),
            ConnPhase::Mature(_) => {}
        }
        phase
    }

    /// Enter Handshake and wake phase subscribers.
    pub(crate) fn enter_handshake(&self) {
        let mut phase = self.0.write().unwrap();
        let ConnPhase::Initial(initial) = &*phase else {
            unreachable!("enter_handshake starts with InitialPhase")
        };
        let upgrade_wakers = initial.upgrade_wakers.clone();
        *phase = ConnPhase::Handshake(Arc::new(HandshakePhase {
            upgrade_wakers: upgrade_wakers.clone(),
        }));
        drop(phase);
        upgrade_wakers.wake_all();
    }

    pub(crate) fn enter_mature(&self, phase: Arc<MaturePhase>) {
        let mut current = self.0.write().unwrap();
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
