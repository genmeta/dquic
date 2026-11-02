//! Connection-level handshake transitions and packet-space lifetime.
use std::sync::{Arc, Mutex};

use qbase::{Epoch, cid::ConnectionId, role::Role};
use qcongestion::HandshakeFacts;
use qtransport::{
    space::{ArcSpaces, DataSpace, Encapsulate, HandshakeSpace, Spaces},
    terminate::ArcTerminator,
};

use crate::{ArcConnPhase, ArcResend, ConnPhase, MaturePhase, Paths};

/// Serializes edge-triggered lifecycle effects for the shared handshake facts.
#[derive(Clone)]
pub(crate) struct ArcProgress(Arc<Mutex<Progress>>);

impl ArcProgress {
    pub(crate) fn new(
        role: Role,
        phase: ArcConnPhase,
        spaces: ArcSpaces,
        loss_resender: ArcResend,
        terminator: ArcTerminator,
    ) -> Self {
        Self(Arc::new(Mutex::new(Progress::new(
            role,
            phase,
            spaces,
            loss_resender,
            terminator,
        ))))
    }

    pub(crate) fn facts(&self) -> Arc<HandshakeFacts> {
        self.0.lock().unwrap().facts.clone()
    }

    pub(crate) fn install_handshake(&self, space: Arc<HandshakeSpace>) -> Option<ConnectionId> {
        self.0.lock().unwrap().install_handshake(space)
    }

    pub(crate) fn install_data(&self, space: Arc<DataSpace>) {
        self.0.lock().unwrap().install_data(space);
    }

    pub(crate) fn enter_mature(&self, phase: Arc<MaturePhase>) {
        self.0.lock().unwrap().enter_mature(phase);
    }

    pub(crate) fn on_tls_finished(&self) {
        self.0.lock().unwrap().on_tls_finished();
    }

    pub(crate) fn on_handshake_sent(&self) {
        self.0.lock().unwrap().on_handshake_sent();
    }

    pub(crate) fn on_handshake_received(&self) {
        self.0.lock().unwrap().on_handshake_received();
    }

    pub(crate) fn on_handshake_done(&self, paths: &Arc<Paths>) {
        self.0.lock().unwrap().on_handshake_done(paths);
    }

    pub(crate) fn clean(&self) {
        self.0.lock().unwrap().clean();
    }
}

/// Connection resources used by handshake transitions.
struct Progress {
    facts: Arc<HandshakeFacts>,
    role: Role,
    phase: ArcConnPhase,
    spaces: ArcSpaces,
    loss_resender: ArcResend,
    terminator: ArcTerminator,
}

impl Progress {
    fn new(
        role: Role,
        phase: ArcConnPhase,
        spaces: ArcSpaces,
        loss_resender: ArcResend,
        terminator: ArcTerminator,
    ) -> Self {
        Self {
            facts: Arc::new(HandshakeFacts::with_role(role)),
            role,
            phase,
            spaces,
            loss_resender,
            terminator,
        }
    }

    fn install_handshake(&mut self, space: Arc<HandshakeSpace>) -> Option<ConnectionId> {
        if !self.facts.install_handshake_key() {
            return None;
        }
        self.install(space);
        if let Some(initial) = self.spaces.read_guard().get(Epoch::Initial as u64) {
            initial.crypto().recver.retire();
            if self.role == Role::Client {
                initial.crypto().sender.retire();
            }
        }
        Some(self.phase.enter_handshake())
    }

    fn install_data(&mut self, space: Arc<DataSpace>) {
        self.install(space);
    }

    fn enter_mature(&mut self, phase: Arc<MaturePhase>) {
        self.phase.enter_mature(phase);
    }

    fn on_tls_finished(&mut self) {
        if self.facts.on_tls_finished() && self.role == Role::Client {
            let spaces = self.spaces.read_guard();
            if let Some(handshake) = spaces.get(Epoch::Handshake as u64) {
                handshake.crypto().recver.retire();
            }
        }
    }

    fn on_handshake_sent(&mut self) {
        if self.facts.on_handshake_sent() && self.role == Role::Client {
            self.retire_initial();
        }
    }

    fn on_handshake_received(&mut self) {
        if self.facts.on_handshake_received() && self.role == Role::Server {
            self.retire_initial();
        }
    }

    fn on_handshake_done(&mut self, paths: &Arc<Paths>) {
        let ConnPhase::Mature(_) = self.phase.get() else {
            return;
        };
        let Some(data) = Spaces::get::<DataSpace>(&self.spaces.read_guard(), Epoch::Data) else {
            // Cleanup may have removed Data before this confirmation was handled.
            return;
        };
        if !self.facts.on_handshake_done() {
            return;
        }
        data.keys.allow_update();
        {
            let mut spaces = self.spaces.write_guard();
            let mut resender = self.loss_resender.write_guard();
            while spaces
                .front()
                .is_some_and(|(epoch, _)| epoch < Epoch::Data as u64)
            {
                let (_, space) = spaces.pop_front().unwrap();
                space.retire();
                resender.pop_front();
            }
        }
        let entries = paths.entries.lock().unwrap();
        if paths.cids.is_confirmed() {
            return;
        }
        // Prepare per-path state before releasing suspended senders.
        for path in entries.values() {
            if paths.cids.is_selected(&path.cid) {
                let _ = path.validation.enter_validated();
            }
        }
        paths.cids.confirm_handshake();
        for path in entries.values() {
            paths.start_validation(path);
        }
    }

    fn clean(&mut self) {
        let mut spaces = self.spaces.write_guard();
        let mut resender = self.loss_resender.write_guard();
        while let Some((_, space)) = spaces.pop_front() {
            space.retire();
        }
        let end = resender.largest();
        resender.drain_to(end).for_each(drop);
    }

    /// Called under the lifecycle lock; queue guards never enclose a CC operation.
    fn install(&self, space: Arc<impl Encapsulate + qcongestion::Resend>) {
        {
            let mut spaces = self.spaces.write_guard();
            let mut resender = self.loss_resender.write_guard();
            spaces.push_back(space.clone()).expect("next space epoch");
            resender
                .push_back(space.clone())
                .expect("next recovery epoch");
        }
        self.terminator.register(Arc::new(space.crypto().clone()));
    }

    fn retire_initial(&self) {
        let mut spaces = self.spaces.write_guard();
        if spaces
            .front()
            .is_some_and(|(epoch, _)| epoch == Epoch::Initial as u64)
        {
            let mut resender = self.loss_resender.write_guard();
            let (_, initial) = spaces.pop_front().unwrap();
            initial.retire();
            resender.pop_front();
        }
    }
}
