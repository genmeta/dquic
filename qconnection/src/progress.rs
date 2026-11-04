//! Connection-level handshake transitions and packet-space lifetime.
use std::sync::{Arc, Mutex, atomic::Ordering};

use qbase::{Epoch, cid::ConnectionId, role::Role};
use qcongestion::HandshakeFacts;
use qtransport::{
    path::Path,
    space::{ArcSpaces, DataSpace, Encapsulate, HandshakeSpace, Spaces},
    terminate::ArcTerminator,
};

use crate::{ArcResend, CidRegistry, Paths};

/// Serializes edge-triggered lifecycle effects for the shared handshake facts.
#[derive(Clone)]
pub struct ArcProgress(Arc<Mutex<Progress>>);

impl ArcProgress {
    pub(crate) fn new(
        role: Role,
        cid_registry: CidRegistry,
        spaces: ArcSpaces,
        loss_resender: ArcResend,
        terminator: ArcTerminator,
    ) -> Self {
        Self(Arc::new(Mutex::new(Progress::new(
            role,
            cid_registry,
            spaces,
            loss_resender,
            terminator,
        ))))
    }

    pub fn facts(&self) -> Arc<HandshakeFacts> {
        self.0.lock().unwrap().facts.clone()
    }

    /// Record the first authenticated Initial and publish its peer SCID before TLS delivery.
    pub fn on_initial_received(&self, peer_scid: ConnectionId) -> bool {
        self.0.lock().unwrap().on_initial_received(peer_scid)
    }

    pub(crate) fn install_handshake(&self, space: Arc<HandshakeSpace>) -> bool {
        self.0.lock().unwrap().install_handshake(space)
    }

    pub(crate) fn install_data(&self, space: Arc<DataSpace>) {
        self.0.lock().unwrap().install(space);
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

    pub fn on_path_selected(&self, paths: &Paths, path: &Arc<Path>) -> bool {
        self.0.lock().unwrap().on_path_selected(paths, path)
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
    cid_registry: CidRegistry,
    spaces: ArcSpaces,
    loss_resender: ArcResend,
    terminator: ArcTerminator,
}

impl Progress {
    fn new(
        role: Role,
        cid_registry: CidRegistry,
        spaces: ArcSpaces,
        loss_resender: ArcResend,
        terminator: ArcTerminator,
    ) -> Self {
        Self {
            facts: Arc::new(HandshakeFacts::with_role(role)),
            role,
            cid_registry,
            spaces,
            loss_resender,
            terminator,
        }
    }

    fn on_initial_received(&mut self, peer_scid: ConnectionId) -> bool {
        if !self.facts.on_initial_received() {
            return false;
        }
        // Assigning sequence zero wakes only the path waiting for that CID cell.
        self.cid_registry.remote.on_receive_from(peer_scid);
        true
    }

    fn install_handshake(&mut self, space: Arc<HandshakeSpace>) -> bool {
        if !self.facts.install_handshake_key() {
            return false;
        }
        self.install(space);
        if let Some(initial) = self.spaces.read_guard().get(Epoch::Initial as u64) {
            initial.crypto().recver.retire();
            if self.role == Role::Client {
                initial.crypto().sender.retire();
            }
        }
        true
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

    fn on_path_selected(&mut self, paths: &Paths, path: &Arc<Path>) -> bool {
        let entries = paths.entries.lock().unwrap();
        if !entries
            .get(&path.pathway)
            .is_some_and(|current| Arc::ptr_eq(current, path))
            || path.validation.is_cancelled()
            || self.facts.is_handshake_done()
            || !self.facts.on_path_selected()
        {
            return false;
        }
        path.dcid.upgrade();
        paths.is_mp_handshaking.store(false, Ordering::Relaxed);
        for other in entries.values() {
            if !Arc::ptr_eq(other, path) {
                other.disable();
            }
        }
        path.enable();
        path.send_waker.wake_all();
        true
    }

    fn on_handshake_done(&mut self, paths: &Arc<Paths>) {
        let Some(data) = Spaces::get::<DataSpace>(&self.spaces.read_guard(), Epoch::Data) else {
            // Cleanup may have removed Data before this confirmation was handled.
            return;
        };
        let entries = paths.entries.lock().unwrap();
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
        self.cid_registry.remote.upgrade();
        for path in entries.values() {
            if path.dcid.is_allocated() {
                let _ = path.validation.enter_validated();
            } else {
                path.dcid.upgrade();
                paths.spawn_validation(path);
            }
            path.enable();
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
