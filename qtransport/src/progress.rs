//! Connection-level handshake transitions and packet-space lifetime.
use std::sync::{Arc, Mutex};

use qbase::{Epoch, cid::ConnectionId, handshake::HandshakeFacts, role::Role};

use crate::{
    ArcRemoteCids, ArcResend, Paths,
    path::Path,
    space::{ArcSpaces, DataSpace, Encapsulate, HandshakeSpace},
    terminate::ArcTerminator,
};

/// Serializes edge-triggered lifecycle effects for the shared handshake facts.
#[derive(Clone)]
pub struct ArcProgress(Arc<Mutex<Progress>>);

impl ArcProgress {
    pub fn new(
        facts: Arc<HandshakeFacts>,
        remote_cids: ArcRemoteCids,
        spaces: ArcSpaces,
        resenders: ArcResend,
        terminator: ArcTerminator,
    ) -> Self {
        Self(Arc::new(Mutex::new(Progress::new(facts, remote_cids, spaces, resenders, terminator))))
    }

    pub fn facts(&self) -> Arc<HandshakeFacts> {
        self.0.lock().unwrap().facts.clone()
    }

    /// Record the first authenticated Initial and publish its peer SCID before TLS delivery.
    pub fn on_initial_received(&self, peer_scid: ConnectionId) -> bool {
        self.0.lock().unwrap().on_initial_received(peer_scid)
    }

    pub fn install_handshake(&self, space: Arc<HandshakeSpace>) -> bool {
        self.0.lock().unwrap().install_handshake(space)
    }

    pub fn install_data(&self, space: Arc<DataSpace>) {
        self.0.lock().unwrap().install(space);
    }

    pub fn on_tls_finished(&self) {
        self.0.lock().unwrap().on_tls_finished();
    }

    pub fn on_handshake_sent(&self) {
        self.0.lock().unwrap().on_handshake_sent();
    }

    pub fn on_handshake_received(&self) {
        self.0.lock().unwrap().on_handshake_received();
    }

    /// Select the handshake path and suspend payload on the other paths.
    pub fn on_path_selected(&self, paths: &Paths, path: &Arc<Path>) -> bool {
        self.0.lock().unwrap().on_path_selected(paths, path)
    }

    /// Confirm the handshake and enable and validate the registered paths.
    pub fn on_handshake_done(&self, paths: &Arc<Paths>) {
        self.0.lock().unwrap().on_handshake_done(paths);
    }

    pub fn clean(&self) {
        self.0.lock().unwrap().clean();
    }
}

/// Connection resources used by handshake transitions.
struct Progress {
    facts: Arc<HandshakeFacts>,
    role: Role,
    remote_cids: ArcRemoteCids,
    spaces: ArcSpaces,
    loss_resender: ArcResend,
    terminator: ArcTerminator,
}

impl Progress {
    fn new(
        facts: Arc<HandshakeFacts>,
        remote_cids: ArcRemoteCids,
        spaces: ArcSpaces,
        resenders: ArcResend,
        terminator: ArcTerminator,
    ) -> Self {
        Self { role: facts.role(), facts, remote_cids, spaces, loss_resender: resenders, terminator }
    }

    fn on_initial_received(&mut self, peer_scid: ConnectionId) -> bool {
        if !self.facts.on_initial_received() {
            return false;
        }
        // Assigning sequence zero wakes only the path waiting for that CID cell.
        self.remote_cids.on_receive_from(peer_scid);
        true
    }

    fn install_handshake(&mut self, space: Arc<HandshakeSpace>) -> bool {
        if !self.facts.install_handshake_key() {
            return false;
        }
        self.install(space);
        if let Some(initial) = self.spaces.get(Epoch::Initial) {
            initial.crypto().recver.retire();
            if self.role == Role::Client {
                initial.crypto().sender.retire();
            }
        }
        true
    }

    fn on_tls_finished(&mut self) {
        if self.facts.on_tls_finished()
            && self.role == Role::Client
            && let Some(handshake) = self.spaces.get(Epoch::Handshake)
        {
            handshake.crypto().recver.retire();
        }
    }

    fn on_handshake_sent(&mut self) {
        if self.facts.on_handshake_sent() && self.role == Role::Client {
            self.retire(Epoch::Initial);
        }
    }

    fn on_handshake_received(&mut self) {
        if self.facts.on_handshake_received() && self.role == Role::Server {
            self.retire(Epoch::Initial);
        }
    }

    fn on_path_selected(&mut self, paths: &Paths, path: &Arc<Path>) -> bool {
        let entries = paths.entries.lock().unwrap();
        if !entries.get(&path.pathway).is_some_and(|current| Arc::ptr_eq(current, path))
            || path.validation.is_cancelled()
            || self.facts.is_handshake_done()
            || !self.facts.on_path_selected()
        {
            return false;
        }
        path.dcid.upgrade();
        self.facts.quit_mp_replaying();
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
        let entries = paths.entries.lock().unwrap();
        let Some(data) = self.spaces.get_as::<DataSpace>(Epoch::Data) else {
            // Cleanup may have removed Data before this confirmation was handled.
            return;
        };
        if !self.facts.on_handshake_done() {
            return;
        }
        data.keys.allow_update();
        self.retire(Epoch::Handshake);
        self.remote_cids.upgrade();
        for path in entries.values() {
            if path.dcid.is_allocated() {
                let _ = path.validation.grant();
            } else {
                path.dcid.upgrade();
                paths.spawn_validation(path);
            }
            path.enable();
        }
    }

    fn clean(&mut self) {
        self.retire(Epoch::Data);
    }

    /// Called under the lifecycle lock; collection locks never enclose a CC operation.
    fn install(&self, space: Arc<impl Encapsulate + qcongestion::Resend>) {
        self.spaces.add(space.clone());
        self.loss_resender.write_guard().push_back(space.clone()).expect("next recovery epoch");
        self.terminator.register(Arc::new(space.crypto().clone()));
    }

    fn retire(&self, epoch: Epoch) {
        self.spaces.retire(epoch);
        let mut resender = self.loss_resender.write_guard();
        let end = (epoch as u64 + 1).clamp(resender.offset(), resender.largest());
        resender.drain_to(end).for_each(drop);
    }
}
