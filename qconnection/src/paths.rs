use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
    time::Duration,
};

use qbase::{
    ArcReceiving, Epoch,
    error::{ErrorKind, QuicError},
    frame::{PathChallengeFrame, PathResponseFrame},
    net::route::Pathway,
    role::Role,
    time::ArcConnIdle,
};
use qcongestion::{HandshakeStatus, Transport as _};
use qtransport::{
    CloseReason,
    path::{Path, PathState},
};

use crate::{ArcConnPhase, ConnPhase, Error};

/// Connection-level path control. Every path has exactly one sending task.
pub struct Paths {
    phase: ArcConnPhase,
    pub(crate) handshake: Arc<HandshakeStatus>,
    pub(crate) entries: Mutex<BTreeMap<Pathway, Arc<Path>>>,
    pub(crate) responses: Mutex<HashMap<Pathway, ArcReceiving<[u8; 8]>>>,
    role: Role,
    idle: ArcConnIdle,
    close_reason: ArcReceiving<CloseReason>,
}

impl Paths {
    pub fn new(role: Role, phase: ArcConnPhase, idle: ArcConnIdle) -> Arc<Self> {
        let handshake = Arc::new(HandshakeStatus::new(role == Role::Server));
        if !matches!(phase.get(), ConnPhase::Initial(_)) {
            handshake.got_handshake_key();
        }
        Arc::new(Self {
            phase,
            handshake,
            entries: Mutex::new(BTreeMap::new()),
            responses: Mutex::new(HashMap::new()),
            role,
            idle,
            close_reason: ArcReceiving::default(),
        })
    }

    /// Enable a path and start its only sender. After handshake confirmation, also
    /// start validation; existing paths and validation tasks are reused.
    pub fn add_path(self: &Arc<Self>, pathway: Pathway) -> Result<Arc<Path>, Error> {
        let handshaking =
            self.role == Role::Client && matches!(self.phase.get(), ConnPhase::Initial(_));
        let path = self.create_path(pathway, handshaking)?;
        self.start_validation(&path);
        Ok(path)
    }

    pub(crate) fn on_incoming_path(self: &Arc<Self>, pathway: Pathway) -> Result<Arc<Path>, Error> {
        self.create_path(pathway, false)
    }

    /// Opening-key retention needs a PTO before an unknown path is admitted.
    /// Use existing path measurements without allocating a path or sender.
    pub(crate) fn pto_for(&self, pathway: &Pathway, epoch: Epoch) -> Duration {
        let entries = self.entries.lock().unwrap();
        if let Some(path) = entries.get(pathway) {
            return path.cc.get_pto(epoch);
        }
        entries
            .values()
            .map(|path| path.cc.get_pto(epoch))
            .max()
            .unwrap_or(Duration::from_secs(1))
    }

    fn create_path(
        self: &Arc<Self>,
        pathway: Pathway,
        handshaking: bool,
    ) -> Result<Arc<Path>, Error> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(path) = entries.get(&pathway) {
            return Ok(path.clone());
        }
        let path = Arc::new(Path::new(
            pathway,
            self.handshake.clone(),
            self.idle.timer(),
            self.phase.get().trackers(),
        ));
        if entries
            .values()
            .any(|path| path.selected() == Path::HANDSHAKED)
        {
            path.handshake_confirmed();
            if self.role == Role::Client {
                path.client_validating();
            }
        } else if entries
            .values()
            .any(|path| path.selected() != Path::MP_INITIAL)
        {
            path.decide(false);
        } else if handshaking {
            path.client_handshaking();
        }
        entries.insert(pathway, path.clone());
        drop(entries);

        tokio::spawn(crate::send::sending(self.clone(), path.clone()));
        path.send_waker.wake_all();
        Ok(path)
    }

    pub(crate) fn select_path(&self, path: &Arc<Path>) {
        let entries = self.entries.lock().unwrap();
        if path.selected() != Path::MP_INITIAL
            || !entries
                .get(&path.pathway)
                .is_some_and(|current| Arc::ptr_eq(current, path))
        {
            return;
        }
        for other in entries.values() {
            other.decide(other.pathway == path.pathway);
            if other.selected() == 0 {
                other.guard_amplification();
            }
        }
    }

    pub(crate) fn phase(&self) -> ArcConnPhase {
        self.phase.clone()
    }

    pub(crate) fn role(&self) -> Role {
        self.role
    }

    pub(crate) fn idle(&self) -> ArcConnIdle {
        self.idle.clone()
    }

    pub(crate) fn close_reason(&self) -> ArcReceiving<CloseReason> {
        self.close_reason.clone()
    }

    pub(crate) fn on_error(&self, error: Error) {
        self.close_reason.set(error.into());
    }

    pub(crate) fn on_handshake_sent(&self) {
        let phase = self.phase.lock_guard();
        if self.role == Role::Client {
            phase.retire_initial();
        }
        self.handshake.on_handshake_sent();
    }

    pub(crate) fn on_handshake_received(&self) {
        let phase = self.phase.lock_guard();
        if self.role == Role::Server {
            phase.retire_initial();
        }
        self.handshake.on_handshake_received();
    }

    pub(crate) fn handshake_confirmed(self: &Arc<Self>) {
        {
            let phase = self.phase.lock_guard();
            match &*phase {
                ConnPhase::Initial(p) => p.initial_space.retire(),
                ConnPhase::Handshake(p) => {
                    p.initial_space.retire();
                    p.handshake_space.retire();
                }
                ConnPhase::Mature(p) => p.retire_handshake_spaces(),
            }
            self.handshake.handshake_confirmed();
        }
        // The selected sender releases paths after it has requested its CID cell.
        for path in self.entries.lock().unwrap().values() {
            if path.selected() == Path::SELECTED {
                path.send_waker.wake_all();
            }
        }
    }

    /// Called by the selected sender only after it has requested its CID cell.
    pub(crate) fn activate_paths(self: &Arc<Self>, selected: &Path) {
        let entries = self.entries.lock().unwrap();
        if selected.selected() != Path::SELECTED || !self.handshake.is_handshake_confirmed() {
            return;
        }
        for path in entries.values() {
            if path.selected() == Path::SELECTED {
                path.validate();
            } else if self.role == Role::Client {
                path.client_validating();
            }
            path.handshake_confirmed();
            self.start_validation(path);
        }
    }

    pub(crate) fn start_validation(self: &Arc<Self>, path: &Arc<Path>) {
        if path.selected() != 2 {
            return;
        }
        if !matches!(
            path.state(),
            PathState::AmplifyGuard { .. } | PathState::ClientValidating
        ) {
            return;
        }
        let mut responses = self.responses.lock().unwrap();
        if responses.contains_key(&path.pathway) {
            return;
        }
        let response = ArcReceiving::default();
        responses.insert(path.pathway, response.clone());
        drop(responses);
        let paths = self.clone();
        let path = path.clone();
        tokio::spawn(async move {
            let challenge = PathChallengeFrame::random();
            for _ in 0..3 {
                if !matches!(
                    path.state(),
                    PathState::AmplifyGuard { .. } | PathState::ClientValidating
                ) {
                    break;
                }
                path.set_challenge(challenge);
                match tokio::time::timeout(path.cc.pto_base(Epoch::Data) * 3, response.clone())
                    .await
                {
                    Ok(Ok(Some(data))) if data == *challenge => {
                        path.validate();
                        break;
                    }
                    Ok(_) => break,
                    Err(_) => continue,
                }
            }
            // A replacement at the same Pathway has its own receiver and task.
            if paths
                .get(&path.pathway)
                .is_some_and(|current| Arc::ptr_eq(&current, &path))
            {
                paths.responses.lock().unwrap().remove(&path.pathway);
                path.clear_challenge();
                if matches!(
                    path.state(),
                    PathState::AmplifyGuard { .. } | PathState::ClientValidating
                ) {
                    paths.remove(&path);
                    if paths.snapshot().is_empty() {
                        paths.on_error(
                            QuicError::with_default_fty(
                                ErrorKind::NoViablePath,
                                "path validation timed out",
                            )
                            .into(),
                        );
                    }
                }
            }
        });
    }

    pub(crate) fn on_path_response(&self, path: &Path, frame: PathResponseFrame) {
        if path.matches_response(frame)
            && let Some(response) = self.responses.lock().unwrap().get(&path.pathway)
        {
            response.with(*frame);
        }
    }

    pub fn get(&self, pathway: &Pathway) -> Option<Arc<Path>> {
        self.entries.lock().unwrap().get(pathway).cloned()
    }

    pub fn snapshot(&self) -> Vec<Arc<Path>> {
        self.entries.lock().unwrap().values().cloned().collect()
    }

    /// Remove this exact retired instance, never a replacement at the same address.
    pub fn remove(&self, path: &Arc<Path>) -> bool {
        path.retire();
        let mut entries = self.entries.lock().unwrap();
        if entries
            .get(&path.pathway)
            .is_some_and(|current| Arc::ptr_eq(current, path))
        {
            entries.remove(&path.pathway);
            if let Some(response) = self.responses.lock().unwrap().remove(&path.pathway) {
                response.cancel();
            }
            true
        } else {
            false
        }
    }
}
