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
    time::{heartbeat::ArcHeartbeat, timer::ArcIdleTimer},
};
use qcongestion::{HandshakeStatus, Transport as _};
use qtransport::path::{Path, PathState};

use crate::{ArcConnPhase, CloseReason, ConnPhase};

/// Connection-level path control. Every path has exactly one sending task.
pub struct Paths {
    phase: ArcConnPhase,
    pub(crate) handshake: Arc<HandshakeStatus>,
    pub(crate) entries: Mutex<BTreeMap<Pathway, Arc<Path>>>,
    pub(crate) responses: Mutex<HashMap<Pathway, ArcReceiving<[u8; 8]>>>,
    role: Role,
    idle: ArcIdleTimer,
    max_idle_timeout: Mutex<Duration>,
    defer_idle_timeout: Duration,
}

impl Paths {
    pub fn new(
        role: Role,
        phase: ArcConnPhase,
        max_idle_timeout: Duration,
        defer_idle_timeout: Duration,
    ) -> Arc<Self> {
        let handshake = Arc::new(HandshakeStatus::new(role == Role::Server));
        if !matches!(phase.get(), ConnPhase::Initial(_)) {
            handshake.got_handshake_key();
        }
        let idle = ArcIdleTimer::new(max_idle_timeout);
        let terminator = phase.terminator();
        let paths = Arc::new(Self {
            phase,
            handshake,
            entries: Mutex::new(BTreeMap::new()),
            responses: Mutex::new(HashMap::new()),
            role,
            idle,
            max_idle_timeout: Mutex::new(max_idle_timeout),
            defer_idle_timeout,
        });
        tokio::spawn({
            let weak = Arc::downgrade(&paths);
            let idle = paths.idle.clone();
            let terminator = terminator.clone();
            async move {
                tokio::select! {
                    result = idle.timeout() => if result.is_ok() {
                        let Some(paths) = weak.upgrade() else { return };
                        terminator.close(
                            CloseReason::Internal(QuicError::with_default_fty(
                                ErrorKind::None,
                                "connection idle timeout",
                            )),
                            paths.closing_pto(),
                        );
                        drop(paths);
                        terminator.await;
                    },
                    _ = terminator.clone() => {},
                }
            }
        });
        paths
    }

    /// Enable a path and start its only sender. After handshake confirmation, also
    /// start validation; existing paths and validation tasks are reused.
    pub fn add_path(self: &Arc<Self>, pathway: Pathway) -> Arc<Path> {
        let handshaking =
            self.role == Role::Client && matches!(self.phase.get(), ConnPhase::Initial(_));
        let path = self.create_path(pathway, handshaking);
        self.start_validation(&path);
        path
    }

    pub(crate) fn on_incoming_path(self: &Arc<Self>, pathway: Pathway) -> Arc<Path> {
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

    fn create_path(self: &Arc<Self>, pathway: Pathway, handshaking: bool) -> Arc<Path> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(path) = entries.get(&pathway) {
            return path.clone();
        }
        let resender = match self.phase.get() {
            ConnPhase::Initial(phase) => phase.resender.clone(),
            ConnPhase::Handshake(phase) => phase.resender.clone(),
            ConnPhase::Mature(phase) => phase.resender.clone(),
        };
        let path = Arc::new(Path::new(
            pathway,
            self.handshake.clone(),
            ArcHeartbeat::new(
                self.defer_idle_timeout,
                *self.max_idle_timeout.lock().unwrap(),
            ),
            resender,
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
        path
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

    pub(crate) fn idle(&self) -> ArcIdleTimer {
        self.idle.clone()
    }

    pub(crate) fn update_max_idle_timeout(&self, timeout: Duration) {
        // Parameters use MAX for disabled expiry; IdleTimer uses ZERO.
        let timeout = if timeout == Duration::MAX {
            Duration::ZERO
        } else {
            timeout
        };
        let entries = self.entries.lock().unwrap();
        *self.max_idle_timeout.lock().unwrap() = timeout;
        self.idle.update_max_idle_timeout(timeout);
        for path in entries.values() {
            path.heartbeat.adapt_max_idle_timeout(timeout);
        }
    }

    pub(crate) fn closing_pto(&self) -> Duration {
        self.snapshot()
            .iter()
            .map(|path| path.cc.pto_base(Epoch::Data))
            .max()
            .unwrap_or(Duration::from_secs(1))
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
            let trackers = match &*phase {
                ConnPhase::Initial(p) => {
                    p.initial_space.retire();
                    &p.resender
                }
                ConnPhase::Handshake(p) => {
                    p.initial_space.retire();
                    p.handshake_space.retire();
                    &p.resender
                }
                ConnPhase::Mature(p) => {
                    p.spaces.initial.retire();
                    p.spaces.handshake.retire();
                    &p.resender
                }
            };
            let mut trackers = trackers.write().unwrap();
            while trackers
                .front()
                .is_some_and(|(epoch, _)| epoch < Epoch::Data as u64)
            {
                trackers.pop_front();
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
            let terminator = paths.phase().terminator();
            let challenge = PathChallengeFrame::random();
            for _ in 0..3 {
                if !matches!(
                    path.state(),
                    PathState::AmplifyGuard { .. } | PathState::ClientValidating
                ) {
                    break;
                }
                path.set_challenge(challenge);
                match tokio::select! {
                    biased;
                    _ = terminator.clone() => break,
                    result = tokio::time::timeout(path.cc.pto_base(Epoch::Data) * 3, response.clone()) => result,
                } {
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
                        terminator.close(
                            CloseReason::Internal(QuicError::with_default_fty(
                                ErrorKind::NoViablePath,
                                "path validation timed out",
                            )),
                            paths.closing_pto(),
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

impl Drop for Paths {
    fn drop(&mut self) {
        self.idle.cancel();
    }
}
