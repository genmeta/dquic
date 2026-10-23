use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    frame::{PathChallengeFrame, PathResponseFrame},
    net::route::Pathway,
    role::Role,
    time::{heartbeat::ArcHeartbeat, timer::ArcIdleTimer},
    util::IndexDeque,
    validate::ArcValidations,
};
use qcongestion::{HandshakeStatus, Transport as _};
use qtransport::{
    path::{Path, PathCids},
    space::{ArcSpaces, InitialSpace},
    terminate::ArcTerminator,
};

use crate::{
    ArcConnPhase, ArcLocalCids, ArcReliableFrames, ArcResend, CloseReason, ConnPhase, InitialPhase,
};

/// Shared connection resources and path control. Every path has exactly one sending task.
pub struct Paths {
    phase: ArcConnPhase,
    pub cids: Arc<PathCids>,
    pub spaces: ArcSpaces,
    pub reliable_frames: ArcReliableFrames,
    pub(crate) loss_resender: ArcResend,
    pub terminator: ArcTerminator,
    pub(crate) handshake: Arc<HandshakeStatus>,
    /// Shared by every CRYPTO sender; cleared by path selection or a CRYPTO ACK.
    pub(crate) is_mp_handshaking: Arc<AtomicBool>,
    pub(crate) entries: Mutex<BTreeMap<Pathway, Arc<Path>>>,
    pub validations: ArcValidations,
    role: Role,
    idle: ArcIdleTimer,
    max_idle_timeout: Mutex<Duration>,
    defer_idle_timeout: Duration,
}

impl Paths {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        initial_space: Arc<InitialSpace>,
        role: Role,
        dcid: ConnectionId,
        reliable_frames: ArcReliableFrames,
        local_cids: ArcLocalCids,
        max_idle_timeout: Duration,
        defer_idle_timeout: Duration,
        is_mp_handshaking: Arc<AtomicBool>,
    ) -> Arc<Self> {
        let handshake = Arc::new(HandshakeStatus::new(role == Role::Server));
        let idle = ArcIdleTimer::new(max_idle_timeout);
        let mut loss_resender = IndexDeque::<Arc<dyn qcongestion::Resend>, 2>::with_capacity(3);
        loss_resender
            .push_back(initial_space.clone())
            .expect("Initial epoch");
        let terminator = ArcTerminator::no_error();
        terminator.register(Arc::new(initial_space.crypto.clone()));
        let spaces = ArcSpaces::from(IndexDeque::with_capacity(3));
        spaces
            .write_guard()
            .push_back(initial_space)
            .expect("Initial epoch");
        let phase = ArcConnPhase::initial(InitialPhase::new(dcid, local_cids));
        let paths = Arc::new(Self {
            phase,
            cids: PathCids::new(dcid),
            spaces,
            reliable_frames,
            loss_resender: ArcResend::from(loss_resender),
            terminator: terminator.clone(),
            handshake,
            is_mp_handshaking,
            entries: Mutex::new(BTreeMap::new()),
            validations: ArcValidations::default(),
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
        self.create_path(pathway)
    }

    pub(crate) fn on_incoming_path(self: &Arc<Self>, pathway: Pathway) -> Arc<Path> {
        self.create_path(pathway)
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

    fn create_path(self: &Arc<Self>, pathway: Pathway) -> Arc<Path> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(path) = entries.get(&pathway) {
            return path.clone();
        }
        let path = Arc::new(Path::new(
            pathway,
            self.handshake.clone(),
            ArcHeartbeat::new(
                self.defer_idle_timeout,
                *self.max_idle_timeout.lock().unwrap(),
            ),
            self.loss_resender.clone(),
            &self.cids,
        ));
        if self.role == Role::Client {
            path.exempt();
        }
        self.validations.insert(pathway, path.validation.clone());
        entries.insert(pathway, path.clone());
        self.start_validation(&path);
        drop(entries);

        tokio::spawn(crate::send::sending(self.clone(), path.clone()));
        path.send_waker.wake_all();
        path
    }

    pub(crate) fn select_path(&self, path: &Arc<Path>) {
        let entries = self.entries.lock().unwrap();
        if !entries
            .get(&path.pathway)
            .is_some_and(|current| Arc::ptr_eq(current, path))
            || !self.cids.select(&path.cid)
        {
            return;
        }
        self.is_mp_handshaking.store(false, Ordering::Relaxed);
    }

    pub fn phase(&self) -> ArcConnPhase {
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
        self.handshake.on_handshake_sent();
        if self.role == Role::Client {
            let spaces = self.spaces.read_guard();
            if let Some(initial) = spaces.get(Epoch::Initial as u64) {
                initial.retire();
            }
        }
    }

    pub(crate) fn on_handshake_received(&self) {
        self.handshake.on_handshake_received();
        if self.role == Role::Server {
            let spaces = self.spaces.read_guard();
            if let Some(initial) = spaces.get(Epoch::Initial as u64) {
                initial.retire();
            }
        }
    }

    pub(crate) fn handshake_confirmed(self: &Arc<Self>) {
        self.handshake.handshake_confirmed();
        let ConnPhase::Mature(_) = self.phase.get() else {
            return;
        };
        let entries = self.entries.lock().unwrap();
        if self.cids.is_confirmed() {
            return;
        }
        // Prepare per-path state before releasing suspended senders.
        for path in entries.values() {
            if self.cids.is_selected(&path.cid) {
                path.validate();
            }
        }
        self.cids.confirm_handshake();
        for path in entries.values() {
            self.start_validation(path);
        }
    }

    /// Spawn one round at path creation or handshake confirmation.
    /// After revalidation, the caller explicitly starts the next round.
    pub(crate) fn start_validation(self: &Arc<Self>, path: &Arc<Path>) {
        if !self.cids.is_confirmed() || path.is_validated() || path.is_retired() {
            return;
        }
        let response = path.validation.respond();
        let paths = self.clone();
        let path = path.clone();
        tokio::spawn(async move {
            let terminator = paths.terminator.clone();
            let challenge = PathChallengeFrame::random();
            for _ in 0..=3 {
                if path.is_validated() || path.validation.challenge(challenge).is_err() {
                    break;
                }
                match tokio::select! {
                    biased;
                    _ = terminator.clone() => break,
                    result = tokio::time::timeout(path.cc.pto_base(Epoch::Data) * 3, response.clone()) => result,
                } {
                    Ok(Ok(Some(frame))) if frame == PathResponseFrame::from(challenge) => {
                        path.validate();
                        break;
                    }
                    Ok(_) => break,
                    Err(_) => continue,
                }
            }
            // A replacement at the same Pathway has its own receiver and task.
            if !path.is_validated() && paths.remove(&path) && paths.snapshot().is_empty() {
                terminator.close(
                    CloseReason::Internal(QuicError::with_default_fty(
                        ErrorKind::NoViablePath,
                        "path validation failed",
                    )),
                    paths.closing_pto(),
                );
            }
        });
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
            self.validations.remove(&path.pathway);
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
