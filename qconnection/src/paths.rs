use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, atomic::AtomicBool},
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
use qcongestion::{HandshakeFacts, Transport};
use qtransport::{
    path::Path,
    space::{ArcSpaces, InitialSpace},
    terminate::ArcTerminator,
};
use qtraversal::punch::{ArcPuncher, ProbeEncoder};

use super::progress::ArcProgress;
use crate::{ArcDcid, ArcReliableFrames, ArcResend, CidRegistry, CloseReason};

/// Shared connection resources and path control. Every path has exactly one sending task.
pub struct Paths {
    pub cid_registry: CidRegistry,
    pub puncher: ArcPuncher<ArcReliableFrames, ProbeEncoder>,
    pub spaces: ArcSpaces,
    pub reliable_frames: ArcReliableFrames,
    pub(crate) loss_resender: ArcResend,
    pub terminator: ArcTerminator,
    pub(crate) progress: ArcProgress,
    /// Shared by every CRYPTO sender; cleared by path selection or a CRYPTO ACK.
    pub(crate) is_mp_handshaking: Arc<AtomicBool>,
    pub entries: Mutex<BTreeMap<Pathway, Arc<Path>>>,
    pub validations: ArcValidations,
    role: Role,
    idle: ArcIdleTimer,
    max_idle_timeout: Mutex<Duration>,
    defer_idle_timeout: Duration,
}

impl Paths {
    pub fn new(
        initial_space: Arc<InitialSpace>,
        role: Role,
        cid_registry: CidRegistry,
        reliable_frames: ArcReliableFrames,
        max_idle_timeout: Duration,
        defer_idle_timeout: Duration,
        is_mp_handshaking: Arc<AtomicBool>,
    ) -> Arc<Self> {
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
        let puncher = ArcPuncher::new(
            reliable_frames.clone(),
            ProbeEncoder::new(spaces.clone(), cid_registry.remote.apply_dcid()),
        );
        let loss_resender = ArcResend::from(loss_resender);
        let progress = ArcProgress::new(
            role,
            spaces.clone(),
            loss_resender.clone(),
            terminator.clone(),
        );
        let paths = Arc::new(Self {
            cid_registry,
            puncher,
            spaces,
            reliable_frames,
            loss_resender,
            terminator: terminator.clone(),
            progress,
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
        self.get_or_create_path(&pathway)
    }

    /// Reuse the registered path, or create it and start its sender and validation.
    pub fn get_or_create_path(self: &Arc<Self>, pathway: &Pathway) -> Arc<Path> {
        // Take shared facts before entries to preserve the Progress -> entries lock order.
        let facts = self.progress.facts();
        self.entries
            .lock()
            .unwrap()
            .entry(*pathway)
            .or_insert_with(|| self.create_path(*pathway, facts))
            .clone()
    }

    /// Remove the registered path and stop its validation, heartbeat and sender.
    pub fn del_path(&self, pathway: &Pathway) -> bool {
        let mut entries = self.entries.lock().unwrap();
        let Some(path) = entries.remove(pathway) else {
            return false;
        };
        path.close();
        self.validations.remove(pathway);
        true
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

    fn create_path(self: &Arc<Self>, pathway: Pathway, facts: Arc<HandshakeFacts>) -> Arc<Path> {
        let confirmed = facts.is_handshake_done();
        let path = Arc::new(Path::new(
            pathway,
            facts,
            ArcHeartbeat::new(
                self.defer_idle_timeout,
                *self.max_idle_timeout.lock().unwrap(),
            ),
            self.loss_resender.clone(),
            self.cid_registry.remote.apply_dcid(),
        ));
        if self.role == Role::Client {
            let _ = path.validation.exempt();
        }
        self.validations.insert(pathway, path.validation.clone());
        if confirmed {
            self.spawn_validation(&path);
        }

        tokio::spawn(crate::send::sending(self.clone(), path.clone()));
        path.send_waker.wake_all();
        path
    }

    /// Construct a distinct CID source for a path added by a connection driver.
    pub fn new_dcid(&self) -> ArcDcid {
        let _entries = self.entries.lock().unwrap();
        self.cid_registry.remote.apply_dcid()
    }

    pub fn update_initial_dcid(&self, cid: ConnectionId) {
        if self.cid_registry.remote.on_receive_from(cid) {
            for path in self.entries.lock().unwrap().values() {
                path.send_waker.wake_all();
            }
        }
    }

    pub fn select_path(&self, path: &Arc<Path>) -> bool {
        self.progress.on_path_selected(self, path)
    }

    pub fn is_initial(&self) -> bool {
        !self.progress.facts().has_selected_path()
    }

    pub fn is_confirmed(&self) -> bool {
        self.progress.facts().is_handshake_done()
    }

    pub fn is_selected(&self, path: &Path) -> bool {
        !self.is_confirmed() && path.dcid.is_allocated()
    }

    /// A ready CID does not open additional paths before handshake confirmation.
    pub(crate) fn can_send(&self, path: &Path) -> bool {
        let facts = self.progress.facts();
        // Wait for the path bindings and validation associated with a transition.
        let _entries = self.entries.lock().unwrap();
        !facts.has_selected_path() || facts.is_handshake_done() || path.dcid.is_allocated()
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
        self.entries
            .lock()
            .unwrap()
            .values()
            .map(|path| path.cc.pto_base(Epoch::Data))
            .max()
            .unwrap_or(Duration::from_secs(1))
    }

    /// Spawn one round at path creation or handshake confirmation.
    /// After revalidation, the caller explicitly starts the next round.
    pub fn start_validation(self: &Arc<Self>, path: &Arc<Path>) {
        if !self.is_confirmed() {
            return;
        }
        self.spawn_validation(path);
    }

    pub(crate) fn spawn_validation(self: &Arc<Self>, path: &Arc<Path>) {
        if path.validation.is_validated() || path.validation.is_cancelled() {
            return;
        }
        let response = path.validation.respond();
        let paths = self.clone();
        let path = path.clone();
        tokio::spawn(async move {
            let terminator = paths.terminator.clone();
            let challenge = PathChallengeFrame::random();
            for _ in 0..=3 {
                if path.validation.is_validated() || path.validation.challenge(challenge).is_err() {
                    break;
                }
                match tokio::select! {
                    biased;
                    _ = terminator.clone() => break,
                    result = tokio::time::timeout(path.cc.pto_base(Epoch::Data) * 3, response.clone()) => result,
                } {
                    Ok(Ok(Some(frame))) if frame == PathResponseFrame::from(challenge) => {
                        if path.validation.enter_validated().is_ok() {
                            path.send_waker.wake_all();
                        }
                        break;
                    }
                    Ok(_) => break,
                    Err(_) => continue,
                }
            }
            // Check and remove under one lock: an old task must not remove a replacement.
            let no_paths = {
                let mut entries = paths.entries.lock().unwrap();
                if !path.validation.is_validated()
                    && entries
                        .get(&path.pathway)
                        .is_some_and(|current| Arc::ptr_eq(current, &path))
                {
                    path.close();
                    entries.remove(&path.pathway);
                    paths.validations.remove(&path.pathway);
                    entries.is_empty()
                } else {
                    false
                }
            };
            if no_paths {
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

    /// Stop idle expiry and release paths, packet spaces and recovery trackers.
    pub fn clean(&self) {
        self.idle.cancel();
        self.puncher.abort_transactions();
        self.puncher.release_temporary_sockets();
        {
            let entries = self.entries.lock().unwrap();
            for path in entries.values() {
                for epoch in [Epoch::Initial, Epoch::Handshake] {
                    path.cc.discard_epoch(epoch);
                }
            }
        }
        self.progress.clean();
        let mut entries = self.entries.lock().unwrap();
        for (pathway, path) in std::mem::take(&mut *entries) {
            path.close();
            self.validations.remove(&pathway);
        }
    }
}

impl Drop for Paths {
    fn drop(&mut self) {
        self.idle.cancel();
    }
}
