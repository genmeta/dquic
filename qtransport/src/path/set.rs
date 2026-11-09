use std::{
    collections::BTreeMap,
    future::poll_fn,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};

use qbase::{
    Epoch,
    error::{ErrorKind, QuicError},
    frame::{PathChallengeFrame, PathResponseFrame},
    handshake::HandshakeFacts,
    net::{route::Pathway, tx::UnregisterWaker, validate::ArcValidations},
    role::Role,
    time::{heartbeat::ArcHeartbeat, timer::ArcIdleTimer},
    util::IndexDeque,
};
use qcongestion::Transport;

use super::{Datagram, Path};
use crate::{
    ArcProgress, ArcPuncher, ArcReliableFrames, ArcResend, CidRegistry, CloseReason,
    punch::ProbeEncoder,
    space::{ArcSpaces, InitialSpace},
    terminate::ArcTerminator,
};

/// Manages the path collection and holds shared resources for path sending tasks.
/// Every path has exactly one sending task.
pub struct Paths {
    pub cid_registry: CidRegistry,
    pub puncher: ArcPuncher,
    pub spaces: ArcSpaces,
    pub reliable_frames: ArcReliableFrames,
    pub(crate) resenders: ArcResend,
    pub terminator: ArcTerminator,
    pub progress: ArcProgress,
    pub entries: Mutex<BTreeMap<Pathway, Arc<Path>>>,
    pub validations: ArcValidations,
    role: Role,
    idle_timer: ArcIdleTimer,
    max_idle_timeout: Mutex<Duration>,
    defer_idle_timeout: Duration,
    failed_opened: AtomicU64,
}

impl Paths {
    pub fn new(
        initial_space: Arc<InitialSpace>,
        facts: Arc<HandshakeFacts>,
        cid_registry: CidRegistry,
        reliable_frames: ArcReliableFrames,
        max_idle_timeout: Duration,
        defer_idle_timeout: Duration,
    ) -> Arc<Self> {
        let role = facts.role();
        let idle = ArcIdleTimer::new(max_idle_timeout);
        let mut loss_resender = IndexDeque::<Arc<dyn qcongestion::Resend>, 2>::with_capacity(3);
        loss_resender.push_back(initial_space.clone()).expect("Initial epoch");
        let terminator = ArcTerminator::no_error();
        terminator.register(Arc::new(initial_space.crypto.clone()));
        let spaces = ArcSpaces::default();
        spaces.add(initial_space);
        let puncher = ArcPuncher::new(reliable_frames.clone(), ProbeEncoder::new(spaces.clone(), cid_registry.remote.apply_dcid()));
        let loss_resender = ArcResend::from(loss_resender);
        let progress = ArcProgress::new(facts, cid_registry.remote.clone(), spaces.clone(), loss_resender.clone(), terminator.clone());
        let paths = Arc::new(Self {
            cid_registry,
            puncher,
            spaces,
            reliable_frames,
            resenders: loss_resender,
            terminator: terminator.clone(),
            progress,
            entries: Mutex::new(BTreeMap::new()),
            validations: ArcValidations::default(),
            role,
            idle_timer: idle,
            max_idle_timeout: Mutex::new(max_idle_timeout),
            defer_idle_timeout,
            failed_opened: AtomicU64::new(0),
        });
        tokio::spawn({
            let weak = Arc::downgrade(&paths);
            let idle_timer = paths.idle_timer.clone();
            let terminator = terminator.clone();
            async move {
                tokio::select! {
                    result = idle_timer.timeout() => if result.is_ok() {
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
        self.entries.lock().unwrap().entry(*pathway).or_insert_with(|| self.create_path(*pathway, facts)).clone()
    }

    /// Remove only this path instance and release its resources, even if already removed.
    pub fn del_path(&self, path: &Arc<Path>) -> bool {
        let removed = {
            let mut entries = self.entries.lock().unwrap();
            if entries.get(&path.pathway).is_some_and(|current| Arc::ptr_eq(current, path)) {
                entries.remove(&path.pathway);
                self.validations.remove(&path.pathway);
                true
            } else {
                false
            }
        };
        path.close();
        // A poll already in progress can register again after an earlier del_path.
        for waker in path.send_waker.drain() {
            path.spaces.unregister(&waker);
            self.reliable_frames.unregister(&waker);
        }
        path.cc.on_path_lost();
        removed
    }

    /// Run until the connection terminates or this path fails or is closed.
    /// The detached task's owner calls del_path after this method returns.
    pub(crate) async fn send_via(&self, path: &Path) -> io::Result<()> {
        let mut datagrams = std::array::from_fn::<_, 8, _>(|_| Datagram::default());
        let mut frames = Vec::with_capacity(256);
        let terminator = path.terminator.clone();
        let idle_timer = self.idle_timer();
        let waker = poll_fn(|cx| {
            path.send_waker.register(cx.waker());
            Poll::Ready(cx.waker().clone())
        })
        .await;
        let result = loop {
            let result = tokio::select! {
                biased;
                _ = terminator.clone() => break Ok(()),
                // Path::close wakes collect/send, which then return BrokenPipe.
                result = async {
                    let (count, _) = path.collect(&mut datagrams, &mut frames).await?;
                    path.send(&mut datagrams[..count], &idle_timer).await
                } => result,
            };
            if let Err(error) = result {
                break Err(error);
            }
            path.refresh(&mut datagrams, &mut frames);
        };
        path.refresh(&mut datagrams, &mut frames);
        // An earlier del_path may have drained it before this poll finished registering sources.
        path.send_waker.register(&waker);
        result
    }

    /// Wake every registered path's sending task.
    pub fn wake_all_to_send(&self) {
        for path in self.entries.lock().unwrap().values() {
            path.send_waker.wake_all();
        }
    }

    /// Opening-key retention needs a PTO before an unknown path is admitted.
    /// Use existing path measurements without allocating a path or sender.
    pub fn pto_for(&self, pathway: &Pathway, epoch: Epoch) -> Duration {
        let entries = self.entries.lock().unwrap();
        if let Some(path) = entries.get(pathway) {
            return path.cc.get_pto(epoch);
        }
        entries.values().map(|path| path.cc.get_pto(epoch)).max().unwrap_or(Duration::from_secs(1))
    }

    fn create_path(self: &Arc<Self>, pathway: Pathway, facts: Arc<HandshakeFacts>) -> Arc<Path> {
        let confirmed = facts.is_handshake_done();
        let path = Arc::new(Path::new(
            self.cid_registry.remote.apply_dcid(),
            pathway,
            facts,
            self.spaces.clone(),
            self.resenders.clone(),
            ArcHeartbeat::new(self.defer_idle_timeout, *self.max_idle_timeout.lock().unwrap()),
            self.terminator.clone(),
            self.progress.clone(),
        ));
        if self.role == Role::Client {
            let _ = path.validation.exempt();
        }
        self.validations.insert(pathway, path.validation.clone());
        if confirmed {
            self.spawn_validation(&path);
        }

        tokio::spawn({
            let paths = self.clone();
            let path = path.clone();
            async move {
                let result = paths.send_via(&path).await;
                let pto = path.cc.pto_base(Epoch::Data);
                paths.del_path(&path);
                // An idle handshake upgrade can retain a CID without another collect poll.
                path.dcid.refresh();
                if paths.entries.lock().unwrap().is_empty() {
                    let reason = result.err().map_or_else(|| "all paths retired".to_owned(), |error| format!("all paths failed: {error}"));
                    paths.terminator.close(CloseReason::Internal(QuicError::with_default_fty(ErrorKind::NoViablePath, reason)), pto);
                }
            }
        });
        path
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn idle_timer(&self) -> ArcIdleTimer {
        self.idle_timer.clone()
    }

    pub fn update_max_idle_timeout(&self, timeout: Duration) {
        // Parameters use MAX for disabled expiry; IdleTimer uses ZERO.
        let timeout = if timeout == Duration::MAX {
            Duration::ZERO
        } else {
            timeout
        };
        let entries = self.entries.lock().unwrap();
        *self.max_idle_timeout.lock().unwrap() = timeout;
        self.idle_timer.update_max_idle_timeout(timeout);
        for path in entries.values() {
            path.heartbeat.revise_max_idle_timeout(timeout);
        }
    }

    pub fn closing_pto(&self) -> Duration {
        self.entries.lock().unwrap().values().map(|path| path.cc.pto_base(Epoch::Data)).max().unwrap_or(Duration::from_secs(1))
    }

    /// Share the authentication failure budget across paths and encryption levels.
    pub fn on_authentication_failed(&self, limit: u64) {
        if self.failed_opened.fetch_add(1, Ordering::Relaxed) >= limit.saturating_sub(1) {
            self.terminator.abort(QuicError::with_default_fty(ErrorKind::AeadLimitReached, "packet protection integrity limit").into());
        }
    }

    /// Spawn one round at path creation or handshake confirmation.
    /// After revalidation, the caller explicitly starts the next round.
    pub fn start_validation(self: &Arc<Self>, path: &Arc<Path>) {
        if !self.progress.facts().is_handshake_done() {
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
                        if path.validation.grant().is_ok() {
                            path.send_waker.wake_all();
                        }
                        break;
                    }
                    Ok(_) => break,
                    Err(_) => continue,
                }
            }
            if !path.validation.is_validated() {
                path.close();
            }
        });
    }

    /// Stop idle expiry and release paths, packet spaces and recovery trackers.
    pub fn clean(&self) {
        self.idle_timer.cancel();
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
        self.clean();
        self.cid_registry.local.clear();
    }
}
