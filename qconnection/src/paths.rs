use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, OnceLock, Weak},
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
use qcongestion::Transport as _;
use qtransport::{
    CloseReason,
    path::{Path, PathState},
};

use crate::{ArcConnPhase, ConnPhase, Error, terminate::ArcTerminator};

/// Connection-level path control. Every path has exactly one sending task.
pub struct Paths {
    phase: ArcConnPhase,
    pub(crate) entries: Mutex<BTreeMap<Pathway, Arc<Path>>>,
    responses: Mutex<HashMap<Pathway, ArcReceiving<[u8; 8]>>>,
    role: Role,
    selected: OnceLock<Weak<Path>>,
    idle: ArcConnIdle,
    closed: ArcReceiving<CloseReason>,
    terminator: ArcTerminator,
}

impl Paths {
    pub fn new(role: Role, phase: ArcConnPhase, idle: ArcConnIdle) -> Arc<Self> {
        let terminator = phase.terminator();
        Arc::new(Self {
            phase,
            entries: Mutex::new(BTreeMap::new()),
            responses: Mutex::new(HashMap::new()),
            role,
            selected: OnceLock::new(),
            idle,
            closed: ArcReceiving::default(),
            terminator,
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
            self.role,
            self.idle.timer(),
            self.phase.get().trackers(),
        ));
        if entries.values().any(|path| path.selected() == 2) {
            path.handshake_confirmed();
            if self.role == Role::Client {
                path.client_validating();
            }
        } else if self.selected.get().is_some() {
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
        if self.selected.set(Arc::downgrade(path)).is_err() {
            return;
        }
        for other in entries.values() {
            other.decide(other.pathway == path.pathway);
            if other.selected() == 0 {
                other.guard_amplification();
            }
        }
    }

    pub(crate) fn is_handshake_path(&self, path: &Path) -> bool {
        self.selected
            .get()
            .is_some_and(|selected| std::ptr::eq(selected.as_ptr(), path))
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

    pub(crate) fn closed(&self) -> ArcReceiving<CloseReason> {
        self.closed.clone()
    }

    pub(crate) fn terminator(&self) -> ArcTerminator {
        self.terminator.clone()
    }

    pub(crate) fn on_error(&self, error: Error) {
        self.closed.set(error.into());
    }

    pub(crate) fn on_rcvd_packet(&self) {
        self.terminator.on_rcvd_packet(tokio::time::Instant::now());
    }

    pub(crate) fn on_rcvd_close(
        &self,
        epoch: Epoch,
        path: &Path,
        frame: qbase::frame::ConnectionCloseFrame,
    ) {
        let duration = path.cc.pto_base(epoch) * 3;
        self.terminator
            .on_rcvd_connection_close_frame(frame.clone(), duration);
        self.closed.set(CloseReason::Peer(frame));
    }

    pub(crate) fn handshake_confirmed(self: &Arc<Self>) {
        let entries = self.entries.lock().unwrap();
        for path in entries.values() {
            if self.is_handshake_path(path) {
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

    #[cfg(test)]
    pub(crate) fn retire_all(&self) {
        self.terminator.terminate();
        for path in self.snapshot() {
            self.remove(&path);
        }
    }

    pub(crate) async fn finish(&self, reason: &CloseReason) {
        let snapshot = self.phase.get();
        let error: Error = match reason {
            CloseReason::App(error) => error.clone().into(),
            CloseReason::Internal(error) => error.clone().into(),
            CloseReason::Peer(frame) => frame.clone().into(),
        };
        let active_paths = self.snapshot();
        let pto = active_paths
            .iter()
            .map(|path| path.cc.pto_base(Epoch::Data))
            .max()
            .unwrap_or(Duration::from_secs(1));
        self.terminator.on_error(reason, pto * 3);

        match &snapshot {
            ConnPhase::Initial(phase) => phase.initial.crypto.on_error(&error),
            ConnPhase::Handshake(phase) => {
                phase.initial.crypto.on_error(&error);
                phase.handshake.crypto.on_error(&error);
            }
            ConnPhase::Mature(phase) => {
                phase.spaces.initial.crypto.on_error(&error);
                phase.spaces.handshake.crypto.on_error(&error);
                phase.spaces.data.crypto.on_error(&error);
                phase.spaces.data.streams.on_conn_error(&error);
                phase.flow.on_conn_error(&error);
            }
        }
        for path in &active_paths {
            for epoch in [Epoch::Initial, Epoch::Handshake] {
                path.cc.discard_epoch(epoch);
            }
        }

        self.terminator.wait().await;
        match &snapshot {
            ConnPhase::Initial(phase) => phase.initial.retire(),
            ConnPhase::Handshake(phase) => {
                phase.initial.retire();
                phase.handshake.retire();
            }
            ConnPhase::Mature(phase) => {
                phase.retire_handshake_spaces();
                phase.spaces.data.keys.retire();
            }
        }
        {
            let trackers = snapshot.trackers();
            let mut trackers = trackers.write().unwrap();
            let end = trackers.largest();
            trackers.drain_to(end).for_each(drop);
        }
        for path in active_paths {
            self.remove(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    use qbase::{cid::ConnectionId, net::addr::EndpointAddr};
    use qtransport::space::Space;

    use super::*;
    use crate::InitialPhase;

    fn paths(role: Role) -> Arc<Paths> {
        let keys = qtls::default_provider()
            .cipher_suites
            .iter()
            .find_map(|suite| suite.tls13().and_then(|suite| suite.quic_suite()))
            .unwrap()
            .keys(
                b"original",
                if role == Role::Server {
                    tls_backend::Side::Server
                } else {
                    tls_backend::Side::Client
                },
                tls_backend::quic::Version::V1,
            )
            .into();
        Paths::new(
            role,
            ArcConnPhase::initial(InitialPhase::new(
                ConnectionId::from_slice(b"localcid"),
                ConnectionId::from_slice(b"original"),
                keys,
            )),
            ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO),
        )
    }

    fn pathway(port: u16) -> Pathway {
        Pathway::new(
            EndpointAddr::direct(([127, 0, 0, 1], 30001).into()),
            EndpointAddr::direct(([127, 0, 0, 1], port).into()),
        )
    }

    #[tokio::test]
    async fn only_client_initial_paths_are_exempt_and_losing_paths_reset_the_guard() {
        let paths = paths(Role::Client);
        let first = paths.add_path(pathway(30002)).unwrap();
        let second = paths.add_path(pathway(30003)).unwrap();
        assert_eq!(first.state(), PathState::ClientHandshaking);
        assert_eq!(second.amplification_credit(), usize::MAX);
        let incoming = paths.on_incoming_path(pathway(30004)).unwrap();
        assert_eq!(incoming.amplification_credit(), 0);
        assert_eq!(first.selected(), u8::MAX);
        assert_eq!(second.selected(), u8::MAX);
        paths.select_path(&first);
        assert_eq!(first.selected(), 1);
        assert_eq!(second.selected(), 0);
        assert_eq!(incoming.selected(), 0);
        assert_eq!(first.state(), PathState::ClientHandshaking);
        assert_eq!(
            second.state(),
            PathState::AmplifyGuard {
                rcvd_bytes: 0,
                sent_bytes: 0
            }
        );
        assert_eq!(second.amplification_credit(), 0);
        second.on_datagram_received(100);
        second.anti_amplifier.on_sent(200);
        assert_eq!(second.amplification_credit(), 100);
        let ConnPhase::Initial(initial) = paths.phase.get() else {
            panic!()
        };
        paths.phase.enter_handshake(Arc::new(Space::new(
            Epoch::Handshake,
            initial.initial.keys.clone(),
        )));
        assert_eq!(
            paths
                .add_path(pathway(30005))
                .unwrap()
                .amplification_credit(),
            0
        );
        paths.handshake_confirmed();
        assert!(paths.snapshot().iter().all(|path| path.selected() == 2));
        assert!(first.is_validated());
        assert!(!second.is_validated());
        assert_eq!(second.state(), PathState::ClientValidating);
        assert_eq!(second.amplification_credit(), usize::MAX);
        assert!(paths.is_handshake_path(&first));
        let added = paths.add_path(pathway(30006)).unwrap();
        assert_eq!(added.selected(), 2);
        assert_eq!(added.state(), PathState::ClientValidating);
        let validating = paths.responses.lock().unwrap().len();
        assert!(Arc::ptr_eq(&added, &paths.add_path(added.pathway).unwrap()));
        assert_eq!(paths.responses.lock().unwrap().len(), validating);
        tokio::task::yield_now().await;
        assert!(first.challenge().is_none());
        assert!(second.challenge().is_some());
        assert!(added.challenge().is_some());
        paths.on_path_response(&second, second.challenge().unwrap().into());
        tokio::task::yield_now().await;
        assert!(second.is_validated());
        paths.retire_all();
    }

    #[tokio::test]
    async fn server_paths_start_guarded_and_only_the_correct_path_response_validates() {
        let paths = paths(Role::Server);
        let first = paths.add_path(pathway(30002)).unwrap();
        let second = paths.add_path(pathway(30003)).unwrap();
        assert_eq!(first.amplification_credit(), 0);
        paths.start_validation(&first);
        assert!(paths.responses.lock().unwrap().is_empty());
        first.handshake_confirmed();
        paths.start_validation(&first);
        paths.start_validation(&first);
        tokio::task::yield_now().await;
        assert_eq!(paths.responses.lock().unwrap().len(), 1);
        let challenge = first.challenge().unwrap();
        paths.on_path_response(&second, challenge.into());
        paths.on_path_response(&first, PathChallengeFrame::from_slice(&[42; 8]).into());
        assert!(!first.is_validated());
        paths.on_path_response(&first, challenge.into());
        tokio::task::yield_now().await;
        assert!(first.is_validated());
        assert_eq!(first.amplification_credit(), usize::MAX);
        assert_eq!(second.amplification_credit(), 0);
        assert!(paths.responses.lock().unwrap().is_empty());
        paths.retire_all();
    }

    #[tokio::test(start_paused = true)]
    async fn validation_times_out_after_three_attempts_and_retirement_cancels_waiting() {
        let paths = paths(Role::Server);
        let path = paths.add_path(pathway(30002)).unwrap();
        path.handshake_confirmed();
        paths.start_validation(&path);
        tokio::task::yield_now().await;
        for _ in 0..3 {
            assert!(path.challenge().is_some());
            tokio::time::advance(path.cc.pto_base(Epoch::Data) * 3).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(path.state(), PathState::Retired);
        assert!(paths.get(&path.pathway).is_none());
        assert!(paths.responses.lock().unwrap().is_empty());
        assert!(
            matches!(paths.closed().await.unwrap(), Some(CloseReason::Internal(error)) if error.kind() == ErrorKind::NoViablePath)
        );
        let replacement = paths.add_path(pathway(30002)).unwrap();
        replacement.handshake_confirmed();
        paths.start_validation(&replacement);
        tokio::task::yield_now().await;
        let response = paths
            .responses
            .lock()
            .unwrap()
            .get(&replacement.pathway)
            .unwrap()
            .clone();
        paths.remove(&replacement);
        assert!(response.await.is_err());
        tokio::task::yield_now().await;
        assert!(paths.responses.lock().unwrap().is_empty());
    }
}
