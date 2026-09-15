//! Path validation and per-path congestion control. One sending owner per path.
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
    },
    time::Duration,
};

use qbase::{
    Epoch,
    cid::ConnectionId,
    error::ErrorKind,
    frame::{Frame, PathChallengeFrame, PathResponseFrame, io::ReceiveFrame},
    net::{
        route::Pathway,
        tx::{ArcSendWaker, Signals},
    },
};
use qcongestion::{Algorithm, ArcCC, Feedback, HandshakeStatus, PathStatus, Transport as _};
use tokio::time::Instant;

use crate::{Error, send::constraints::Constraints};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    Unvalidated,
    Validating {
        challenge: PathChallengeFrame,
        attempts: u8,
        retry_at: Instant,
    },
    Validated,
    Retired,
}

pub struct Path {
    pub pathway: Pathway,
    dcid: RwLock<ConnectionId>,
    pub cc: ArcCC,
    state: Mutex<PathState>,
    pub send_waker: ArcSendWaker,
    responses: Mutex<VecDeque<PathResponseFrame>>,
    received_bytes: AtomicU64,
    sent_bytes: AtomicU64,
    address_validated: AtomicBool,
    pub(crate) submission: Arc<Mutex<()>>,
    pub(crate) sender_active: AtomicBool,
    status: PathStatus,
}

impl Path {
    pub fn new(
        pathway: Pathway,
        dcid: ConnectionId,
        handshake: Arc<HandshakeStatus>,
        max_ack_delay: Duration,
        feedback: [Arc<dyn Feedback>; 3],
        submission: Arc<Mutex<()>>,
    ) -> Self {
        let send_waker = ArcSendWaker::new();
        let status = PathStatus::new(handshake, Arc::new(AtomicU16::new(1200)));
        let cc = ArcCC::new(
            Algorithm::NewReno,
            max_ack_delay,
            feedback,
            status.clone(),
            send_waker.clone(),
        );
        Self {
            pathway,
            dcid: RwLock::new(dcid),
            cc,
            state: Mutex::new(PathState::Unvalidated),
            send_waker,
            responses: Mutex::new(VecDeque::new()),
            received_bytes: 0.into(),
            sent_bytes: 0.into(),
            address_validated: false.into(),
            submission,
            sender_active: false.into(),
            status,
        }
    }

    pub fn dcid(&self) -> ConnectionId {
        *self.dcid.read().unwrap()
    }
    pub fn set_dcid(&self, dcid: ConnectionId) {
        let _submission = self.submission.lock().unwrap();
        *self.dcid.write().unwrap() = dcid;
        self.send_waker.wake_by(Signals::CONNECTION_ID);
    }
    pub fn state(&self) -> PathState {
        *self.state.lock().unwrap()
    }
    pub fn is_validated(&self) -> bool {
        self.state() == PathState::Validated
    }

    /// Account each received UDP datagram once, at the connection router.
    pub fn on_datagram_received(&self, bytes: usize) {
        self.received_bytes
            .fetch_add(bytes as u64, Ordering::AcqRel);
        if self.amplification_credit() >= 1200 {
            self.status.release_anti_amplification_limit();
            self.cc.grant_anti_amplification();
        }
        self.send_waker.wake_by(Signals::CREDIT);
    }

    /// Client-originated traffic, a validated token, or successful address validation grants this.
    /// Granting anti-amplification credit alone does not enable business traffic on a new path.
    pub fn grant_amplification(&self) {
        self.address_validated.store(true, Ordering::Release);
        self.status.release_anti_amplification_limit();
        self.cc.grant_anti_amplification();
        self.send_waker.wake_by(Signals::CREDIT);
    }
    pub fn validate(&self) {
        let _submission = self.submission.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        if *state != PathState::Retired {
            *state = PathState::Validated;
            self.grant_amplification();
        }
        self.send_waker.wake_by(Signals::PATH_VALIDATE);
    }
    pub fn start_validation(&self) {
        let mut state = self.state.lock().unwrap();
        if *state == PathState::Unvalidated {
            *state = PathState::Validating {
                challenge: PathChallengeFrame::random(),
                attempts: 0,
                retry_at: Instant::now(),
            };
            self.send_waker.wake_by(Signals::TRANSPORT);
        }
    }
    pub fn retire(&self) {
        {
            let _submission = self.submission.lock().unwrap();
            *self.state.lock().unwrap() = PathState::Retired;
        }
        self.cc.on_path_lost();
        self.responses.lock().unwrap().clear();
        self.send_waker.wake_by(Signals::all());
    }

    pub fn amplification_credit(&self) -> usize {
        if self.address_validated.load(Ordering::Acquire) {
            return usize::MAX;
        }
        self.received_bytes
            .load(Ordering::Acquire)
            .saturating_mul(3)
            .saturating_sub(self.sent_bytes.load(Ordering::Acquire))
            .min(usize::MAX as u64) as usize
    }
    pub fn constraints(&self, capacity: usize, probe: bool) -> Constraints {
        Constraints {
            capacity,
            congestion: self
                .cc
                .send_quota()
                .unwrap_or(0)
                .max(if probe { 1200 } else { 0 }),
            anti_amplification: self.amplification_credit(),
        }
    }
    pub(crate) fn challenge(&self) -> Result<Option<PathChallengeFrame>, Error> {
        match self.state() {
            PathState::Validating {
                attempts: 3..,
                retry_at,
                ..
            } if Instant::now() >= retry_at => Err(crate::error(
                ErrorKind::NoViablePath,
                "path validation timed out",
            )),
            PathState::Validating {
                challenge,
                retry_at,
                ..
            } if Instant::now() >= retry_at => Ok(Some(challenge)),
            _ => Ok(None),
        }
    }
    pub(crate) fn response(&self) -> Option<PathResponseFrame> {
        self.responses.lock().unwrap().front().copied()
    }
    pub(crate) fn on_sent(&self, bytes: usize, frames: &[Frame<()>]) {
        self.sent_bytes.fetch_add(bytes as u64, Ordering::AcqRel);
        for frame in frames {
            match frame {
                Frame::PathResponse(frame) => {
                    let mut responses = self.responses.lock().unwrap();
                    if responses.front() == Some(frame) {
                        responses.pop_front();
                    }
                }
                Frame::PathChallenge(sent) => {
                    if let PathState::Validating {
                        challenge,
                        attempts,
                        retry_at,
                    } = &mut *self.state.lock().unwrap()
                        && challenge == sent
                    {
                        *attempts += 1;
                        *retry_at = Instant::now()
                            + self
                                .cc
                                .pto_base(Epoch::Data)
                                .max(Duration::from_millis(100))
                                * 3;
                    }
                }
                _ => {}
            }
        }
        if self.amplification_credit() < 1200 {
            self.status.enter_anti_amplification_limit();
        }
    }
}

impl ReceiveFrame<PathChallengeFrame> for Path {
    type Output = ();
    fn recv_frame(&self, frame: PathChallengeFrame) -> Result<(), Error> {
        let mut responses = self.responses.lock().unwrap();
        let response = frame.into();
        if !responses.contains(&response) {
            // PATH_CHALLENGE is retried by its owner; bounded response storage cannot grow with input.
            if responses.len() == 8 {
                responses.pop_front();
            }
            responses.push_back(response);
        }
        self.send_waker.wake_by(Signals::TRANSPORT);
        Ok(())
    }
}
impl ReceiveFrame<PathResponseFrame> for Path {
    type Output = ();
    fn recv_frame(&self, response: PathResponseFrame) -> Result<(), Error> {
        let matches = matches!(self.state(), PathState::Validating { challenge, attempts: 1.., .. } if PathResponseFrame::from(challenge) == response);
        if matches {
            self.validate();
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct Paths {
    entries: Mutex<BTreeMap<Pathway, Arc<Path>>>,
}
impl Paths {
    pub fn insert(&self, path: Arc<Path>) -> bool {
        let mut entries = self.entries.lock().unwrap();
        if entries.contains_key(&path.pathway) {
            return false;
        }
        entries.insert(path.pathway, path);
        true
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
            true
        } else {
            false
        }
    }
}
