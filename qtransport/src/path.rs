//! Path validation and per-path congestion control. One sending owner per path.
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::Duration,
};

use qbase::{
    cid::ConnectionId,
    frame::{PathChallengeFrame, PathResponseFrame, io::ReceiveFrame},
    net::{
        route::Pathway,
        tx::{ArcSendWaker, Signals},
    },
    role::Role,
    time::PathIdleTimer,
};
use qcongestion::{Algorithm, ArcCC, Feedback, HandshakeStatus, PathStatus, Transport as _};

use crate::{
    Error,
    send::{
        constraints::{AntiAmplifier, Constraints},
        write::PendingPacket,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    ClientHandshaking,
    AmplifyGuard {
        rcvd_bytes: usize,
        sent_bytes: usize,
    },
    Validated,
    Retired,
}

pub struct Path {
    pub pathway: Pathway,
    dcid: RwLock<ConnectionId>,
    selected: AtomicBool,
    handshake: Arc<HandshakeStatus>,
    pub cc: ArcCC,
    challenge: Mutex<Option<(PathChallengeFrame, bool)>>,
    pub send_waker: ArcSendWaker,
    responses: Mutex<VecDeque<PathResponseFrame>>,
    pub anti_amplifier: Arc<AntiAmplifier>,
    pub activity: PathIdleTimer,
}

impl Path {
    pub fn new(
        pathway: Pathway,
        role: Role,
        activity: PathIdleTimer,
        feedback: [Arc<dyn Feedback>; 3],
    ) -> Self {
        let send_waker = ArcSendWaker::new();
        let handshake = Arc::new(HandshakeStatus::new(role == Role::Server));
        let status = PathStatus::new(handshake.clone(), Arc::new(AtomicU16::new(1200)));
        let cc = ArcCC::new(
            Algorithm::NewReno,
            Duration::from_millis(25),
            feedback,
            status.clone(),
            send_waker.clone(),
        );
        Self {
            pathway,
            dcid: RwLock::new(ConnectionId::default()),
            selected: AtomicBool::new(false),
            handshake,
            cc,
            challenge: Mutex::new(None),
            send_waker,
            responses: Mutex::new(VecDeque::new()),
            anti_amplifier: Arc::new(AntiAmplifier::new(status)),
            activity,
        }
    }

    pub fn dcid(&self) -> ConnectionId {
        *self.dcid.read().unwrap()
    }
    pub fn set_dcid(&self, dcid: ConnectionId) {
        *self.dcid.write().unwrap() = dcid;
        self.send_waker.wake_by(Signals::CONNECTION_ID);
    }
    pub fn select(&self) {
        self.selected.store(true, Ordering::Release);
    }
    pub fn is_selected(&self) -> bool {
        self.selected.load(Ordering::Acquire)
    }
    pub fn got_handshake_key(&self) {
        self.handshake.got_handshake_key();
    }
    pub fn handshake_confirmed(&self) {
        self.handshake.handshake_confirmed();
    }
    pub fn state(&self) -> PathState {
        *self.anti_amplifier.state.lock().unwrap()
    }
    pub fn is_validated(&self) -> bool {
        self.state() == PathState::Validated
    }

    /// Account each received UDP datagram once, at the connection router.
    pub fn on_datagram_received(&self, bytes: usize) {
        self.anti_amplifier.on_received(bytes);
        if self.amplification_credit() >= 1200 {
            self.cc.grant_anti_amplification();
        }
        self.send_waker.wake_by(Signals::CREDIT);
    }

    pub fn client_handshaking(&self) {
        self.anti_amplifier.client_handshaking();
        self.cc.grant_anti_amplification();
        self.send_waker.wake_by(Signals::CREDIT);
    }

    pub fn guard_amplification(&self) {
        self.anti_amplifier.guard();
        *self.challenge.lock().unwrap() = None;
        self.responses.lock().unwrap().clear();
        self.send_waker.wake_by(Signals::CREDIT);
    }

    pub fn validate(&self) {
        self.anti_amplifier.grant();
        *self.challenge.lock().unwrap() = None;
        self.cc.grant_anti_amplification();
        self.send_waker.wake_by(Signals::PATH_VALIDATE);
    }

    pub fn set_challenge(&self, challenge: PathChallengeFrame) {
        if matches!(self.state(), PathState::AmplifyGuard { .. }) {
            *self.challenge.lock().unwrap() = Some((challenge, false));
            self.send_waker.wake_by(Signals::TRANSPORT);
        }
    }

    pub fn matches_response(&self, response: PathResponseFrame) -> bool {
        self.challenge
            .lock()
            .unwrap()
            .is_some_and(|(challenge, _)| PathResponseFrame::from(challenge) == response)
    }

    pub fn clear_challenge(&self) {
        *self.challenge.lock().unwrap() = None;
    }

    pub fn retire(&self) {
        *self.anti_amplifier.state.lock().unwrap() = PathState::Retired;
        self.clear_challenge();
        self.responses.lock().unwrap().clear();
        self.send_waker.wake_by(Signals::all());
    }

    pub fn amplification_credit(&self) -> usize {
        self.anti_amplifier.balance()
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
    pub fn challenge(&self) -> Option<PathChallengeFrame> {
        self.challenge
            .lock()
            .unwrap()
            .and_then(|(challenge, sent)| (!sent).then_some(challenge))
    }
    pub fn response(&self) -> Option<PathResponseFrame> {
        self.responses.lock().unwrap().front().copied()
    }
    /// Confirm only path validation frames whose datagram reached the socket.
    pub fn on_packet_sent(&self, packet: &PendingPacket) {
        if let Some(frame) = packet.response {
            let mut responses = self.responses.lock().unwrap();
            if responses.front() == Some(&frame) {
                responses.pop_front();
            }
        }
        if let Some(sent) = packet.challenge
            && let Some((challenge, submitted)) = self.challenge.lock().unwrap().as_mut()
            && *challenge == sent
        {
            *submitted = true;
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
