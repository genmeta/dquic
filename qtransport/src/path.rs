//! Path validation and per-path congestion control. One sending owner per path.
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, RwLock, atomic::AtomicU16},
    time::Duration,
};

use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    frame::{PathChallengeFrame, PathResponseFrame, io::ReceiveFrame},
    net::{
        route::Pathway,
        tx::{ArcSendWaker, Signals},
    },
    time::PathIdleTimer,
};
use qcongestion::{Algorithm, ArcCC, Feedback, HandshakeStatus, PathStatus, Transport as _};
use tokio::time::Instant;

use crate::{
    Error,
    send::{
        constraints::{AntiAmplifier, Constraints},
        write::PendingPacket,
    },
};

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
    pub anti_amplifier: Arc<AntiAmplifier>,
    pub activity: PathIdleTimer,
}

impl Path {
    pub fn new(
        pathway: Pathway,
        dcid: ConnectionId,
        handshake: Arc<HandshakeStatus>,
        max_ack_delay: Duration,
        activity: PathIdleTimer,
        feedback: [Arc<dyn Feedback>; 3],
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
    pub fn state(&self) -> PathState {
        *self.state.lock().unwrap()
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

    /// Client-originated traffic, a validated token, or successful address validation grants this.
    /// Granting anti-amplification credit alone does not enable business traffic on a new path.
    pub fn grant_amplification(&self) {
        self.anti_amplifier.grant();
        self.cc.grant_anti_amplification();
        self.send_waker.wake_by(Signals::CREDIT);
    }
    pub fn validate(&self) {
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
        *self.state.lock().unwrap() = PathState::Retired;
        // Connection-level recovery retains the sent packets and their deadlines.
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
    pub fn challenge(&self) -> Result<Option<PathChallengeFrame>, Error> {
        match self.state() {
            PathState::Validating {
                attempts: 3..,
                retry_at,
                ..
            } if Instant::now() >= retry_at => Err(QuicError::with_default_fty(
                ErrorKind::NoViablePath,
                "path validation timed out",
            )
            .into()),
            PathState::Validating {
                challenge,
                retry_at,
                ..
            } if Instant::now() >= retry_at => Ok(Some(challenge)),
            _ => Ok(None),
        }
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
            && let PathState::Validating {
                challenge,
                attempts,
                retry_at,
            } = &mut *self.state.lock().unwrap()
            && *challenge == sent
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
