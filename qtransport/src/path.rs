//! Path validation and per-path congestion control. One sending owner per path.
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU8, AtomicU16, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::BufMut;
use qbase::{
    frame::{Frame, PathChallengeFrame, PathResponseFrame, io::ReceiveFrame},
    net::{route::Pathway, tx::ArcSendWakers},
    packet::{ConstraintBuffer, Package},
    time::heartbeat::ArcHeartbeat,
    util::IndexDeque,
};
use qcongestion::{Algorithm, ArcCC, HandshakeStatus, PathStatus, Resend, Transport as _};

use crate::Error;
mod anti_amplifier;
pub use anti_amplifier::AntiAmplifier;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    ClientHandshaking,
    ClientValidating,
    AmplifyGuard {
        rcvd_bytes: usize,
        sent_bytes: usize,
    },
    Validated,
    Retired,
}

pub struct Path {
    pub pathway: Pathway,
    // 0xff: undecided, 0: suspended, 1: selected, 2: released after handshake
    // confirmation and the selected sender's CID allocation.
    selected: AtomicU8,
    handshake: Arc<HandshakeStatus>,
    pub cc: ArcCC,
    challenge: Mutex<Option<(PathChallengeFrame, bool)>>,
    pub send_waker: ArcSendWakers,
    responses: Mutex<VecDeque<PathResponseFrame>>,
    pub anti_amplifier: Arc<AntiAmplifier>,
    pub heartbeat: ArcHeartbeat,
}

impl Path {
    pub const MP_INITIAL: u8 = 0xFF;
    pub const SUSPEND: u8 = 0;
    pub const SELECTED: u8 = 1;
    pub const HANDSHAKED: u8 = 2;

    /// Construct a path using the connection's shared handshake lifecycle.
    pub fn new(
        pathway: Pathway,
        handshake: Arc<HandshakeStatus>,
        heartbeat: ArcHeartbeat,
        trackers: Arc<RwLock<IndexDeque<Arc<dyn Resend>, 2>>>,
    ) -> Self {
        let send_waker = ArcSendWakers::default();
        let status = PathStatus::new(handshake.clone(), Arc::new(AtomicU16::new(1200)));
        let cc = ArcCC::new(
            Algorithm::NewReno,
            Duration::from_millis(25),
            trackers,
            status.clone(),
            send_waker.clone(),
        );
        Self {
            pathway,
            selected: AtomicU8::new(u8::MAX),
            handshake,
            cc,
            challenge: Mutex::new(None),
            send_waker,
            responses: Mutex::new(VecDeque::new()),
            anti_amplifier: Arc::new(AntiAmplifier::new(status)),
            heartbeat,
        }
    }

    pub fn decide(&self, selected: bool) {
        self.selected.store(
            if selected {
                Self::SELECTED
            } else {
                Self::SUSPEND
            },
            Ordering::Release,
        );
        self.send_waker.wake_all();
    }

    pub fn selected(&self) -> u8 {
        self.selected.load(Ordering::Acquire)
    }

    pub fn got_handshake_key(&self) {
        self.handshake.got_handshake_key();
    }

    pub fn handshake_confirmed(&self) {
        self.handshake.handshake_confirmed();
        self.selected.store(Self::HANDSHAKED, Ordering::Release);
        self.send_waker.wake_all();
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
        self.send_waker.wake_all();
    }

    pub fn client_handshaking(&self) {
        self.anti_amplifier.client_handshaking();
        self.cc.grant_anti_amplification();
        self.send_waker.wake_all();
    }

    pub fn client_validating(&self) {
        self.anti_amplifier.client_validating();
        self.cc.grant_anti_amplification();
        self.send_waker.wake_all();
    }

    pub fn guard_amplification(&self) {
        self.anti_amplifier.guard();
        *self.challenge.lock().unwrap() = None;
        self.responses.lock().unwrap().clear();
        self.send_waker.wake_all();
    }

    pub fn validate(&self) {
        self.anti_amplifier.grant();
        *self.challenge.lock().unwrap() = None;
        self.cc.grant_anti_amplification();
        self.send_waker.wake_all();
    }

    pub fn set_challenge(&self, challenge: PathChallengeFrame) {
        if matches!(
            self.state(),
            PathState::AmplifyGuard { .. } | PathState::ClientValidating
        ) {
            *self.challenge.lock().unwrap() = Some((challenge, false));
            self.send_waker.wake_all();
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
        self.anti_amplifier.retire();
        self.heartbeat.stop();
        self.clear_challenge();
        self.responses.lock().unwrap().clear();
        self.send_waker.wake_all();
    }

    pub fn amplification_credit(&self) -> usize {
        self.anti_amplifier.balance()
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

    pub fn on_frame_assembled(&self, frame: &qbase::frame::Frame) {
        match frame {
            qbase::frame::Frame::PathResponse(frame) => {
                let mut responses = self.responses.lock().unwrap();
                if responses.front() == Some(frame) {
                    responses.pop_front();
                }
            }
            qbase::frame::Frame::PathChallenge(frame) => {
                if let Some((challenge, submitted)) = self.challenge.lock().unwrap().as_mut()
                    && challenge == frame
                {
                    *submitted = true;
                }
            }
            _ => {}
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
        self.send_waker.wake_all();
        Ok(())
    }
}

impl<B: BufMut + ?Sized> Package<B> for &Path {
    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ConstraintBuffer<'_, B>,
        frames: &mut Vec<Frame>,
    ) -> Poll<Result<usize, Error>> {
        let responses = self.responses.lock().unwrap();
        let challenge = self.challenge.lock().unwrap();
        let response = responses.front().copied();
        let challenge_frame = challenge.and_then(|(frame, sent)| (!sent).then_some(frame));
        if response.is_none() && challenge_frame.is_none() {
            self.send_waker.register(cx.waker());
            return Poll::Pending;
        }
        drop(challenge);
        drop(responses);
        let start = frames.len();
        let mut result = Poll::Pending;
        if let Some(mut response) = response {
            result = response.poll_dump(cx, buffer, frames);
        }
        if let Some(mut challenge) = challenge_frame {
            match challenge.poll_dump(cx, buffer, frames) {
                Poll::Pending => {}
                ready => result = ready,
            }
        }
        for frame in &frames[start..] {
            self.on_frame_assembled(frame);
        }
        if frames.len() > start {
            Poll::Ready(Ok(frames.len() - start))
        } else {
            result
        }
    }
}

#[cfg(test)]
mod package_tests {
    use std::{sync::atomic::AtomicUsize, task::Waker};

    use qbase::{
        net::addr::EndpointAddr,
        packet::{Constraints, GetType, OneRttHeader},
    };

    use super::*;

    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn handshake_confirmation_stops_early_epoch_pto() {
        use qbase::Epoch;
        let path = Path::new(
            Pathway::new(
                EndpointAddr::direct("127.0.0.1:4400".parse().unwrap()),
                EndpointAddr::direct("127.0.0.1:5500".parse().unwrap()),
            ),
            Arc::new(HandshakeStatus::new(false)),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            Arc::new(RwLock::new(IndexDeque::with_capacity(3))),
        );
        path.client_handshaking();
        path.got_handshake_key();
        for epoch in [Epoch::Initial, Epoch::Handshake] {
            path.cc.on_pkt_sent(epoch, 0, true, 1200, true, None);
        }
        path.handshake_confirmed();
        for _ in 0..8 {
            tokio::time::advance(Duration::from_secs(1)).await;
            path.cc.do_tick().unwrap();
            assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Initial), 0);
            assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Handshake), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn validation_registers_only_when_both_sources_are_empty() {
        for queued in [false, true] {
            for quota in [0, 128] {
                let path = Path::new(
                    Pathway::new(
                        EndpointAddr::direct("127.0.0.1:4400".parse().unwrap()),
                        EndpointAddr::direct("127.0.0.1:5500".parse().unwrap()),
                    ),
                    Arc::new(HandshakeStatus::new(true)),
                    ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                    Arc::default(),
                );
                if queued {
                    path.recv_frame(PathChallengeFrame::from_slice(&[1; 8]))
                        .unwrap();
                    path.set_challenge(PathChallengeFrame::from_slice(&[2; 8]));
                }
                let counter = Arc::new(Counter(AtomicUsize::new(0)));
                let waker = Waker::from(counter.clone());
                let mut bytes = bytes::BytesMut::new();
                let mut frames = Vec::new();
                let mut limits = Constraints {
                    flow_ctrl: 0,
                    send_quota: quota,
                    credit: 128,
                    min_size: 0,
                    max_size: 128,
                    ..Default::default()
                };
                let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
                let result = (&path).poll_dump(
                    &mut Context::from_waker(&waker),
                    &mut ConstraintBuffer::new(&mut bytes, &mut limits, ty, 0, 0),
                    &mut frames,
                );
                assert_eq!(result.is_pending(), !queued);
                if queued {
                    assert_eq!(result, Poll::Ready(Ok(if quota == 0 { 0 } else { 2 })));
                }
                path.recv_frame(PathChallengeFrame::from_slice(&[3; 8]))
                    .unwrap();
                assert_eq!(counter.0.load(Ordering::Relaxed), usize::from(!queued));
            }
        }
    }
}
