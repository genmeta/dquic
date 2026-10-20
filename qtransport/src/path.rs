//! Path validation and per-path congestion control. One sending owner per path.
use std::{
    collections::VecDeque,
    future::poll_fn,
    sync::{Arc, Mutex, RwLock, atomic::AtomicU16},
    task::{Context, Poll},
    time::Duration,
};

use bytes::BufMut;
use qbase::{
    Epoch,
    frame::{Frame, PathChallengeFrame, PathResponseFrame, io::ReceiveFrame},
    net::{route::Pathway, tx::ArcSendWakers},
    packet::{self, Package, PacketBuffer, assemble::Metadata},
    time::{heartbeat::ArcHeartbeat, timer::ArcIdleTimer},
    util::IndexDeque,
};
use qcongestion::{
    Algorithm, ArcCC, CongestionController, HandshakeStatus, PathStatus, Resend, Transport as _,
};
use qprotocol::QuicProtocol;
use tokio::time::Instant;

use crate::Error;
mod cids;
pub use cids::{PathCid, PathCids};

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
    pub cid: Arc<PathCid>,
    pub cc: ArcCC,
    challenge: Mutex<Option<(PathChallengeFrame, bool)>>,
    pub send_waker: ArcSendWakers,
    responses: Mutex<VecDeque<PathResponseFrame>>,
    pub anti_amplifier: Arc<AntiAmplifier>,
    pub heartbeat: ArcHeartbeat,
}

impl Path {
    /// Construct a path using the connection's shared handshake lifecycle.
    pub fn new(
        pathway: Pathway,
        handshake: Arc<HandshakeStatus>,
        heartbeat: ArcHeartbeat,
        trackers: Arc<RwLock<IndexDeque<Arc<dyn Resend>, 2>>>,
        cids: &Arc<PathCids>,
    ) -> Self {
        let send_waker = ArcSendWakers::default();
        let status = PathStatus::new(handshake, Arc::new(AtomicU16::new(1200)));
        let cc = ArcCC::new(
            Algorithm::NewReno,
            Duration::from_millis(25),
            trackers,
            status.clone(),
            send_waker.clone(),
        );
        Self {
            pathway,
            cid: cids.register(pathway, send_waker.clone()),
            cc,
            challenge: Mutex::new(None),
            send_waker,
            responses: Mutex::new(VecDeque::new()),
            anti_amplifier: Arc::new(AntiAmplifier::new(status)),
            heartbeat,
        }
    }

    pub async fn failed(&self) {
        poll_fn(|cx| {
            self.send_waker.register(cx.waker());
            if self.state() == PathState::Retired {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
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

    /// Account one successfully submitted datagram under the submission's CC lock.
    pub fn on_sent(
        &self,
        cc: &mut CongestionController,
        bytes: usize,
        packets: [Option<Metadata>; 3],
        idle: &ArcIdleTimer,
    ) {
        let overhead = QuicProtocol::packet_overhead(self.pathway);
        let charged = packets
            .iter()
            .position(|p| p.as_ref().is_some_and(|meta| meta.in_flight))
            .or_else(|| packets.iter().position(Option::is_some));
        let now = Instant::now();
        self.anti_amplifier.on_sent(bytes + overhead);
        let _ = idle.on_sent_at(now);
        for (epoch, packet) in Epoch::EPOCHS.into_iter().zip(packets) {
            let Some(meta) = packet else { continue };
            let size = meta.pktlen
                + if charged == Some(epoch as usize) {
                    overhead
                } else {
                    0
                };
            cc.on_pkt_sent(
                epoch,
                meta.pn,
                meta.content.is_ack_eliciting(),
                size,
                meta.in_flight,
                meta.ack,
            );
            let _ = self.heartbeat.on_sent_at(meta.content, now);
        }
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
        self.cid.retire();
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
    fn belongs_to(&self, packet_type: packet::Type) -> bool {
        matches!(packet_type, packet::Type::Short(_))
    }

    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut PacketBuffer<'_, B>,
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
        let start = buffer.meta.nframes;
        let mut result = Poll::Pending;
        if let Some(mut response) = response {
            result = response.poll_dump(cx, buffer);
            if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
                self.on_frame_assembled(&Frame::PathResponse(response));
            }
        }
        if let Some(mut challenge) = challenge_frame {
            match challenge.poll_dump(cx, buffer) {
                Poll::Pending => {}
                ready => {
                    if matches!(ready, Poll::Ready(Ok(n)) if n > 0) {
                        self.on_frame_assembled(&Frame::PathChallenge(challenge));
                    }
                    result = ready;
                }
            }
        }
        if buffer.meta.nframes > start {
            Poll::Ready(Ok(buffer.meta.nframes - start))
        } else {
            result
        }
    }
}
