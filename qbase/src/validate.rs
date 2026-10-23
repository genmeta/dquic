//! Per-path validation. One task sends frames and spends credit on each path.
//! Challenge matching, timeouts and retransmission belong to the owning task.
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use bytes::BufMut;

use crate::{
    ArcReceiving, Cancelled,
    error::Error,
    frame::{
        PathChallengeFrame, PathResponseFrame,
        io::{ReceiveFrame, SendFrame},
    },
    net::route::Pathway,
    packet::{Package, PacketBuffer, Type},
};

/// Outgoing challenges and responses, with a single sending-task waiter.
/// Keeps the latest queued challenge and one response for every received challenge.
/// Shared access is synchronized by `ArcValidation`.
#[derive(Debug, Default)]
pub struct PathValidateFrames {
    challenge: Option<PathChallengeFrame>,
    responses: VecDeque<PathResponseFrame>,
    waker: Option<Waker>,
}

impl PathValidateFrames {
    fn wake(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

impl<B: BufMut + ?Sized> Package<B> for PathValidateFrames {
    fn belongs_to(&self, packet_type: Type) -> bool {
        matches!(packet_type, Type::Short(_))
    }

    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut PacketBuffer<'_, B>,
    ) -> Poll<Result<usize, Error>> {
        if self.responses.is_empty() && self.challenge.is_none() {
            self.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let start = buffer.meta.nframes;
        while let Some(frame) = self.responses.front_mut() {
            let n = std::task::ready!(frame.poll_dump(cx, buffer))?;
            if n == 0 {
                return Poll::Ready(Ok(buffer.meta.nframes - start));
            }
            self.responses.pop_front();
        }
        if self.challenge.is_some() {
            std::task::ready!(self.challenge.poll_dump(cx, buffer))?;
        }
        Poll::Ready(Ok(buffer.meta.nframes - start))
    }
}

/// Address validation and amplification allowance for one path.
/// Each state retains the same attempt's response receiver.
#[derive(Debug)]
pub enum Validation {
    Validating {
        rcvd_bytes: usize,
        sent_bytes: usize,
        credit_waker: Option<Waker>,
        frames: PathValidateFrames,
        response: ArcReceiving<PathResponseFrame>,
    },
    Validated {
        frames: PathValidateFrames,
        response: ArcReceiving<PathResponseFrame>,
    },
    Cancelled {
        response: ArcReceiving<PathResponseFrame>,
    },
}

impl Default for Validation {
    fn default() -> Self {
        Self::Validating {
            rcvd_bytes: 0,
            sent_bytes: 0,
            credit_waker: None,
            frames: PathValidateFrames::default(),
            response: ArcReceiving::default(),
        }
    }
}

impl Validation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_validated(&self) -> bool {
        matches!(self, Self::Validated { .. })
    }

    /// `None` grants unlimited credit. Zero finite credit waits for new input.
    pub fn poll_credit(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<usize>, Cancelled>> {
        match self {
            Self::Validating {
                rcvd_bytes,
                sent_bytes,
                credit_waker,
                ..
            } => {
                let credit = rcvd_bytes.saturating_mul(3).saturating_sub(*sent_bytes);
                if credit == 0 {
                    *credit_waker = Some(cx.waker().clone());
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(Some(credit)))
                }
            }
            Self::Validated { .. } => Poll::Ready(Ok(None)),
            Self::Cancelled { .. } => Poll::Ready(Err(Cancelled)),
        }
    }

    /// Account for each received UDP datagram once.
    pub fn on_received(&mut self, bytes: usize) {
        if let Self::Validating {
            rcvd_bytes,
            sent_bytes,
            credit_waker,
            ..
        } = self
        {
            *rcvd_bytes = rcvd_bytes.saturating_add(bytes);
            if rcvd_bytes.saturating_mul(3) > *sent_bytes {
                if let Some(waker) = credit_waker.take() {
                    waker.wake();
                }
            }
        }
    }

    /// Debit only successfully sent datagrams, after checking their full size against credit.
    pub fn on_sent(&mut self, bytes: usize) {
        if let Self::Validating { sent_bytes, .. } = self {
            *sent_bytes = sent_bytes.saturating_add(bytes);
        }
    }

    /// Grant credit without running a local challenge, for example on the client.
    pub fn exempt(&mut self) -> Result<(), Cancelled> {
        self.trust()
    }

    /// Enter the validated state after the caller has accepted the response or other proof.
    /// Pending responses to the peer's challenges remain queued.
    pub fn trust(&mut self) -> Result<(), Cancelled> {
        let response = self.respond();
        match std::mem::replace(self, Self::Cancelled { response }) {
            Self::Validating {
                response,
                mut frames,
                credit_waker,
                ..
            } => {
                frames.challenge = None;
                *self = Self::Validated { frames, response };
                if let Some(waker) = credit_waker {
                    waker.wake();
                }
                Ok(())
            }
            state @ Self::Validated { .. } => {
                *self = state;
                Ok(())
            }
            Self::Cancelled { .. } => Err(Cancelled),
        }
    }

    /// Revoke a validated path's trust and start a new attempt with zero credit.
    /// Preserve replies owed to the peer; an ongoing validation is unchanged.
    pub fn revalidate(&mut self) -> Result<(), Cancelled> {
        match self {
            Self::Validated { frames, .. } => {
                *self = Self::Validating {
                    rcvd_bytes: 0,
                    sent_bytes: 0,
                    credit_waker: None,
                    frames: std::mem::take(frames),
                    response: ArcReceiving::default(),
                };
                Ok(())
            }
            Self::Validating { .. } => Ok(()),
            Self::Cancelled { .. } => Err(Cancelled),
        }
    }

    /// Queue a local challenge while unvalidated. Revalidate first to challenge a trusted path.
    /// Retransmissions keep the current response receiver and credit.
    pub fn challenge(&mut self, frame: PathChallengeFrame) -> Result<(), Cancelled> {
        match self {
            Self::Validating { frames, .. } => {
                frames.challenge = Some(frame);
                frames.wake();
                Ok(())
            }
            Self::Validated { .. } => Ok(()),
            Self::Cancelled { .. } => Err(Cancelled),
        }
    }

    /// Clone the response receiver without matching or changing validation state.
    /// The caller owns challenge matching, retries and the validated transition.
    pub fn respond(&self) -> ArcReceiving<PathResponseFrame> {
        match self {
            Self::Validating { response, .. }
            | Self::Validated { response, .. }
            | Self::Cancelled { response } => response.clone(),
        }
    }

    pub fn recv_path_challenge_frame(&mut self, frame: PathChallengeFrame) {
        match self {
            Self::Validating { frames, .. } | Self::Validated { frames, .. } => {
                frames.responses.push_back(frame.into());
                frames.wake();
            }
            Self::Cancelled { .. } => (),
        }
    }

    pub fn recv_path_response_frame(&self, frame: PathResponseFrame) {
        if let Self::Validating { response, .. } = self {
            response.obtain(frame);
        }
    }

    /// Permanently stop this instance and wake its response, credit and frame waiters.
    pub fn cancel(&mut self) {
        let response = self.respond();
        match std::mem::replace(self, Self::Cancelled { response }) {
            Self::Validating {
                response,
                mut frames,
                credit_waker,
                ..
            } => {
                response.cancel();
                if let Some(waker) = credit_waker {
                    waker.wake();
                }
                frames.wake();
            }
            Self::Validated {
                response,
                mut frames,
            } => {
                response.cancel();
                frames.wake();
            }
            Self::Cancelled { .. } => (),
        }
    }
}

impl<B: BufMut + ?Sized> Package<B> for Validation {
    fn belongs_to(&self, packet_type: Type) -> bool {
        matches!(packet_type, Type::Short(_))
    }

    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut PacketBuffer<'_, B>,
    ) -> Poll<Result<usize, Error>> {
        match self {
            Self::Validating { frames, .. } | Self::Validated { frames, .. } => {
                frames.poll_dump(cx, buffer)
            }
            Self::Cancelled { .. } => Poll::Ready(Ok(0)),
        }
    }
}

/// Shared validation state. At most one sender and one response waiter per path.
/// All frame sends, receives and packet assembly use this instance's mutex.
///
/// The validation task retains the challenge and explicitly grants credit on success:
///
/// ```no_run
/// # use qbase::{Cancelled, frame::{PathChallengeFrame, PathResponseFrame}, validate::ArcValidation};
/// # async fn attempt(validation: ArcValidation) -> Result<(), Cancelled> {
/// let challenge = PathChallengeFrame::random();
/// validation.challenge(challenge)?;
/// let response = validation.respond().await?;
/// if response == Some(PathResponseFrame::from(challenge)) {
///     validation.enter_validated()?;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct ArcValidation(Arc<Mutex<Validation>>);

impl ArcValidation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_validated(&self) -> bool {
        self.0.lock().unwrap().is_validated()
    }

    /// Wait for positive credit, return `None` for unlimited credit, or report cancellation.
    pub fn poll_credit(&self, cx: &mut Context<'_>) -> Poll<Result<Option<usize>, Cancelled>> {
        self.0.lock().unwrap().poll_credit(cx)
    }

    pub fn on_received(&self, bytes: usize) {
        self.0.lock().unwrap().on_received(bytes);
    }

    pub fn on_sent(&self, bytes: usize) {
        self.0.lock().unwrap().on_sent(bytes);
    }

    pub fn exempt(&self) -> Result<(), Cancelled> {
        self.0.lock().unwrap().exempt()
    }

    pub fn enter_validated(&self) -> Result<(), Cancelled> {
        self.0.lock().unwrap().trust()
    }

    pub fn revalidate(&self) -> Result<(), Cancelled> {
        self.0.lock().unwrap().revalidate()
    }

    pub fn challenge(&self, frame: PathChallengeFrame) -> Result<(), Cancelled> {
        self.0.lock().unwrap().challenge(frame)
    }

    /// Snapshot this attempt's receiver; only the caller matches and accepts the result.
    pub fn respond(&self) -> ArcReceiving<PathResponseFrame> {
        self.0.lock().unwrap().respond()
    }

    pub fn cancel(&self) {
        self.0.lock().unwrap().cancel();
    }
}

impl SendFrame<PathChallengeFrame> for ArcValidation {
    fn send_frame<I: IntoIterator<Item = PathChallengeFrame>>(&self, iter: I) {
        if let Some(frame) = iter.into_iter().last() {
            let _ = self.0.lock().unwrap().challenge(frame);
        }
    }
}

impl SendFrame<PathResponseFrame> for ArcValidation {
    fn send_frame<I: IntoIterator<Item = PathResponseFrame>>(&self, iter: I) {
        let mut validation = self.0.lock().unwrap();
        let frames = match &mut *validation {
            Validation::Validating { frames, .. } => frames,
            Validation::Validated { frames, .. } => frames,
            Validation::Cancelled { .. } => return,
        };
        let start = frames.responses.len();
        frames.responses.extend(iter);
        if frames.responses.len() > start {
            frames.wake();
        }
    }
}

impl ReceiveFrame<PathChallengeFrame> for ArcValidation {
    type Output = ();

    fn recv_frame(&self, frame: PathChallengeFrame) -> Result<(), Error> {
        self.0.lock().unwrap().recv_path_challenge_frame(frame);
        Ok(())
    }
}

impl ReceiveFrame<PathResponseFrame> for ArcValidation {
    type Output = ();

    fn recv_frame(&self, frame: PathResponseFrame) -> Result<(), Error> {
        self.0.lock().unwrap().recv_path_response_frame(frame);
        Ok(())
    }
}

impl<B: BufMut + ?Sized> Package<B> for ArcValidation {
    fn belongs_to(&self, packet_type: Type) -> bool {
        matches!(packet_type, Type::Short(_))
    }

    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut PacketBuffer<'_, B>,
    ) -> Poll<Result<usize, Error>> {
        self.0.lock().unwrap().poll_dump(cx, buffer)
    }
}

/// Dispatches validation frames to their owning paths.
#[derive(Debug, Clone, Default)]
pub struct ArcValidations(Arc<Mutex<HashMap<Pathway, ArcValidation>>>);

impl ArcValidations {
    pub fn insert(&self, pathway: Pathway, validation: ArcValidation) -> Option<ArcValidation> {
        let old = self.0.lock().unwrap().insert(pathway, validation.clone());
        if let Some(old) = &old {
            if !Arc::ptr_eq(&old.0, &validation.0) {
                old.cancel();
            }
        }
        old
    }

    pub fn get(&self, pathway: &Pathway) -> Option<ArcValidation> {
        self.0.lock().unwrap().get(pathway).cloned()
    }

    pub fn remove(&self, pathway: &Pathway) -> Option<ArcValidation> {
        let old = self.0.lock().unwrap().remove(pathway);
        if let Some(old) = &old {
            old.cancel();
        }
        old
    }
}

impl ReceiveFrame<(Pathway, PathChallengeFrame)> for ArcValidations {
    type Output = ();

    fn recv_frame(&self, (pathway, frame): (Pathway, PathChallengeFrame)) -> Result<(), Error> {
        if let Some(validation) = self.get(&pathway) {
            validation.recv_frame(frame)?;
        }
        Ok(())
    }
}

impl ReceiveFrame<(Pathway, PathResponseFrame)> for ArcValidations {
    type Output = ();

    fn recv_frame(&self, (pathway, frame): (Pathway, PathResponseFrame)) -> Result<(), Error> {
        if let Some(validation) = self.get(&pathway) {
            validation.recv_frame(frame)?;
        }
        Ok(())
    }
}
