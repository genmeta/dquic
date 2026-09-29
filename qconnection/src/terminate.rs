//! Closing and Draining state for a connection.
use std::{
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
    time::Duration,
};

use qbase::{
    error::{ErrorKind, QuicError},
    frame::{ConnectionCloseFrame, Frame},
    net::tx::ArcSendWakers,
    packet::{ConstraintBuffer, Package, Type},
};
use tokio::time::Instant;

use crate::{CloseReason, Error};

/// Owns the monotonic Normal -> Closing/Draining -> Terminated state machine.
#[derive(Debug)]
pub(crate) enum Terminator {
    NoError(ArcSendWakers),
    Closing {
        send_wakers: ArcSendWakers,
        sync_ccf: bool,
        sent_ccf: bool,
        frame: ConnectionCloseFrame,
        rcvd_packets: u8,
        close_at: Instant,
        last_sent: Instant,
        duration: Duration,
    },
    Draining {
        frame: ConnectionCloseFrame,
        sent_ccf: bool,
        drain_at: Instant,
        duration: Duration,
    },
    Terminated(Error),
}

impl Terminator {
    fn no_error() -> Self {
        Self::NoError(ArcSendWakers::default())
    }

    fn on_error(&mut self, reason: &CloseReason, duration: Duration) {
        let now = Instant::now();
        match self {
            Self::NoError(wakers) => {
                wakers.wake_all();
                match reason {
                    CloseReason::Peer(frame) => {
                        *self = Self::Draining {
                            frame: frame.clone(),
                            sent_ccf: false,
                            drain_at: now,
                            duration: duration,
                        }
                    }
                    CloseReason::App(error) => {
                        *self = Self::Closing {
                            send_wakers: wakers.clone(),
                            sync_ccf: true,
                            sent_ccf: false,
                            frame: ConnectionCloseFrame::from(Error::from(error.clone())),
                            rcvd_packets: 0,
                            close_at: now,
                            last_sent: now,
                            duration,
                        }
                    }
                    CloseReason::Internal(error) => {
                        *self = Self::Closing {
                            send_wakers: wakers.clone(),
                            sync_ccf: true,
                            sent_ccf: false,
                            frame: ConnectionCloseFrame::from(Error::from(error.clone())),
                            rcvd_packets: 0,
                            close_at: now,
                            last_sent: now,
                            duration,
                        }
                    }
                };
            }
            _ => (),
        }
    }

    fn poll_dump<B: bytes::BufMut + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ConstraintBuffer<'_, B>,
        frames: &mut Vec<Frame>,
    ) -> Poll<Result<usize, Error>> {
        let mut dump_ccf = |frame: &ConnectionCloseFrame, buffer: &mut ConstraintBuffer<'_, B>| {
            let mut frame = match (buffer.packet_type, frame) {
                (Type::Long(_), ConnectionCloseFrame::App(frame)) => {
                    ConnectionCloseFrame::Quic(frame.conceal())
                }
                (_, frame) => frame.clone(),
            };
            frame.poll_dump(cx, buffer, frames)
        };
        match self {
            Self::NoError(send_wakers) => {
                send_wakers.register(cx.waker());
                Poll::Pending
            }
            Self::Closing {
                send_wakers,
                sync_ccf,
                sent_ccf,
                frame,
                ..
            } => {
                if *sync_ccf {
                    let result = dump_ccf(frame, buffer);
                    if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
                        *sync_ccf = false;
                        *sent_ccf = true;
                    }
                    result
                } else {
                    buffer.limits.set_max_size(0);
                    send_wakers.register(cx.waker());
                    Poll::Pending
                }
            }
            Self::Draining {
                frame, sent_ccf, ..
            } => {
                if !*sent_ccf {
                    let result = dump_ccf(frame, buffer);
                    if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
                        *sent_ccf = true;
                    }
                    result
                } else {
                    Poll::Ready(Ok(0))
                }
            }
            Self::Terminated(error) => Poll::Ready(Err(error.clone())),
        }
    }

    fn on_rcvd_packet(&mut self, now: Instant) {
        match self {
            Self::Closing {
                send_wakers,
                sync_ccf,
                rcvd_packets,
                last_sent,
                duration,
                ..
            } => {
                *rcvd_packets = rcvd_packets.saturating_add(1);
                let time_due = now.saturating_duration_since(*last_sent) >= *duration / 3;
                if !*sync_ccf && (*rcvd_packets >= 5 || time_due) {
                    *sync_ccf = true;
                    *rcvd_packets = 0;
                    *last_sent = now;
                    send_wakers.wake_all();
                }
            }
            _ => (),
        }
    }

    fn on_rcvd_connection_close_frame(&mut self, frame: ConnectionCloseFrame, duration: Duration) {
        let now = Instant::now();
        match self {
            Self::NoError(wakers) => {
                wakers.wake_all();
                *self = Self::Draining {
                    frame,
                    sent_ccf: false,
                    drain_at: now,
                    duration,
                }
            }
            Terminator::Closing {
                send_wakers,
                sent_ccf,
                close_at,
                duration,
                ..
            } => {
                if !*sent_ccf {
                    send_wakers.wake_all();
                }
                *self = Self::Draining {
                    frame,
                    sent_ccf: *sent_ccf,
                    drain_at: now,
                    duration: *close_at + *duration - now,
                }
            }
            _ => (),
        }
    }

    fn terminate(&mut self) {
        match self {
            Self::NoError(wakers) => {
                wakers.wake_all();
                *self = Self::Terminated(
                    QuicError::with_default_fty(ErrorKind::None, "connection terminated").into(),
                );
            }
            Self::Closing {
                send_wakers, frame, ..
            } => {
                send_wakers.wake_all();
                *self = Self::Terminated(frame.clone().into());
            }
            Self::Draining { frame, .. } => {
                *self = Self::Terminated(frame.clone().into());
            }
            _ => (),
        }
    }

    fn deadline(&self) -> Option<Instant> {
        match self {
            Self::Closing {
                close_at, duration, ..
            } => Some(*close_at + *duration),
            Self::Draining {
                drain_at, duration, ..
            } => Some(*drain_at + *duration),
            Self::Terminated(_) => None,
            Self::NoError(_) => unreachable!("wait requires Closing or Draining"),
        }
    }
}

#[derive(Clone)]
pub struct ArcTerminator(Arc<Mutex<Terminator>>);

impl ArcTerminator {
    pub(crate) fn no_error() -> Self {
        Self(Arc::new(Mutex::new(Terminator::no_error())))
    }

    pub(crate) fn lock_guard(&self) -> MutexGuard<'_, Terminator> {
        self.0.lock().unwrap()
    }

    /// Start local Closing, or preserve an earlier peer-initiated Draining state.
    pub(crate) fn on_error(&self, reason: &CloseReason, duration: Duration) {
        self.lock_guard().on_error(reason, duration);
    }

    /// Count one authenticated packet. Only Closing schedules another CLOSE response.
    pub(crate) fn on_rcvd_packet(&self, now: Instant) {
        self.lock_guard().on_rcvd_packet(now);
    }

    /// A peer CLOSE enters Draining. Direct entry keeps one frame to synchronize the peer;
    /// a connection that was already Closing discards any pending CLOSE response.
    pub(crate) fn on_rcvd_connection_close_frame(
        &self,
        frame: ConnectionCloseFrame,
        duration: Duration,
    ) {
        self.lock_guard()
            .on_rcvd_connection_close_frame(frame, duration);
    }

    pub(crate) fn terminate(&self) {
        self.lock_guard().terminate();
    }

    /// Wait for the deadline of the state observed by this sole waiter.
    pub(crate) async fn wait(&self) {
        if let Some(deadline) = { self.lock_guard().deadline() } {
            tokio::time::sleep_until(deadline).await;
        }
        self.terminate();
    }
}

impl<B: bytes::BufMut + ?Sized> Package<B> for &ArcTerminator {
    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ConstraintBuffer<'_, B>,
        frames: &mut Vec<Frame>,
    ) -> Poll<Result<usize, Error>> {
        self.lock_guard().poll_dump(cx, buffer, frames)
    }

    fn cancel(&mut self, waker: &Waker) {
        match &*self.lock_guard() {
            Terminator::NoError(send_wakers) | Terminator::Closing { send_wakers, .. } => {
                send_wakers.cancel(waker);
            }
            Terminator::Draining { .. } | Terminator::Terminated(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        task::{Context, Poll, Waker},
        time::Duration,
    };

    use qbase::{
        error::{ErrorKind, QuicError},
        frame::{ConnectionCloseFrame, Frame},
        packet::{ConstraintBuffer, Constraints, GetType, Limit, OneRttHeader, Package},
    };
    use tokio::time::Instant;

    use super::{ArcTerminator, Terminator};
    use crate::{CloseReason, Error};

    fn close_frame(reason: &'static str) -> ConnectionCloseFrame {
        ConnectionCloseFrame::from(Error::from(QuicError::with_default_fty(
            ErrorKind::Internal,
            reason,
        )))
    }

    fn local_reason() -> CloseReason {
        CloseReason::Internal(QuicError::with_default_fty(ErrorKind::Internal, "local"))
    }

    fn poll_close(terminator: &ArcTerminator, waker: &Waker) -> Poll<Result<usize, Error>> {
        let mut limits = Constraints {
            send_quota: 2400,
            credit: 2400,
            max_size: 1200,
            ..Default::default()
        };
        let mut bytes = bytes::BytesMut::new();
        let mut frames = Vec::new();
        let mut buffer = ConstraintBuffer::new(
            &mut bytes,
            &mut limits,
            OneRttHeader::new(Default::default(), Default::default()).get_type(),
            0,
            0,
        );
        (&*terminator).poll_dump(&mut Context::from_waker(waker), &mut buffer, &mut frames)
    }

    #[test]
    fn draining_writes_one_close_and_never_schedules_another() {
        for via_error in [false, true] {
            let terminator = ArcTerminator::no_error();
            let frame = close_frame("peer");
            let duration = Duration::from_secs(3);
            if via_error {
                terminator.on_error(&CloseReason::Peer(frame.clone()), duration);
            } else {
                terminator.on_rcvd_connection_close_frame(frame.clone(), duration);
            }
            // Insufficient space must not consume the one permitted response.
            for (max_size, expected) in [(1, 0), (1200, 1), (1200, 0)] {
                let mut limits = Constraints {
                    send_quota: 2400,
                    credit: 2400,
                    max_size,
                    ..Default::default()
                };
                let mut bytes = bytes::BytesMut::new();
                let mut frames = Vec::new();
                let mut buffer = ConstraintBuffer::new(
                    &mut bytes,
                    &mut limits,
                    OneRttHeader::new(Default::default(), Default::default()).get_type(),
                    0,
                    0,
                );
                assert!(matches!(
                    (&terminator).poll_dump(
                        &mut Context::from_waker(Waker::noop()),
                        &mut buffer,
                        &mut frames,
                    ),
                    Poll::Ready(Ok(n)) if n == expected
                ));
                if expected == 1 {
                    assert!(matches!(frames.as_slice(), [Frame::Close(sent)] if sent == &frame));
                    assert!(!bytes.is_empty());
                } else {
                    assert!(frames.is_empty());
                    assert!(bytes.is_empty());
                    assert_eq!(limits.max_size(), max_size);
                }
                terminator.on_rcvd_packet(Instant::now() + duration);
                terminator.on_rcvd_connection_close_frame(close_frame("again"), duration);
            }
        }
    }

    #[test]
    fn closing_without_a_written_frame_preserves_send_budget() {
        for (pending, overhead) in [(false, 0), (true, 0), (false, 40), (true, 40)] {
            let terminator = ArcTerminator::no_error();
            terminator.on_error(&local_reason(), Duration::from_secs(3));
            if pending {
                assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
            }
            let mut limits = Constraints {
                flow_ctrl: 0,
                send_quota: 2400,
                credit: 2400,
                min_size: 0,
                max_size: 1 + overhead,
                overhead,
                ..Default::default()
            };
            let mut bytes = bytes::BytesMut::new();
            let mut frames = Vec::new();
            let mut buffer = ConstraintBuffer::new(
                &mut bytes,
                &mut limits,
                OneRttHeader::new(Default::default(), Default::default()).get_type(),
                0,
                0,
            );
            let result = (&terminator).poll_dump(
                &mut Context::from_waker(Waker::noop()),
                &mut buffer,
                &mut frames,
            );
            if pending {
                assert!(result.is_pending());
            } else {
                assert!(matches!(result, Poll::Ready(Ok(0))));
                assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
            }
            assert!(frames.is_empty());
            assert_eq!(limits.send_quota, 2400);
            assert_eq!(limits.credit, 2400);
            assert_eq!(limits.max_size(), usize::from(!pending));
        }
    }

    #[test]
    fn closing_sends_immediately_and_again_after_five_packets() {
        let terminator = ArcTerminator::no_error();
        let duration = Duration::from_secs(3);
        terminator.on_error(&local_reason(), duration);
        assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));

        for _ in 0..4 {
            terminator.on_rcvd_packet(Instant::now());
            assert!(poll_close(&terminator, Waker::noop()).is_pending());
        }
        terminator.on_rcvd_packet(Instant::now());
        assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
    }

    #[test]
    fn closing_sends_again_when_a_later_packet_crosses_the_time_threshold() {
        let terminator = ArcTerminator::no_error();
        let duration = Duration::from_secs(3);
        terminator.on_error(&local_reason(), duration);
        assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
        let sent_at = Instant::now();
        terminator.on_rcvd_packet(sent_at + Duration::from_secs(1));
        assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
    }

    #[test]
    fn peer_close_during_closing_discards_the_local_close() {
        for sent in [false, true] {
            let terminator = ArcTerminator::no_error();
            terminator.on_error(&local_reason(), Duration::from_secs(3));
            if sent {
                assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
            }
            terminator.on_rcvd_connection_close_frame(close_frame("peer"), Duration::from_secs(3));
            if !sent {
                assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
            }
            assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(0)));
        }
    }

    #[test]
    fn pending_senders_are_woken_and_can_cancel_in_normal_and_closing() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        #[derive(Default)]
        struct Counter(AtomicUsize);
        impl std::task::Wake for Counter {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        for closing in [false, true] {
            for cancel in [false, true] {
                for draining in [false, true] {
                    let terminator = ArcTerminator::no_error();
                    let counter = Arc::new(Counter::default());
                    let waker = Waker::from(counter.clone());
                    assert!(poll_close(&terminator, &waker).is_pending());
                    if closing {
                        terminator.on_error(&local_reason(), Duration::from_secs(3));
                        assert_eq!(counter.0.swap(0, Ordering::Relaxed), 1);
                        assert_eq!(poll_close(&terminator, &waker), Poll::Ready(Ok(1)));
                        assert!(poll_close(&terminator, &waker).is_pending());
                    }
                    if cancel {
                        <&ArcTerminator as Package<bytes::BytesMut>>::cancel(
                            &mut &terminator,
                            &waker,
                        );
                    }
                    if draining {
                        terminator.on_rcvd_connection_close_frame(
                            close_frame("peer"),
                            Duration::from_secs(3),
                        );
                        assert_eq!(
                            poll_close(&terminator, &waker),
                            Poll::Ready(Ok(usize::from(!closing)))
                        );
                        assert_eq!(poll_close(&terminator, &waker), Poll::Ready(Ok(0)));
                    }
                    terminator.terminate();
                    assert_eq!(
                        counter.0.load(Ordering::Relaxed),
                        usize::from(!cancel && !(closing && draining))
                    );
                    assert!(matches!(
                        poll_close(&terminator, &waker),
                        Poll::Ready(Err(_))
                    ));
                }
            }
        }
    }

    #[test]
    fn terminated_returns_its_stored_error() {
        let terminator = ArcTerminator::no_error();
        let error = Error::from(close_frame("terminated"));
        *terminator.lock_guard() = Terminator::Terminated(error.clone());
        terminator.terminate();
        terminator.on_error(&local_reason(), Duration::from_secs(3));
        terminator.on_rcvd_connection_close_frame(close_frame("peer"), Duration::from_secs(3));
        assert_eq!(
            poll_close(&terminator, Waker::noop()),
            Poll::Ready(Err(error))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn wait_uses_the_initial_deadline_without_a_notification() {
        let terminator = ArcTerminator::no_error();
        let duration = Duration::from_secs(30);
        terminator.on_error(&local_reason(), duration);
        let waiter = tokio::spawn({
            let terminator = terminator.clone();
            async move { terminator.wait().await }
        });

        tokio::time::advance(Duration::from_secs(10)).await;
        terminator.on_rcvd_connection_close_frame(close_frame("peer"), duration);
        tokio::time::advance(Duration::from_secs(20)).await;
        waiter.await.unwrap();
        assert!(matches!(
            &*terminator.lock_guard(),
            Terminator::Terminated(_)
        ));
    }
}
