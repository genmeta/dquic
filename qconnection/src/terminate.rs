//! Closing and Draining state for a connection.
use std::{
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
    time::Duration,
};

use qbase::{
    frame::{ConnectionCloseFrame, Frame},
    net::tx::ArcSendWakers,
    packet::{ConstraintBuffer, Package, Type},
};
use tokio::time::Instant;

use crate::{CloseReason, Error};

#[derive(Debug)]
pub(crate) enum State {
    Normal,
    Closing {
        frame: ConnectionCloseFrame,
        rcvd_packets: u8,
        close_at: Instant,
        last_sent: Instant,
        duration: Duration,
    },
    Draining {
        drain_at: Instant,
        duration: Duration,
    },
    Terminated,
}

/// Owns the monotonic Normal -> Closing/Draining -> Terminated state machine.
pub(crate) struct Terminator {
    pub(crate) state: State,
    sync_msg: Option<ConnectionCloseFrame>,
    send_wakers: ArcSendWakers,
}

#[derive(Clone)]
pub struct ArcTerminator(Arc<Mutex<Terminator>>);

impl ArcTerminator {
    pub(crate) fn normal() -> Self {
        Self(Arc::new(Mutex::new(Terminator {
            state: State::Normal,
            sync_msg: None,
            send_wakers: ArcSendWakers::default(),
        })))
    }

    pub(crate) fn lock_guard(&self) -> MutexGuard<'_, Terminator> {
        self.0.lock().unwrap()
    }

    /// Start local Closing, or preserve an earlier peer-initiated Draining state.
    pub(crate) fn on_error(&self, reason: &CloseReason, duration: Duration) {
        let now = Instant::now();
        let mut terminator = self.lock_guard();
        if !matches!(terminator.state, State::Normal) {
            return;
        }
        match reason {
            CloseReason::Peer(frame) => {
                terminator.sync_msg = Some(frame.clone());
                terminator.state = State::Draining {
                    drain_at: now,
                    duration,
                };
            }
            CloseReason::App(error) => {
                let frame = ConnectionCloseFrame::from(Error::from(error.clone()));
                terminator.sync_msg = Some(frame.clone());
                terminator.state = State::Closing {
                    frame,
                    rcvd_packets: 0,
                    close_at: now,
                    last_sent: now,
                    duration,
                };
            }
            CloseReason::Internal(error) => {
                let frame = ConnectionCloseFrame::from(Error::from(error.clone()));
                terminator.sync_msg = Some(frame.clone());
                terminator.state = State::Closing {
                    frame,
                    rcvd_packets: 0,
                    close_at: now,
                    last_sent: now,
                    duration,
                };
            }
        }
        let send_wakers = terminator.send_wakers.clone();
        drop(terminator);
        send_wakers.wake_all();
    }

    /// Count one authenticated packet. Only Closing schedules another CLOSE response.
    pub(crate) fn on_rcvd_packet(&self, now: Instant) {
        let mut terminator = self.lock_guard();
        let sync_idle = terminator.sync_msg.is_none();
        let mut scheduled = None;
        if let State::Closing {
            frame,
            rcvd_packets,
            last_sent,
            duration,
            ..
        } = &mut terminator.state
        {
            *rcvd_packets = rcvd_packets.saturating_add(1);
            let time_due = now.saturating_duration_since(*last_sent) >= *duration / 3;
            if sync_idle && (*rcvd_packets >= 5 || time_due) {
                scheduled = Some(frame.clone());
                *rcvd_packets = 0;
                *last_sent = now;
            }
        }
        if let Some(frame) = scheduled {
            terminator.sync_msg = Some(frame);
            let send_wakers = terminator.send_wakers.clone();
            drop(terminator);
            send_wakers.wake_all();
        }
    }

    /// A peer CLOSE enters Draining. Direct entry keeps one frame to synchronize the peer;
    /// a connection that was already Closing has already sent its own CLOSE.
    pub(crate) fn on_rcvd_close_connection_frame(
        &self,
        frame: ConnectionCloseFrame,
        duration: Duration,
    ) {
        let now = Instant::now();
        let mut terminator = self.lock_guard();
        match terminator.state {
            State::Normal => {
                terminator.sync_msg = Some(frame);
                terminator.state = State::Draining {
                    drain_at: now,
                    duration,
                };
            }
            State::Closing { .. } => {
                terminator.sync_msg = None;
                terminator.state = State::Draining {
                    drain_at: now,
                    duration,
                };
            }
            State::Draining { .. } | State::Terminated => return,
        }
        let send_wakers = terminator.send_wakers.clone();
        drop(terminator);
        send_wakers.wake_all();
    }

    pub(crate) fn terminate(&self) {
        let mut terminator = self.lock_guard();
        terminator.state = State::Terminated;
        terminator.sync_msg = None;
        let send_wakers = terminator.send_wakers.clone();
        drop(terminator);
        send_wakers.wake_all();
    }

    /// Wait for the deadline of the state observed by this sole waiter.
    pub(crate) async fn wait(&self) {
        let deadline = {
            let terminator = self.lock_guard();
            match terminator.state {
                State::Closing {
                    close_at, duration, ..
                } => close_at + duration,
                State::Draining {
                    drain_at, duration, ..
                } => drain_at + duration,
                State::Terminated => return,
                State::Normal => unreachable!("wait requires Closing or Draining"),
            }
        };
        tokio::time::sleep_until(deadline).await;
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
        let mut terminator = self.lock_guard();
        if matches!(terminator.state, State::Draining { .. } | State::Terminated) {
            return Poll::Ready(Err(qbase::error::QuicError::with_default_fty(
                qbase::error::ErrorKind::None,
                "connection terminated",
            )
            .into()));
        }
        let Some(frame) = &terminator.sync_msg else {
            if matches!(terminator.state, State::Closing { .. }) {
                buffer.limits.set_max_size(0);
            }
            terminator.send_wakers.register(cx.waker());
            return Poll::Pending;
        };
        let mut frame = match (buffer.packet_type, frame) {
            (Type::Long(_), ConnectionCloseFrame::App(frame)) => {
                ConnectionCloseFrame::Quic(frame.conceal())
            }
            (_, frame) => frame.clone(),
        };
        let result = frame.poll_dump(cx, buffer, frames);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            terminator.sync_msg = None;
        } else {
            buffer.limits.set_max_size(0);
        }
        result
    }

    fn cancel(&mut self, waker: &Waker) {
        self.lock_guard().send_wakers.cancel(waker);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use qbase::{
        error::{ErrorKind, QuicError},
        frame::ConnectionCloseFrame,
    };
    use tokio::time::Instant;

    use super::{ArcTerminator, State};
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

    #[test]
    fn closing_without_a_written_frame_preserves_send_budget() {
        use std::task::{Context, Poll, Waker};

        use qbase::packet::{ConstraintBuffer, Constraints, GetType, Limit, OneRttHeader, Package};

        for (pending, overhead) in [(false, 0), (true, 0), (false, 40), (true, 40)] {
            let terminator = ArcTerminator::normal();
            terminator.on_error(&local_reason(), Duration::from_secs(3));
            if pending {
                terminator.lock_guard().sync_msg.take();
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
                assert!(terminator.lock_guard().sync_msg.is_some());
            }
            assert!(frames.is_empty());
            assert_eq!(limits.send_quota, 2400);
            assert_eq!(limits.credit, 2400);
            assert_eq!(limits.max_size(), 0);
        }
    }

    #[test]
    fn closing_sends_immediately_and_again_after_five_packets() {
        let terminator = ArcTerminator::normal();
        let duration = Duration::from_secs(3);
        terminator.on_error(&local_reason(), duration);
        assert!(terminator.lock_guard().sync_msg.take().is_some());

        for _ in 0..4 {
            terminator.on_rcvd_packet(Instant::now());
            assert!(terminator.lock_guard().sync_msg.take().is_none());
        }
        terminator.on_rcvd_packet(Instant::now());
        assert!(terminator.lock_guard().sync_msg.take().is_some());
    }

    #[test]
    fn closing_sends_again_when_a_later_packet_crosses_the_time_threshold() {
        let terminator = ArcTerminator::normal();
        let duration = Duration::from_secs(3);
        terminator.on_error(&local_reason(), duration);
        assert!(terminator.lock_guard().sync_msg.take().is_some());
        let sent_at = Instant::now();
        terminator.on_rcvd_packet(sent_at + Duration::from_secs(1));
        assert!(terminator.lock_guard().sync_msg.take().is_some());
    }

    #[test]
    fn direct_peer_close_enters_draining_with_one_sync_message() {
        let terminator = ArcTerminator::normal();
        let frame = close_frame("peer");
        terminator.on_rcvd_close_connection_frame(frame.clone(), Duration::from_secs(3));
        assert_eq!(terminator.lock_guard().sync_msg.take(), Some(frame));
        assert!(terminator.lock_guard().sync_msg.take().is_none());
    }

    #[test]
    fn peer_close_during_closing_discards_the_local_sync_message() {
        let terminator = ArcTerminator::normal();
        terminator.on_error(&local_reason(), Duration::from_secs(3));
        terminator.on_rcvd_close_connection_frame(close_frame("peer"), Duration::from_secs(3));
        assert!(terminator.lock_guard().sync_msg.take().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn wait_uses_the_initial_deadline_without_a_notification() {
        let terminator = ArcTerminator::normal();
        let duration = Duration::from_secs(30);
        terminator.on_error(&local_reason(), duration);
        let waiter = tokio::spawn({
            let terminator = terminator.clone();
            async move { terminator.wait().await }
        });

        tokio::time::advance(Duration::from_secs(10)).await;
        terminator.on_rcvd_close_connection_frame(close_frame("peer"), duration);
        tokio::time::advance(Duration::from_secs(20)).await;
        waiter.await.unwrap();
        assert!(matches!(&terminator.lock_guard().state, State::Terminated));
    }
}
