//! Closing and Draining state for a connection.
use std::{
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
    time::Duration,
};

use qbase::{
    error::{ErrorKind, QuicError},
    frame::{ConnectionCloseFrame, Frame},
    net::tx::{ArcSendWakers, UnregisterWaker},
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
}

impl UnregisterWaker for ArcTerminator {
    fn unregister(&self, waker: &Waker) {
        match &*self.lock_guard() {
            Terminator::NoError(send_wakers) | Terminator::Closing { send_wakers, .. } => {
                send_wakers.unregister(waker);
            }
            Terminator::Draining { .. } | Terminator::Terminated(_) => {}
        }
    }
}
