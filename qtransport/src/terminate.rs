//! Closing and Draining state for a connection.
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use qbase::{
    Close,
    error::{AppError, ErrorKind, QuicError},
    frame::ConnectionCloseFrame,
    net::tx::ArcSendWakers,
    packet::{
        PacketBuffer, Package, Type,
        r#type::long::{Type::V1, Ver1},
    },
    util::Wakers,
};
use tokio::time::Instant;

use crate::Error;

/// The source of a connection's first close request. qconnection drives its lifecycle.
#[derive(Debug, Clone)]
pub enum CloseReason {
    App(AppError),
    Peer(ConnectionCloseFrame),
    Internal(QuicError),
}

impl From<Error> for CloseReason {
    fn from(error: Error) -> Self {
        match error {
            Error::App(error) => Self::App(error),
            Error::Quic(error) => Self::Internal(error),
        }
    }
}

/// Owns the monotonic Normal -> Closing/Draining -> Terminated state machine.
enum Terminator {
    NoError {
        tx_wakers: ArcSendWakers,
        components: Vec<Arc<dyn qbase::Close>>,
        waiters: Arc<Wakers>,
    },
    Closing {
        waiters: Arc<Wakers>,
        tx_wakers: ArcSendWakers,
        sync_ccf: bool,
        sent_ccf: bool,
        error: Error,
        rcvd_packets: u8,
        last_sent: Instant,
        interval: Duration,
    },
    Draining {
        waiters: Arc<Wakers>,
        error: Error,
        sent_ccf: bool,
    },
    Terminated(Error),
}

impl Terminator {
    fn no_error() -> Self {
        Self::NoError {
            tx_wakers: ArcSendWakers::default(),
            components: Vec::new(),
            waiters: Arc::new(Wakers::new()),
        }
    }

    fn close(&mut self, reason: &CloseReason, pto: Duration) -> Option<Duration> {
        let now = Instant::now();
        match self {
            Self::NoError {
                tx_wakers,
                components,
                waiters,
            } => {
                let error: Error = match reason {
                    CloseReason::App(error) => error.clone().into(),
                    CloseReason::Peer(frame) => frame.clone().into(),
                    CloseReason::Internal(error) => error.clone().into(),
                };
                for component in components.iter() {
                    component.close_with_error(error.clone());
                }
                tx_wakers.wake_all();
                match reason {
                    CloseReason::Peer(_) => {
                        *self = Self::Draining {
                            waiters: waiters.clone(),
                            error,
                            sent_ccf: false,
                        }
                    }
                    CloseReason::App(_) | CloseReason::Internal(_) => {
                        *self = Self::Closing {
                            waiters: waiters.clone(),
                            tx_wakers: tx_wakers.clone(),
                            sync_ccf: true,
                            sent_ccf: false,
                            error,
                            rcvd_packets: 0,
                            last_sent: now,
                            interval: pto,
                        }
                    }
                };
                Some(pto)
            }
            _ => None,
        }
    }

    fn poll_dump<B: bytes::BufMut + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut PacketBuffer<'_, B>,
    ) -> Poll<Result<usize, Error>> {
        let mut dump_ccf = |error: &Error, buffer: &mut PacketBuffer<'_, B>| {
            let mut frame = match (buffer.meta.packet_type, error) {
                (Type::Long(V1(Ver1::INITIAL | Ver1::HANDSHAKE)), Error::App(_)) => {
                    // RFC 9000 §10.2.3: conceal application details at these levels.
                    ConnectionCloseFrame::from(Error::from(QuicError::with_default_fty(
                        ErrorKind::Application,
                        "",
                    )))
                }
                (_, error) => ConnectionCloseFrame::from(error.clone()),
            };
            frame.poll_dump(cx, buffer)
        };
        match self {
            Self::NoError { tx_wakers, .. } => {
                tx_wakers.register(cx.waker());
                Poll::Pending
            }
            Self::Closing {
                tx_wakers: send_wakers,
                sync_ccf,
                sent_ccf,
                error,
                ..
            } => {
                if *sync_ccf {
                    let result = dump_ccf(error, buffer);
                    if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
                        *sync_ccf = false;
                        *sent_ccf = true;
                    } else {
                        buffer.limits.set_max_size(0);
                    }
                    result
                } else {
                    buffer.limits.set_max_size(0);
                    send_wakers.register(cx.waker());
                    Poll::Pending
                }
            }
            Self::Draining {
                error, sent_ccf, ..
            } => {
                if !*sent_ccf {
                    let result = dump_ccf(error, buffer);
                    if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
                        *sent_ccf = true;
                    } else {
                        buffer.limits.set_max_size(0);
                    }
                    result
                } else {
                    buffer.limits.set_max_size(0);
                    Poll::Ready(Ok(0))
                }
            }
            Self::Terminated(error) => Poll::Ready(Err(error.clone())),
        }
    }

    fn on_rcvd_packet(&mut self, now: Instant) {
        match self {
            Self::Closing {
                tx_wakers,
                sync_ccf,
                rcvd_packets,
                last_sent,
                interval,
                ..
            } => {
                *rcvd_packets = rcvd_packets.saturating_add(1);
                let time_due = now.saturating_duration_since(*last_sent) >= *interval;
                if !*sync_ccf && (*rcvd_packets >= 5 || time_due) {
                    *sync_ccf = true;
                    *rcvd_packets = 0;
                    *last_sent = now;
                    tx_wakers.wake_all();
                }
            }
            _ => (),
        }
    }

    fn recv_conn_close_frame(&mut self, frame: ConnectionCloseFrame) {
        match self {
            Terminator::Closing {
                waiters,
                tx_wakers: send_wakers,
                sent_ccf,
                ..
            } => {
                if !*sent_ccf {
                    send_wakers.wake_all();
                }
                *self = Self::Draining {
                    waiters: waiters.clone(),
                    error: frame.into(),
                    sent_ccf: *sent_ccf,
                }
            }
            _ => (),
        }
    }

    fn terminate(&mut self) {
        match self {
            Self::NoError { tx_wakers, .. } => {
                tx_wakers.wake_all();
                *self = Self::Terminated(
                    QuicError::with_default_fty(ErrorKind::None, "connection terminated").into(),
                );
            }
            Self::Closing {
                tx_wakers, error, ..
            } => {
                tx_wakers.wake_all();
                *self = Self::Terminated(error.clone());
            }
            Self::Draining { error, .. } => {
                *self = Self::Terminated(error.clone());
            }
            _ => (),
        }
    }

    fn poll_terminate(&mut self, cx: &mut Context<'_>) -> Poll<Error> {
        match self {
            Self::Terminated(error) => Poll::Ready(error.clone()),
            Self::NoError { waiters, .. }
            | Self::Closing { waiters, .. }
            | Self::Draining { waiters, .. } => {
                waiters.add(cx.waker());
                Poll::Pending
            }
        }
    }
}

#[derive(Clone)]
pub struct ArcTerminator(Arc<Mutex<Terminator>>);

impl Default for ArcTerminator {
    fn default() -> Self {
        Self::no_error()
    }
}

impl ArcTerminator {
    pub fn no_error() -> Self {
        Self(Arc::new(Mutex::new(Terminator::no_error())))
    }

    /// Register before publishing a component. Late registrations use the current state error.
    /// Close callbacks must not synchronously reenter this terminator.
    pub fn register(&self, component: Arc<dyn Close>) {
        let error = {
            let mut state = self.0.lock().unwrap();
            match &mut *state {
                Terminator::NoError { components, .. } => {
                    components.push(component);
                    return;
                }
                Terminator::Closing { error, .. }
                | Terminator::Draining { error, .. }
                | Terminator::Terminated(error) => error.clone(),
            }
        };
        component.close_with_error(error);
    }

    /// Request closing once and terminate after three PTOs on the Tokio runtime.
    /// Returns whether this request started closing.
    pub fn close(&self, reason: CloseReason, pto: Duration) -> bool {
        if let Some(pto) = self.0.lock().unwrap().close(&reason, pto) {
            let deadline = Instant::now() + 3 * pto;
            let terminator = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep_until(deadline).await;
                terminator.terminate();
            });
            true
        } else {
            false
        }
    }

    /// Count one authenticated packet. Only Closing schedules another CLOSE response.
    pub fn on_rcvd_packet(&self, now: Instant) {
        self.0.lock().unwrap().on_rcvd_packet(now);
    }

    /// A peer CLOSE enters Draining without extending an existing closing deadline.
    pub fn recv_conn_close_frame(&self, frame: ConnectionCloseFrame, pto: Duration) {
        self.close(CloseReason::Peer(frame.clone()), pto);
        self.0.lock().unwrap().recv_conn_close_frame(frame);
    }

    pub fn terminate(&self) {
        let (error, components, waiters) = {
            let mut state = self.0.lock().unwrap();
            let (components, waiters) = match &mut *state {
                Terminator::NoError {
                    components,
                    waiters,
                    ..
                } => (std::mem::take(components), waiters.clone()),
                Terminator::Closing { waiters, .. } | Terminator::Draining { waiters, .. } => {
                    (Vec::new(), waiters.clone())
                }
                Terminator::Terminated(_) => return,
            };
            state.terminate();
            let Terminator::Terminated(error) = &*state else {
                unreachable!()
            };
            (error.clone(), components, waiters)
        };
        waiters.wake_all();
        for component in components {
            component.close_with_error(error.clone());
        }
    }

    /// Wait for the terminal error without consuming it.
    pub async fn wait(&self) -> Error {
        self.clone().await
    }
}

impl Future for ArcTerminator {
    type Output = Error;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.lock().unwrap().poll_terminate(cx)
    }
}

impl<B: bytes::BufMut + ?Sized> Package<B> for &ArcTerminator {
    fn priority(&self) -> u32 {
        u32::MAX
    }

    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut PacketBuffer<'_, B>,
    ) -> Poll<Result<usize, Error>> {
        self.0.lock().unwrap().poll_dump(cx, buffer)
    }
}
