use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};

use crate::{
    error::{Error, ErrorKind, QuicError},
    frame::{
        HandshakeDoneFrame,
        io::{ReceiveFrame, SendFrame},
    },
    role::Role,
};

/// Client handshake confirmation, with at most one pending waiter.
#[derive(Debug, Default)]
pub enum ClientHandshakeDone {
    #[default]
    Pending,
    Waiting(Waker),
    Done,
}

impl ClientHandshakeDone {
    /// Check if the client handshake is confirmed.
    pub fn is_handshake_done(&self) -> bool {
        matches!(self, Self::Done)
    }

    /// Wait for HANDSHAKE_DONE, replacing the registered waker on a subsequent poll.
    /// Once confirmed, every poll returns success.
    pub fn poll_done(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        match self {
            Self::Pending => {
                *self = Self::Waiting(cx.waker().clone());
                Poll::Pending
            }
            Self::Waiting(waker) => {
                waker.clone_from(cx.waker());
                Poll::Pending
            }
            Self::Done => Poll::Ready(()),
        }
    }

    /// Receive the HANDSHAKE_DONE frame.
    ///
    /// Once the client receives the HANDSHAKE_DONE frame,
    /// it confirms the client handshake and wakes its waiter.
    ///
    /// Return whether it is the first time to receive the HANDSHAKE_DONE frame.
    pub fn recv_handshake_done_frame(&mut self, _frame: HandshakeDoneFrame) -> bool {
        match std::mem::replace(self, Self::Done) {
            Self::Pending => true,
            Self::Waiting(waker) => {
                waker.wake();
                true
            }
            Self::Done => false,
        }
    }
}

/// Server's handshake status.
///
/// - `T` is responsible for reliably sending [`HandshakeDoneFrame`] to the client.
///   It can be a channel, a queue, or a buffer. Whatever, it must be able to send the
///   [`HandshakeDoneFrame`] to the client.
///
/// The server considers the handshake complete only after receiving
/// the [finished message](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.4)
/// from the client during the TLS handshake process.
/// Once TLS reports handshake completion, the server considers the handshake
/// confirmed and sends a [`HandshakeDoneFrame`] immediately.
#[derive(Debug, Clone)]
pub struct ServerHandshakeDone<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    is_done: Arc<AtomicBool>,
    output: T,
}

impl<T> ServerHandshakeDone<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    /// Create a new server handshake signal.
    ///
    /// The `output` is responsible for sending the [`HandshakeDoneFrame`] to the client,
    /// see [`ServerHandshakeDone`].
    pub fn new(output: T) -> Self {
        ServerHandshakeDone { is_done: Arc::new(AtomicBool::new(false)), output }
    }

    /// Check if the server handshake is complete.
    pub fn is_handshake_done(&self) -> bool {
        self.is_done.load(Ordering::Acquire)
    }

    /// Actively set the server's handshake status to complete.
    ///
    /// Call this method when the TLS handshake
    /// [finished message](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.4) is received.
    /// Servers MUST NOT send a [`HandshakeDoneFrame`] before completing the handshake.
    /// and once the server handshake is complete,
    /// servers should send the [`HandshakeDoneFrame`] immediately.
    /// See [`ServerHandshakeDone`].
    ///
    /// This method return [`true`] when it first time set the handshake status to complete.
    pub fn done(&self) -> bool {
        if self.is_done.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            self.output.send_frame([HandshakeDoneFrame]);
            true
        } else {
            false
        }
    }
}

/// A merged handshake state that can be used by both the client and the server.
///
/// Use [`ArcHandshakeDone`] to share this state and await client confirmation.
#[derive(Debug)]
pub enum HandshakeDone<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    /// The client's handshake state if the endpoint is a client.
    Client(ClientHandshakeDone),
    /// The server's handshake state if the endpoint is a server.
    Server(ServerHandshakeDone<T>),
}

impl<T> HandshakeDone<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    /// Create a new handshake state, based on the role.
    pub fn new(role: Role, output: T) -> Self {
        match role {
            Role::Client => HandshakeDone::Client(ClientHandshakeDone::default()),
            Role::Server => HandshakeDone::Server(ServerHandshakeDone::new(output)),
        }
    }

    /// Create a new client handshake state.
    pub fn new_client() -> Self {
        HandshakeDone::Client(ClientHandshakeDone::default())
    }

    /// Create a new server handshake state.
    /// The `output` is responsible for sending the [`HandshakeDoneFrame`] to the client,
    /// see [`ServerHandshakeDone::new`].
    pub fn new_server(output: T) -> Self {
        HandshakeDone::Server(ServerHandshakeDone::new(output))
    }

    /// Check if the handshake is complete.
    pub fn is_handshake_done(&self) -> bool {
        match self {
            HandshakeDone::Client(h) => h.is_handshake_done(),
            HandshakeDone::Server(h) => h.is_handshake_done(),
        }
    }

    /// Set the handshake status to complete(for server)
    ///
    /// For client, this method does nothing and always returns [`false`].
    ///
    /// This method return [`true`] when it first time set the handshake status to complete.
    pub fn done(&self) -> bool {
        match self {
            HandshakeDone::Client(..) => false, /* for client, do nothing */
            HandshakeDone::Server(h) => h.done(),
        }
    }

    /// Return the role of this handshake signal.
    pub fn role(&self) -> Role {
        match self {
            HandshakeDone::Client(_) => Role::Client,
            HandshakeDone::Server(_) => Role::Server,
        }
    }
}

/// Shared handshake state. Only one task may wait for client confirmation at a time.
/// Waiting on the server panics.
#[derive(Debug, Clone)]
pub struct ArcHandshakeDone<T>(Arc<Mutex<HandshakeDone<T>>>)
where
    T: SendFrame<HandshakeDoneFrame> + Clone;

impl<T> ArcHandshakeDone<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    pub fn new(role: Role, output: T) -> Self {
        Self(Arc::new(Mutex::new(HandshakeDone::new(role, output))))
    }

    pub fn new_client() -> Self {
        Self(Arc::new(Mutex::new(HandshakeDone::new_client())))
    }

    pub fn new_server(output: T) -> Self {
        Self(Arc::new(Mutex::new(HandshakeDone::new_server(output))))
    }

    pub fn is_handshake_done(&self) -> bool {
        self.0.lock().unwrap().is_handshake_done()
    }

    /// Confirm the server handshake and queue HANDSHAKE_DONE once.
    pub fn done(&self) -> bool {
        self.0.lock().unwrap().done()
    }

    pub fn role(&self) -> Role {
        self.0.lock().unwrap().role()
    }
}

impl<T> Future for ArcHandshakeDone<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self.0.lock().unwrap() {
            HandshakeDone::Client(handshake) => handshake.poll_done(cx),
            HandshakeDone::Server(_) => {
                unreachable!("server handshake confirmation cannot be awaited",)
            }
        }
    }
}

impl<T> ReceiveFrame<HandshakeDoneFrame> for ArcHandshakeDone<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    type Output = bool;

    /// Receive the [`HandshakeDoneFrame`].
    ///
    /// A [`HandshakeDoneFrame`] can only be received by the client.
    /// A server MUST treat receipt of a [`HandshakeDoneFrame`]
    /// as a connection error of type PROTOCOL_VIOLATION.
    /// See [section 19.20](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.20)
    /// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html).
    ///
    /// Return whether it is the first time to receive the HANDSHAKE_DONE frame(for client).
    fn recv_frame(&self, frame: HandshakeDoneFrame) -> Result<bool, Error> {
        match &mut *self.0.lock().unwrap() {
            HandshakeDone::Client(h) => Ok(h.recv_handshake_done_frame(frame)),
            _ => Err(QuicError::with_default_fty(ErrorKind::ProtocolViolation, "Server received a HANDSHAKE_DONE frame").into()),
        }
    }
}
