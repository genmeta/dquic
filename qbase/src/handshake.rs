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
pub enum ClientHandshake {
    #[default]
    Pending,
    Waiting(Waker),
    Done,
}

impl ClientHandshake {
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
pub struct ServerHandshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    is_done: Arc<AtomicBool>,
    output: T,
}

impl<T> ServerHandshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    /// Create a new server handshake signal.
    ///
    /// The `output` is responsible for sending the [`HandshakeDoneFrame`] to the client,
    /// see [`ServerHandshake`].
    pub fn new(output: T) -> Self {
        ServerHandshake {
            is_done: Arc::new(AtomicBool::new(false)),
            output,
        }
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
    /// See [`ServerHandshake`].
    ///
    /// This method return [`true`] when it first time set the handshake status to complete.
    pub fn done(&self) -> bool {
        if self
            .is_done
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.output.send_frame([HandshakeDoneFrame]);
            true
        } else {
            false
        }
    }
}

/// A merged handshake state that can be used by both the client and the server.
///
/// Use [`ArcHandshake`] to share this state and await client confirmation.
#[derive(Debug)]
pub enum Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    /// The client's handshake state if the endpoint is a client.
    Client(ClientHandshake),
    /// The server's handshake state if the endpoint is a server.
    Server(ServerHandshake<T>),
}

impl<T> Handshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    /// Create a new handshake state, based on the role.
    pub fn new(role: Role, output: T) -> Self {
        match role {
            Role::Client => Handshake::Client(ClientHandshake::default()),
            Role::Server => Handshake::Server(ServerHandshake::new(output)),
        }
    }

    /// Create a new client handshake state.
    pub fn new_client() -> Self {
        Handshake::Client(ClientHandshake::default())
    }

    /// Create a new server handshake state.
    /// The `output` is responsible for sending the [`HandshakeDoneFrame`] to the client,
    /// see [`ServerHandshake::new`].
    pub fn new_server(output: T) -> Self {
        Handshake::Server(ServerHandshake::new(output))
    }

    /// Check if the handshake is complete.
    pub fn is_handshake_done(&self) -> bool {
        match self {
            Handshake::Client(h) => h.is_handshake_done(),
            Handshake::Server(h) => h.is_handshake_done(),
        }
    }

    /// Set the handshake status to complete(for server)
    ///
    /// For client, this method does nothing and always returns [`false`].
    ///
    /// This method return [`true`] when it first time set the handshake status to complete.
    pub fn done(&self) -> bool {
        match self {
            Handshake::Client(..) => false, /* for client, do nothing */
            Handshake::Server(h) => h.done(),
        }
    }

    /// Return the role of this handshake signal.
    pub fn role(&self) -> Role {
        match self {
            Handshake::Client(_) => Role::Client,
            Handshake::Server(_) => Role::Server,
        }
    }
}

/// Shared handshake state. Only one task may wait for client confirmation at a time.
/// Waiting on the server panics.
#[derive(Debug, Clone)]
pub struct ArcHandshake<T>(Arc<Mutex<Handshake<T>>>)
where
    T: SendFrame<HandshakeDoneFrame> + Clone;

impl<T> ArcHandshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    pub fn new(role: Role, output: T) -> Self {
        Self(Arc::new(Mutex::new(Handshake::new(role, output))))
    }

    pub fn new_client() -> Self {
        Self(Arc::new(Mutex::new(Handshake::new_client())))
    }

    pub fn new_server(output: T) -> Self {
        Self(Arc::new(Mutex::new(Handshake::new_server(output))))
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

impl<T> Future for ArcHandshake<T>
where
    T: SendFrame<HandshakeDoneFrame> + Clone,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self.0.lock().unwrap() {
            Handshake::Client(handshake) => handshake.poll_done(cx),
            Handshake::Server(_) => {
                unreachable!("server handshake confirmation cannot be awaited",)
            }
        }
    }
}

impl<T> ReceiveFrame<HandshakeDoneFrame> for ArcHandshake<T>
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
            Handshake::Client(h) => Ok(h.recv_handshake_done_frame(frame)),
            _ => Err(QuicError::with_default_fty(
                ErrorKind::ProtocolViolation,
                "Server received a HANDSHAKE_DONE frame",
            )
            .into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::atomic::AtomicUsize, task::Wake};

    use super::*;
    use crate::{
        error::ErrorKind,
        frame::io::{ReceiveFrame, SendFrame},
    };

    #[derive(Debug, Default, Clone)]
    struct HandshakeDoneFrameTx(Arc<Mutex<Vec<HandshakeDoneFrame>>>);

    impl SendFrame<HandshakeDoneFrame> for HandshakeDoneFrameTx {
        fn send_frame<I: IntoIterator<Item = HandshakeDoneFrame>>(&self, iter: I) {
            self.0.lock().unwrap().extend(iter);
        }
    }

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn client_confirmation_wakes_the_latest_waiter_once() {
        let mut handshake = ArcHandshake::<HandshakeDoneFrameTx>::new_client();
        let receiver = handshake.clone();
        let first = Arc::new(WakeCounter::default());
        let second = Arc::new(WakeCounter::default());
        let first_waker = Waker::from(first.clone());
        let second_waker = Waker::from(second.clone());
        assert!(
            Pin::new(&mut handshake)
                .poll(&mut Context::from_waker(&first_waker))
                .is_pending()
        );
        let mut cx = Context::from_waker(&second_waker);
        assert!(Pin::new(&mut handshake).poll(&mut cx).is_pending());
        assert!(receiver.recv_frame(HandshakeDoneFrame).unwrap());
        assert_eq!(first.0.load(Ordering::Relaxed), 0);
        assert_eq!(second.0.load(Ordering::Relaxed), 1);
        assert!(handshake.is_handshake_done());
        assert!(matches!(
            Pin::new(&mut handshake).poll(&mut cx),
            Poll::Ready(())
        ));
        assert!(!receiver.recv_frame(HandshakeDoneFrame).unwrap());
        assert_eq!(second.0.load(Ordering::Relaxed), 1);
        assert!(matches!(
            Pin::new(&mut handshake).poll(&mut cx),
            Poll::Ready(())
        ));
    }

    #[tokio::test]
    async fn client_confirmation_before_waiting_is_preserved_for_clones() {
        let handshake = ArcHandshake::<HandshakeDoneFrameTx>::new_client();
        assert!(handshake.recv_frame(HandshakeDoneFrame).unwrap());
        handshake.clone().await;
        handshake.await;
    }

    #[test]
    fn client_poll_done_waits_for_confirmation() {
        let mut handshake = ClientHandshake::default();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(handshake.poll_done(&mut cx).is_pending());
        assert!(handshake.recv_handshake_done_frame(HandshakeDoneFrame));
        assert!(matches!(handshake.poll_done(&mut cx), Poll::Ready(())));
    }

    #[tokio::test]
    #[should_panic(expected = "server handshake confirmation cannot be awaited")]
    async fn server_waiting_panics() {
        ArcHandshake::new_server(HandshakeDoneFrameTx::default()).await;
    }

    #[tokio::test]
    #[should_panic(expected = "server handshake confirmation cannot be awaited")]
    async fn server_waiting_after_completion_panics() {
        let output = HandshakeDoneFrameTx::default();
        let handshake = ArcHandshake::new_server(output.clone());
        assert!(handshake.done());
        assert!(!handshake.clone().done());
        assert_eq!(output.0.lock().unwrap().len(), 1);
        handshake.await;
    }

    #[test]
    fn test_client_handshake() {
        let handshake = ArcHandshake::<HandshakeDoneFrameTx>::new_client();
        assert!(!handshake.is_handshake_done());

        let ret = handshake.recv_frame(HandshakeDoneFrame);
        assert!(ret.is_ok());
        assert!(handshake.is_handshake_done());
    }

    #[test]
    fn test_client_handshake_done() {
        let handshake = ArcHandshake::<HandshakeDoneFrameTx>::new_client();
        assert!(!handshake.is_handshake_done());

        assert!(handshake.recv_frame(HandshakeDoneFrame).unwrap());
        assert!(handshake.is_handshake_done());

        // recv_frame will only return `true` once when handshake first done
        assert!(!handshake.recv_frame(HandshakeDoneFrame).unwrap());
        assert!(handshake.is_handshake_done());
    }

    #[test]
    fn test_server_handshake() {
        let handshake = ArcHandshake::new_server(HandshakeDoneFrameTx::default());
        assert!(!handshake.is_handshake_done());

        assert!(handshake.done());
        assert!(handshake.is_handshake_done());

        // same as last test
        assert!(!handshake.done());
        assert!(handshake.is_handshake_done());
    }

    #[test]
    fn test_server_recv_handshake_done_frame() {
        let handshake = ArcHandshake::new_server(HandshakeDoneFrameTx::default());
        assert!(!handshake.is_handshake_done());

        let ret = handshake.recv_frame(HandshakeDoneFrame);
        assert_eq!(
            ret,
            Err(QuicError::with_default_fty(
                ErrorKind::ProtocolViolation,
                "Server received a HANDSHAKE_DONE frame",
            )
            .into())
        );
    }

    #[test]
    fn test_server_send_handshake_done_frame() {
        let handshake = ServerHandshake::new(HandshakeDoneFrameTx::default());
        handshake.done();
        assert!(handshake.is_handshake_done());
        assert_eq!(handshake.output.0.lock().unwrap().len(), 1);
    }
}
