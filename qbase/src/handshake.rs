use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::{
    error::{Error, ErrorKind, QuicError},
    frame::{
        HandshakeDoneFrame,
        io::{ReceiveFrame, SendFrame},
    },
    role::Role,
};

/// The completion flag for the client handshake.
///
/// The client considers the handshake complete only after
/// receiving the [`HandshakeDoneFrame`] from the server.
/// In the QUIC protocol, there are no tasks that specifically
/// require waiting for the client handshake to complete.
/// Instead, it simply queries the handshake status.
#[derive(Debug, Default, Clone)]
pub struct ClientHandshake {
    done: Arc<AtomicBool>,
}

impl ClientHandshake {
    /// Check if the client handshake is complete.
    pub fn is_handshake_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// Receive the HANDSHAKE_DONE frame.
    ///
    /// Once the client receives the HANDSHAKE_DONE frame,
    /// it marks the completion of the client handshake.
    ///
    /// Return whether it is the first time to receive the HANDSHAKE_DONE frame.
    pub fn recv_handshake_done_frame(&self, _frame: HandshakeDoneFrame) -> bool {
        !self.done.swap(true, Ordering::AcqRel)
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
/// If the [finished message](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.4)
/// from the TLS handshake is not received,
/// the server can also consider the handshake complete upon receiving and
/// successfully decrypting the client's 1-RTT packet.
/// Once the server's handshake is complete, the server will send a [`HandshakeDoneFrame`] immediately.
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
    /// If the TLS handshake completion message is not received,
    /// receiving and successfully decrypting the client's 1-RTT packet
    /// is also considered handshake completion.
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
/// For convenience, a unified [`Handshake`]` should be used,
/// which will internally choose the corresponding behavior based on the role.
#[derive(Debug, Clone)]
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

impl<T> ReceiveFrame<HandshakeDoneFrame> for Handshake<T>
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
        match self {
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
    use std::sync::Mutex;

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

    #[test]
    fn test_client_handshake() {
        let handshake = Handshake::<HandshakeDoneFrameTx>::new_client();
        assert!(!handshake.is_handshake_done());

        let ret = handshake.recv_frame(HandshakeDoneFrame);
        assert!(ret.is_ok());
        assert!(handshake.is_handshake_done());
    }

    #[test]
    fn test_client_handshake_done() {
        let handshake = Handshake::<HandshakeDoneFrameTx>::new_client();
        assert!(!handshake.is_handshake_done());

        assert!(handshake.recv_frame(HandshakeDoneFrame).unwrap());
        assert!(handshake.is_handshake_done());

        // recv_frame will only return `true` once when handshake first done
        assert!(!handshake.recv_frame(HandshakeDoneFrame).unwrap());
        assert!(handshake.is_handshake_done());
    }

    #[test]
    fn test_server_handshake() {
        let handshake = Handshake::new_server(HandshakeDoneFrameTx::default());
        assert!(!handshake.is_handshake_done());

        assert!(handshake.done());
        assert!(handshake.is_handshake_done());

        // same as last test
        assert!(!handshake.done());
        assert!(handshake.is_handshake_done());
    }

    #[test]
    fn test_server_recv_handshake_done_frame() {
        let handshake = Handshake::new_server(HandshakeDoneFrameTx::default());
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
