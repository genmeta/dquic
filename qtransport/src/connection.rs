use std::{future::poll_fn, sync::Arc};

use bytes::Bytes;
use qbase::{
    ArcReceiving,
    error::{AppError, QuicError},
    frame::ConnectionCloseFrame,
    param::ParameterId,
};

use crate::{
    ArcParameters, Error, Role, StreamId, StreamReader, StreamWriter, VarInt, transport::Transport,
};

/// The source of a connection's first close request. qconn drives its lifecycle.
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

/// A successfully handshaken QUIC connection. Clones share stream queues and lifetime.
/// Keep one handle alive while using detached stream readers and writers.
#[derive(Clone)]
pub struct ArcConnection(Arc<Connection>);

struct Connection {
    alpn: Bytes,
    transport: Arc<Transport>,
    close: ArcReceiving<CloseReason>,
}

impl ArcConnection {
    /// Integration only: TLS and parameters are authenticated; qconn awaits the shared close signal.
    #[doc(hidden)]
    pub fn new(transport: Arc<Transport>, alpn: Bytes, close: ArcReceiving<CloseReason>) -> Self {
        Self(Arc::new(Connection {
            alpn,
            transport,
            close,
        }))
    }

    pub fn role(&self) -> Role {
        self.parameters().role()
    }
    pub fn alpn(&self) -> &[u8] {
        &self.0.alpn
    }
    pub fn parameters(&self) -> &ArcParameters {
        &self.0.transport.parameters
    }

    /// Wait for stream credit; None means the stream-number space is exhausted.
    pub async fn open_bi_stream(
        &self,
    ) -> Result<Option<(StreamId, (StreamReader, StreamWriter))>, Error> {
        let window = self
            .parameters()
            .remote(ParameterId::InitialMaxStreamDataBidiRemote)
            .unwrap();
        poll_fn(|cx| self.0.transport.streams.poll_open_bi_with_limit(cx, window)).await
    }
    pub async fn open_uni_stream(&self) -> Result<Option<(StreamId, StreamWriter)>, Error> {
        let window = self
            .parameters()
            .remote(ParameterId::InitialMaxStreamDataUni)
            .unwrap();
        poll_fn(|cx| {
            self.0
                .transport
                .streams
                .poll_open_uni_with_limit(cx, window)
        })
        .await
    }
    /// Use one accept loop per direction. Cancellation does not consume a stream.
    pub async fn accept_bi_stream(
        &self,
    ) -> Result<(StreamId, (StreamReader, StreamWriter)), Error> {
        let window = self
            .parameters()
            .remote(ParameterId::InitialMaxStreamDataBidiLocal)
            .unwrap();
        poll_fn(|cx| {
            self.0
                .transport
                .streams
                .poll_accept_bi_with_limit(cx, window)
        })
        .await
    }
    pub async fn accept_uni_stream(&self) -> Result<(StreamId, StreamReader), Error> {
        self.0.transport.streams.accept_uni().await
    }
    /// Stop all clones and streams immediately; qconn completes Closing/Draining.
    pub fn close(self, code: VarInt, reason: &str) {
        self.0.close(AppError::new(code, reason.to_owned()));
    }
}

impl Connection {
    fn close(&self, error: AppError) {
        self.transport.close(error.clone().into());
        self.close.obtain(CloseReason::App(error));
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.close(AppError::new(
            VarInt::from_u32(0),
            "last connection handle dropped",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn explicit_close_wakes_the_driver_and_preserves_the_first_reason() {
        let [(connection, _, _), _] = crate::tests::pair(1);
        let mut close = connection.0.close.clone();
        assert!(futures::poll!(&mut close).is_pending());
        connection.clone().close(42u32.into(), "first");
        connection.close(99u32.into(), "later");
        let CloseReason::App(error) = close.clone().await.unwrap().unwrap() else {
            panic!("expected application close");
        };
        assert_eq!(error, AppError::new(42u32.into(), "first"));
        assert!(close.await.unwrap().is_none());
    }

    #[tokio::test]
    async fn only_the_last_handle_drop_notifies_the_driver() {
        let [(connection, _, _), _] = crate::tests::pair(1);
        let mut close = connection.0.close.clone();
        drop(connection.clone());
        assert!(futures::poll!(&mut close).is_pending());
        drop(connection);
        let CloseReason::App(error) = close.await.unwrap().unwrap() else {
            panic!("expected application close");
        };
        assert_eq!(error.error_code(), 0);
        assert_eq!(error.reason(), "last connection handle dropped");
    }
}
