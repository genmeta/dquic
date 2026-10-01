use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use qbase::{
    ArcReceiving,
    error::{AppError, QuicError},
    frame::ConnectionCloseFrame,
    net::route::Pathway,
};
use qrecovery::streams::DataStreams;

use crate::{ArcReliableFrames, Error, StreamId, StreamReader, StreamWriter, VarInt};

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

/// A successfully handshaken QUIC connection. Clones share stream queues and lifetime.
/// Keep one handle alive while using detached stream readers and writers.
#[derive(Clone)]
pub struct ArcConnection(Arc<Connection>);

struct Connection {
    alpn: Bytes,
    streams: DataStreams<ArcReliableFrames>,
    close: ArcReceiving<CloseReason>,
    paths: OnceLock<Box<dyn Fn() -> Vec<Pathway> + Send + Sync>>,
}

impl ArcConnection {
    /// Integration only: TLS and parameters are authenticated; qconnection awaits the shared close signal.
    #[doc(hidden)]
    pub fn new(
        alpn: Bytes,
        streams: DataStreams<ArcReliableFrames>,
        close: ArcReceiving<CloseReason>,
    ) -> Self {
        Self(Arc::new(Connection {
            alpn,
            streams,
            close,
            paths: OnceLock::new(),
        }))
    }

    /// Integration only: attach a read-only view without retaining the lifecycle owner.
    #[doc(hidden)]
    pub fn with_path_observer(
        self,
        paths: impl Fn() -> Vec<Pathway> + Send + Sync + 'static,
    ) -> Self {
        let _ = self.0.paths.set(Box::new(paths));
        self
    }

    /// Snapshot of currently validated paths. Retired and unvalidated paths are excluded.
    pub fn validated_paths(&self) -> Vec<Pathway> {
        self.0
            .paths
            .get()
            .map_or_else(Vec::new, |snapshot| snapshot())
    }

    pub fn alpn(&self) -> &[u8] {
        &self.0.alpn
    }

    /// Wait for stream credit; None means the stream-number space is exhausted.
    pub async fn open_bi_stream(
        &self,
    ) -> Result<Option<(StreamId, (StreamReader, StreamWriter))>, Error> {
        self.0.streams.open_bi().await
    }

    pub async fn open_uni_stream(&self) -> Result<Option<(StreamId, StreamWriter)>, Error> {
        self.0.streams.open_uni().await
    }

    /// Use one accept loop per direction. Cancellation does not consume a stream.
    pub async fn accept_bi_stream(
        &self,
    ) -> Result<(StreamId, (StreamReader, StreamWriter)), Error> {
        self.0.streams.accept_bi().await
    }

    pub async fn accept_uni_stream(&self) -> Result<(StreamId, StreamReader), Error> {
        self.0.streams.accept_uni().await
    }

    /// Stop all clones and streams immediately; qconnection completes Closing/Draining.
    pub fn close(self, code: VarInt, reason: &str) {
        self.0.close(AppError::new(code, reason.to_owned()));
    }
}

impl Connection {
    fn close(&self, error: AppError) {
        self.streams.on_conn_error(&error.clone().into());
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
    async fn connection_keeps_streams_alive_without_retaining_the_data_space() {
        use tokio::io::AsyncWriteExt;

        let [(connection, transport, path), _] = crate::tests::pair(1);
        let data = Arc::downgrade(&transport.data);
        drop(path);
        drop(transport);
        assert!(data.upgrade().is_none());

        let (_, mut writer) = connection.open_uni_stream().await.unwrap().unwrap();
        writer.write_all(b"pending").await.unwrap();
        let close = connection.0.close.clone();
        connection.close(42u32.into(), "stop");
        assert!(writer.flush().await.is_err());
        assert!(matches!(
            close.await.unwrap().unwrap(),
            CloseReason::App(error) if error == AppError::new(42u32.into(), "stop")
        ));
    }

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
