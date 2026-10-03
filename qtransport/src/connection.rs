use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use bytes::Bytes;
use qbase::{Epoch, error::AppError, net::route::Pathway};
use qrecovery::streams::DataStreams;

use crate::{
    ArcReliableFrames, CloseReason, Error, StreamId, StreamReader, StreamWriter, VarInt,
    path::Path, terminate::ArcTerminator,
};

/// A successfully handshaken QUIC connection. Clones share stream queues and lifetime.
/// Keep one handle alive while using detached stream readers and writers.
#[derive(Clone)]
pub struct ArcConnection(Arc<Connection>);

struct Connection {
    alpn: Bytes,
    streams: DataStreams<ArcReliableFrames>,
    terminator: ArcTerminator,
    paths: OnceLock<Box<dyn Fn() -> Vec<Arc<Path>> + Send + Sync>>,
}

impl ArcConnection {
    /// Integration only: TLS and parameters are authenticated. Register streams with
    /// the terminator before constructing this handle; qconnection awaits termination.
    #[doc(hidden)]
    pub fn new(
        alpn: Bytes,
        streams: DataStreams<ArcReliableFrames>,
        terminator: ArcTerminator,
    ) -> Self {
        Self(Arc::new(Connection {
            alpn,
            streams,
            terminator,
            paths: OnceLock::new(),
        }))
    }

    /// Integration only: attach a read-only view without retaining the lifecycle owner.
    #[doc(hidden)]
    pub fn with_path_observer(
        self,
        paths: impl Fn() -> Vec<Arc<Path>> + Send + Sync + 'static,
    ) -> Self {
        let _ = self.0.paths.set(Box::new(paths));
        self
    }

    /// Snapshot of currently validated paths. Retired and unvalidated paths are excluded.
    pub fn validated_paths(&self) -> Vec<Pathway> {
        self.0.paths.get().map_or_else(Vec::new, |snapshot| {
            snapshot()
                .into_iter()
                .filter(|path| path.is_validated())
                .map(|path| path.pathway)
                .collect()
        })
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
        let pto = self
            .paths
            .get()
            .and_then(|snapshot| {
                snapshot()
                    .iter()
                    .map(|path| path.cc.pto_base(Epoch::Data))
                    .max()
            })
            .unwrap_or(Duration::from_secs(1));
        self.terminator.close(CloseReason::App(error), pto);
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

    #[tokio::test(start_paused = true)]
    async fn connection_keeps_streams_alive_without_retaining_the_data_space() {
        use tokio::io::AsyncWriteExt;

        let space = crate::tests::data();
        let terminator = ArcTerminator::no_error();
        terminator.register(Arc::new(space.streams.clone()));
        let connection =
            ArcConnection::new(Bytes::from_static(b"h3"), space.streams.clone(), terminator);
        let data = Arc::downgrade(&space);
        drop(space);
        assert!(data.upgrade().is_none());

        let (_, mut writer) = connection.open_uni_stream().await.unwrap().unwrap();
        writer.write_all(b"pending").await.unwrap();
        let close = connection.0.terminator.clone();
        connection.close(42u32.into(), "stop");
        assert!(writer.flush().await.is_err());
        assert!(matches!(
            close.await,
            Error::App(error) if error == AppError::new(42u32.into(), "stop")
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn explicit_close_wakes_the_driver_and_preserves_the_first_reason() {
        let data = crate::tests::data();
        let terminator = ArcTerminator::no_error();
        terminator.register(Arc::new(data.streams.clone()));
        let connection =
            ArcConnection::new(Bytes::from_static(b"h3"), data.streams.clone(), terminator);
        let close = connection.0.terminator.clone();
        assert!(futures::poll!(std::pin::pin!(close.wait())).is_pending());
        connection.clone().close(42u32.into(), "first");
        connection.close(99u32.into(), "later");
        let Error::App(error) = close.clone().await else {
            panic!("expected application close");
        };
        assert_eq!(error, AppError::new(42u32.into(), "first"));
        assert_eq!(close.await, Error::App(error));
    }

    #[tokio::test(start_paused = true)]
    async fn only_the_last_handle_drop_notifies_the_driver() {
        let data = crate::tests::data();
        let terminator = ArcTerminator::no_error();
        terminator.register(Arc::new(data.streams.clone()));
        let connection =
            ArcConnection::new(Bytes::from_static(b"h3"), data.streams.clone(), terminator);
        let close = connection.0.terminator.clone();
        drop(connection.clone());
        assert!(futures::poll!(std::pin::pin!(close.wait())).is_pending());
        drop(connection);
        let Error::App(error) = close.await else {
            panic!("expected application close");
        };
        assert_eq!(error.error_code(), 0);
        assert_eq!(error.reason(), "last connection handle dropped");
    }
}
