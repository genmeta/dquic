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
