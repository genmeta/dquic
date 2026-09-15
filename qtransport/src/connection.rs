use std::{future::poll_fn, sync::Arc};

use bytes::Bytes;
use qbase::{
    error::{AppError, ErrorKind},
    param::ParameterId,
};

use crate::{
    ArcParameters, Error, Role, StreamId, StreamReader, StreamWriter, VarInt, transport::Transport,
};

/// A successfully handshaken QUIC connection. Clones share stream queues and lifetime.
/// Keep one handle alive while using detached stream readers and writers.
#[derive(Clone)]
pub struct ArcConnection(Arc<Connection>);

struct Connection {
    alpn: Bytes,
    transport: Arc<Transport>,
}

impl ArcConnection {
    /// Protocol integration only: the caller has completed TLS and authenticated parameters.
    #[doc(hidden)]
    pub fn new(transport: Arc<Transport>, alpn: Bytes) -> Result<Self, Error> {
        if alpn.is_empty() || alpn.len() > 255 {
            return Err(crate::error(
                ErrorKind::Crypto(120),
                "missing or invalid negotiated ALPN",
            ));
        }
        if !transport.data.keys.is_ready()
            || !transport.data.control.can_receive()
            || !transport.data.control.can_send()
        {
            return Err(crate::error(
                ErrorKind::Internal,
                "data transport is not ready for delivery",
            ));
        }
        Ok(Self(Arc::new(Connection { alpn, transport })))
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
        self.0
            .transport
            .close(AppError::new(code, reason.to_owned()).into());
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.transport
            .close(AppError::new(VarInt::from_u32(0), "last connection handle dropped").into());
    }
}
