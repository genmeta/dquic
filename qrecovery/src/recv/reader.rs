use std::{
    io::{self},
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::Stream;
use qbase::{
    frame::{MaxStreamDataFrame, StopSendingFrame, io::SendFrame},
    varint::VARINT_MAX,
};
use qevent::quic::transport::{GranularStreamStates, StreamSide, StreamStateUpdated};
use tokio::io::{AsyncRead, ReadBuf};

use super::recver::{ArcRecver, Recver};
use crate::streams::error::StreamError;

pub trait StopSending {
    /// Tell peer to stop sending data with the given error code.
    ///
    /// If all data has been received (the stream has closed), or the stream has been reset, this method will do
    /// nothing.
    ///
    /// Otherwise, a [`STOP_SENDING frame`] will be sent to the peer, and then the stream will be reset by peer,
    /// neither new data nor lost data will be sent.
    ///
    /// Unlike TCP, stopping a QUIC stream needs an error code, which is used to indicate
    /// the reason for the stopping. The error code should be a `u64` value,
    /// defined by the application protocol using QUIC, such as HTTP/3 or gRPC.
    ///
    /// [`STOP_SENDING frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames
    fn stop(&mut self, error_code: u64);
}

/// The reader part of a QUIC stream.
///
/// A QUIC stream is *reliable*, *ordered*, and *flow-controlled*.
///
/// This struct implements the [`AsyncRead`] trait, allowing you to read an ordered byte stream from
/// the peer, like [`TcpStream`].
///
/// Try to read from the [`Reader`] into a non-empty buffer, the [`Reader`] will block until some data
/// is available, or the stream is closed, or the stream is reset by peer.
///
/// # Note
///
/// The stream must be closed before [`Reader`] dropped.
///
/// The [`read`] returning `Ok(0)` indicates that all data from peer has been read and the stream has
/// `closed`, it is okay to drop the [`Reader`] after that.
///
/// Alternatively, if the [`read`] result an error, its indicates that the stream has been `reset`, or
/// closed duo to other reasons. It's also okay to drop the [`Reader`] after that.
///
/// You can call [`stop`] to tell the peer to stop sending data with the given error code, the [`Reader`]
/// will be consumed, and the error code will be sent to the peer.
///
/// # Example
///
/// The [`Reader`] is created by the `open_bi_stream`, `accept_bi_stream`, or `accept_uni_stream` methods
/// of `QuicConnection` (in the `quic` crate).
///
/// The following example demonstrates how to read and write data on a QUIC stream:
///
/// ```rust, ignore
/// # use tokio::io::{AsyncWriteExt, AsyncReadExt};
/// # async fn example() -> std::io::Result<()> {
/// let (reader, writer) = quic_connection.open_bi_stream().await?;
///
/// writer.write_all(b"GET README.md\r\n").await?;
/// writer.shutdown().await?;
///
/// let mut response = String::new();
/// let n = reader.read_to_string(&mut response).await?;
/// println!("Response {} bytes: {}", n, response);
/// Ok(())
/// # }
/// ```
///
/// [`TcpStream`]: tokio::net::TcpStream
/// [`read`]: tokio::io::AsyncReadExt::read
/// [`stop`]: Reader::stop
/// [`RESET_STREAM frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
#[derive(Debug)]
pub struct Reader<TX> {
    inner: ArcRecver<TX>,
    qlog_span: qevent::telemetry::Span,
    tracing_span: tracing::Span,
}

impl<TX> Reader<TX> {
    /// Create a new [`Reader`] from the given [`Recver`].
    ///
    /// This method is used by the `accept_bi_stream` and `accept_uni_stream` methods of
    /// [`QuicConnection`](crate::QuicConnection).
    pub(crate) fn new(inner: ArcRecver<TX>) -> Self {
        Self {
            inner,
            qlog_span: qevent::telemetry::Span::current(),
            tracing_span: tracing::Span::current(),
        }
    }

    #[inline]
    pub fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut impl bytes::BufMut,
    ) -> Poll<Result<(), StreamError>>
    where
        TX: SendFrame<MaxStreamDataFrame>,
    {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());

        let mut recver = self.inner.recver();
        let receiving_state = recver.as_mut().map_err(|e| e.clone())?;
        // 能相当清楚地看到应用层读取数据驱动的接收状态演变
        match receiving_state {
            Recver::Recv(r) => r.poll_read(cx, buf).map(Ok),
            Recver::SizeKnown(r) => r.poll_read(cx, buf).map(Ok),
            Recver::DataRcvd(r) => {
                r.poll_read(buf);
                if r.is_all_read() {
                    r.upgrade();
                    *receiving_state = Recver::DataRead;
                }
                Poll::Ready(Ok(()))
            }
            Recver::DataRead => Poll::Ready(Ok(())),
            Recver::ResetRcvd(r) => {
                qevent::event!(StreamStateUpdated {
                    stream_id: r.stream_id().id(),
                    stream_type: r.stream_id().dir(),
                    old: GranularStreamStates::ResetReceived,
                    new: GranularStreamStates::ResetRead,
                    stream_side: StreamSide::Receiving
                });
                let reset_stream_error = (&*r).into();
                *receiving_state = Recver::ResetRead(reset_stream_error);
                Poll::Ready(Err(reset_stream_error.into()))
            }
            Recver::ResetRead(r) => Poll::Ready(Err((*r).into())),
        }
    }

    #[inline]
    pub fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, StreamError>>>
    where
        TX: SendFrame<MaxStreamDataFrame>,
    {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());

        let mut recver = self.inner.recver();
        let receiving_state = recver.as_mut().map_err(|e| e.clone())?;
        // 能相当清楚地看到应用层读取数据驱动的接收状态演变
        match receiving_state {
            Recver::Recv(r) => r.poll_next(cx).map(Ok).map(Some),
            Recver::SizeKnown(r) => r.poll_next(cx).map(Ok).map(Some),
            Recver::DataRcvd(r) => {
                let Some(data) = r.poll_next() else {
                    return Poll::Ready(None);
                };
                if r.is_all_read() {
                    r.upgrade();
                    *receiving_state = Recver::DataRead;
                }
                Poll::Ready(Some(Ok(data)))
            }
            Recver::DataRead => Poll::Ready(None),
            Recver::ResetRcvd(r) => {
                qevent::event!(StreamStateUpdated {
                    stream_id: r.stream_id().id(),
                    stream_type: r.stream_id().dir(),
                    old: GranularStreamStates::ResetReceived,
                    new: GranularStreamStates::ResetRead,
                    stream_side: StreamSide::Receiving
                });
                let reset_stream_error = (&*r).into();
                *receiving_state = Recver::ResetRead(reset_stream_error);
                Poll::Ready(Some(Err(reset_stream_error.into())))
            }
            Recver::ResetRead(r) => Poll::Ready(Some(Err((*r).into()))),
        }
    }
}

impl<TX> StopSending for Reader<TX>
where
    TX: SendFrame<StopSendingFrame>,
{
    /// Tell peer to stop sending data with the given error code.
    ///
    /// If all data has been received(the stream has closed), or the stream has been reset, this method will do
    /// nothing.
    ///
    /// Otherwise, a [`STOP_SENDING frame`] will be sent to the peer, and then the stream will be reset by peer.
    ///
    /// [`STOP_SENDING frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames
    fn stop(&mut self, error_code: u64) {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());

        debug_assert!(error_code <= VARINT_MAX);
        let mut recver = self.inner.recver();
        let inner = recver.deref_mut();
        if let Ok(receiving_state) = inner {
            match receiving_state {
                Recver::Recv(r) => {
                    r.stop(error_code);
                }
                Recver::SizeKnown(r) => {
                    r.stop(error_code);
                }
                _ => (),
            }
        }
    }
}

impl<TX> AsyncRead for Reader<TX>
where
    TX: SendFrame<MaxStreamDataFrame>,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Reader::poll_read(self.get_mut(), cx, buf).map_err(io::Error::from)
    }
}

impl<TX> Stream for Reader<TX>
where
    TX: SendFrame<MaxStreamDataFrame>,
{
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Reader::poll_next(self, cx)
    }
}

impl<TX> Drop for Reader<TX> {
    fn drop(&mut self) {
        let mut recver = self.inner.recver();
        let inner = recver.deref_mut();
        if let Ok(receiving_state) = inner {
            match receiving_state {
                Recver::Recv(r) if !r.is_stopped() => {
                    #[cfg(debug_assertions)]
                    tracing::warn!(
                        target: "dquic",
                        "receiving stream {} is not stopped before drop",
                        r.stream_id(),
                    );
                    #[cfg(not(debug_assertions))]
                    tracing::debug!(
                        target: "dquic",
                        "receiving stream {} is not stopped before drop",
                        r.stream_id(),
                    );
                }
                Recver::SizeKnown(r) if !r.is_stopped() => {
                    #[cfg(debug_assertions)]
                    tracing::warn!(
                        target: "dquic",
                        "receiving stream {} is not stopped before drop",
                        r.stream_id()
                    );
                    #[cfg(not(debug_assertions))]
                    tracing::debug!(
                        target: "dquic",
                        "receiving stream {} is not stopped before drop",
                        r.stream_id()
                    );
                }
                _ => (),
            }
        }
    }
}
