use std::{
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::Sink;
use qbase::frame::{ResetStreamFrame, io::SendFrame};
use tokio::io::{self, AsyncWrite};

use super::sender::{ArcSender, Sender};
use crate::streams::error::StreamError;

pub trait CancelStream {
    /// Cancels the stream with the given error code.
    ///
    /// If all data has been sent and acknowledged by the peer, or the stream has been reset, this
    /// method will do nothing.
    ///
    /// Otherwise, a [`RESET_STREAM frame`] will be sent to the peer, and the stream will be reset,
    /// neither new data nor lost data will be sent.
    ///
    /// Unlike TCP, canceling a QUIC stream needs an error code, which is used to indicate
    /// the reason for the cancellation. The error code should be a `u64` value,
    /// defined by the application protocol using QUIC, such as HTTP/3 or gRPC.
    ///
    /// [`RESET_STREAM frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
    fn cancel(&mut self, err_code: u64);
}

/// The writer part of a QUIC stream.
///
/// This struct implements the [`AsyncWrite`] trait, allowing you to write data to the stream.
///
/// A QUIC stream is *reliable*, *ordered*, and *flow-controlled*.
///
/// The amount of data that can be sent is limited by flow control. The [`write`] call will be blocked
/// if the amount of data written reaches the flow control limit.
///
/// The [`flush`] and [`shutdown`] calls will be blocked until all data written to [`Writer`] has
/// been sent and acknowledged by the peer.
///
/// # Note
///
/// The stream must be cancelled or shutdowned before the [`Writer`] dropped.
///
/// Call [`shutdown`] means that there are no more new data will been written to the stream. If all
/// of the data written to the stream has been sent and acknowledged by the peer, the stream will be
/// `closed`, and the [`shutdown`] call complete with `Ok(())`.
///
/// Alternatively, if the operations on the [`Writer`] result an error, its indicates that the stream
/// has been cancelled in other reason, such as connection closed, the peer acked local to stop sending.
///
/// You can call [`cancel`] to `cancel` the stream with the given error code, The [`Writer`] will be
/// consumed, and neither new data nor lost data will be sent anymore.
///
/// # Example
///
/// The [`Writer`] is created by the `open_bi_stream`, `open_uni_stream`, or `accept_bi_stream` methods of
/// `QuicConnection` (in the `dquic` crate).
///
/// The following example demonstrates how to read and write data on a QUIC stream.
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
/// [`write`]: tokio::io::AsyncWriteExt::write
/// [`flush`]: tokio::io::AsyncWriteExt::flush
/// [`shutdown`]: tokio::io::AsyncWriteExt::shutdown
/// [`cancel`]: Writer::cancel
/// [`STOP_SENDING frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames
#[derive(Debug)]
pub struct Writer<TX> {
    inner: ArcSender<TX>,
    qlog_span: qevent::telemetry::Span,
    tracing_span: tracing::Span,
}

impl<TX> Writer<TX> {
    pub(crate) fn new(inner: ArcSender<TX>) -> Self {
        Self {
            inner,
            qlog_span: qevent::telemetry::Span::current(),
            tracing_span: tracing::Span::current(),
        }
    }
}

impl<TX> CancelStream for Writer<TX>
where
    TX: SendFrame<ResetStreamFrame>,
{
    /// Cancels the stream with the given error code(reset the stream).
    ///
    /// If all data has been sent and acknowledged by the peer(the stream has closed), or the stream
    /// has been reset, this method will do nothing.
    ///
    /// Otherwise, a [`RESET_STREAM frame`] will be sent to the peer, and the stream will be reset,
    /// neither new data nor lost data will be sent.
    ///
    /// [`RESET_STREAM frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
    fn cancel(&mut self, err_code: u64) {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());

        let mut sender = self.inner.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            match sending_state {
                Sender::Ready(s) => {
                    *sending_state = Sender::ResetSent(s.cancel(err_code));
                }
                Sender::Sending(s) => {
                    *sending_state = Sender::ResetSent(s.cancel(err_code));
                }
                Sender::DataSent(s) => {
                    *sending_state = Sender::ResetSent(s.cancel(err_code));
                }
                _ => (),
            }
        };
    }
}

impl<TX> Writer<TX> {
    /// Poll to check whether [`Writer`] can cache more appropriate amount of data.
    ///
    /// Even without calling this method in advance, writing data can succeed.
    /// However, this may cause the QUIC layer to cache excessive data.
    #[inline]
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());

        let mut sender = self.inner.sender();
        let sending_state = sender.as_mut().map_err(|e| e.clone())?;
        match sending_state {
            Sender::Ready(s) => s.poll_ready(cx),
            Sender::Sending(s) => s.poll_ready(cx),
            Sender::DataSent(_) => Poll::Ready(Err(StreamError::EosSent)),
            Sender::DataRcvd => Poll::Ready(Err(StreamError::EosSent)),
            Sender::ResetSent(reset) => Poll::Ready(Err(StreamError::Reset(*reset))),
            Sender::ResetRcvd(reset) => Poll::Ready(Err(StreamError::Reset(*reset))),
        }
    }

    /// Write data to the stream.
    ///
    /// Although data written by this method can also be sent,
    /// it is recommended to use the `Sink` or `AsyncWrite` API to avoid excessive data caching at the QUIC layer.
    #[inline]
    pub fn write(&mut self, buf: Bytes) -> Result<(), StreamError> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());

        let mut sender = self.inner.sender();
        let sending_state = sender.as_mut().map_err(|e| e.clone())?;
        match sending_state {
            Sender::Ready(s) => s.write(buf),
            Sender::Sending(s) => s.write(buf),
            Sender::DataSent(_) => Err(StreamError::EosSent),
            Sender::DataRcvd => Err(StreamError::EosSent),
            Sender::ResetSent(reset) => Err(StreamError::Reset(*reset)),
            Sender::ResetRcvd(reset) => Err(StreamError::Reset(*reset)),
        }
    }

    #[inline]
    pub fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        data: Bytes,
    ) -> Poll<Result<(), StreamError>> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());

        let mut sender = self.inner.sender();
        let sending_state = sender.as_mut().map_err(|e| e.clone())?;
        match sending_state {
            Sender::Ready(s) => {
                ready!(s.poll_ready(cx)?);
                Poll::Ready(s.write(data))
            }
            Sender::Sending(s) => {
                ready!(s.poll_ready(cx)?);
                Poll::Ready(s.write(data))
            }
            Sender::DataSent(_) => Poll::Ready(Err(StreamError::EosSent)),
            Sender::DataRcvd => Poll::Ready(Err(StreamError::EosSent)),
            Sender::ResetSent(reset) => Poll::Ready(Err(StreamError::Reset(*reset))),
            Sender::ResetRcvd(reset) => Poll::Ready(Err(StreamError::Reset(*reset))),
        }
    }

    #[inline]
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());

        let mut sender = self.inner.sender();
        let sending_state = sender.as_mut().map_err(|e| e.clone())?;
        match sending_state {
            Sender::Ready(s) => s.poll_flush(cx).map(Ok),
            Sender::Sending(s) => s.poll_flush(cx).map(Ok),
            Sender::DataSent(s) => s.poll_flush(cx).map(Ok),
            Sender::DataRcvd => Poll::Ready(Ok(())),
            Sender::ResetSent(reset) => Poll::Ready(Err(StreamError::Reset(*reset))),
            Sender::ResetRcvd(reset) => Poll::Ready(Err(StreamError::Reset(*reset))),
        }
    }

    #[inline]
    #[doc(alias = "poll_close")]
    pub fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        let _span = (self.qlog_span.enter(), self.tracing_span.enter());

        let mut sender = self.inner.sender();
        let sending_state = sender.as_mut().map_err(|e| e.clone())?;
        match sending_state {
            Sender::Ready(s) => s.poll_shutdown(cx).map(Ok),
            Sender::Sending(s) => s.poll_shutdown(cx).map(Ok),
            Sender::DataSent(s) => s.poll_shutdown(cx).map(Ok),
            Sender::DataRcvd => Poll::Ready(Ok(())),
            Sender::ResetSent(reset) => Poll::Ready(Err(StreamError::Reset(*reset))),
            Sender::ResetRcvd(reset) => Poll::Ready(Err(StreamError::Reset(*reset))),
        }
    }
}

impl<TX> AsyncWrite for Writer<TX> {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Writer::poll_write(self.get_mut(), cx, Bytes::copy_from_slice(buf))
            .map_ok(|()| buf.len())
            .map_err(io::Error::from)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Writer::poll_flush(self.get_mut(), cx).map_err(io::Error::from)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Writer::poll_shutdown(self.get_mut(), cx).map_err(io::Error::from)
    }
}

impl<TX> Sink<Bytes> for Writer<TX> {
    type Error = StreamError;

    #[inline]
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Writer::poll_ready(self.get_mut(), cx)
    }

    #[inline]
    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        Writer::write(self.get_mut(), item)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Writer::poll_flush(self.get_mut(), cx)
    }

    #[inline]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Writer::poll_shutdown(self.get_mut(), cx)
    }
}

impl<TX> Drop for Writer<TX> {
    fn drop(&mut self) {
        let mut sender = self.inner.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            match sending_state {
                Sender::Ready(s) => {
                    #[cfg(debug_assertions)]
                    tracing::warn!(
                        target: "dquic",
                        "sending stream {} is not closed before drop",
                        s.stream_id(),
                    );
                    #[cfg(not(debug_assertions))]
                    tracing::debug!(
                        target: "dquic",
                        "sending stream {} is not closed before drop",
                        s.stream_id(),
                    );
                }
                Sender::Sending(s) => {
                    #[cfg(debug_assertions)]
                    tracing::warn!(
                        target: "dquic",
                        "sending stream {} is not closed before drop",
                        s.stream_id(),
                    );
                    #[cfg(not(debug_assertions))]
                    tracing::debug!(
                        target: "dquic",
                        "sending stream {} is not closed before drop",
                        s.stream_id(),
                    );
                }
                _ => (),
            }
        };
    }
}
