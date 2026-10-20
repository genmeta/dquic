//! The reliable transmission of the crypto stream.
mod send {
    use std::{
        io,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
    };

    use bytes::{BufMut, Bytes};
    use qbase::{
        error::{Error, ErrorKind, QuicError},
        frame::{CryptoFrame, FrameType},
        net::tx::{ArcSendWakers, UnregisterWaker},
        packet::{Package, PacketBuffer},
        varint::{VARINT_MAX, VarInt},
    };
    use tokio::io::AsyncWrite;

    use crate::send::SendBuf;

    #[derive(Debug)]
    pub(super) struct Sender {
        sndbuf: SendBuf,
        writable_waker: Option<Waker>,
        flush_waker: Option<Waker>,
        tx_wakers: ArcSendWakers,
    }

    impl Sender {
        /// Pack CRYPTO ranges until the packet is full or no more data is available.
        fn poll_dump<B: BufMut + ?Sized>(
            &mut self,
            cx: &mut Context<'_>,
            buffer: &mut PacketBuffer<'_, B>,
        ) -> Poll<Result<usize, Error>> {
            buffer.for_frame(FrameType::Crypto);
            let start = buffer.meta.nframes;
            loop {
                let capacity = buffer.remaining_mut();
                let predicate = |offset| CryptoFrame::estimate_max_capacity(capacity, offset);
                let (range, _, data) = match self.sndbuf.pick_up(predicate, usize::MAX) {
                    Ok(data) => data,
                    Err(_) if buffer.meta.nframes != start => {
                        return Poll::Ready(Ok(buffer.meta.nframes - start));
                    }
                    Err(Poll::Ready(())) => return Poll::Ready(Ok(0)),
                    Err(Poll::Pending) => {
                        self.tx_wakers.register(cx.waker());
                        return Poll::Pending;
                    }
                };
                let frame = CryptoFrame::new(
                    VarInt::from_u64(range.start).unwrap(),
                    VarInt::from_u64(range.end - range.start).unwrap(),
                );
                let result = (frame, data.as_slice()).poll_dump(cx, buffer);
                debug_assert!(matches!(result, Poll::Ready(Ok(1))));
            }
        }

        fn on_data_acked(&mut self, crypto_frame: &CryptoFrame) {
            self.sndbuf.on_data_acked(&crypto_frame.range());
            if self.sndbuf.remaining_mut() > 0
                && let Some(waker) = self.writable_waker.take()
            {
                waker.wake();
            }
            if self.sndbuf.is_all_rcvd()
                && let Some(waker) = self.flush_waker.take()
            {
                waker.wake();
            }
        }

        fn may_loss_data(&mut self, crypto_frame: &CryptoFrame) {
            self.sndbuf.may_loss_data(&crypto_frame.range());
            self.tx_wakers.wake_all();
        }
    }

    impl Sender {
        fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            assert!(
                self.writable_waker.is_none()
                    || matches!(self.writable_waker, Some(ref waker) if waker.will_wake(cx.waker()))
            );
            assert!(
                self.flush_waker.is_none()
                    || matches!(self.flush_waker, Some(ref waker) if waker.will_wake(cx.waker()))
            );
            if self.sndbuf.written() + buf.len() as u64 > VARINT_MAX {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "The largest offset delivered on the crypto stream cannot exceed 2^62-1",
                )));
            }

            debug_assert!(self.sndbuf.has_remaining_mut());

            self.tx_wakers.wake_all();
            self.sndbuf.write(Bytes::copy_from_slice(buf));
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            assert!(
                self.flush_waker.is_none()
                    || matches!(self.flush_waker, Some(ref waker) if waker.will_wake(cx.waker()))
            );
            if self.sndbuf.is_all_rcvd() {
                Poll::Ready(Ok(()))
            } else {
                self.flush_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// Sending half of a CRYPTO stream, independently retired from its receiving half.
    #[derive(Debug, Clone)]
    pub struct ArcSender(Arc<Mutex<Result<Sender, Error>>>);

    impl ArcSender {
        /// Abandon this encryption level's CRYPTO output and fail its writer with BrokenPipe.
        pub fn retire(&self) {
            self.on_error(
                &QuicError::with_default_fty(ErrorKind::None, "CRYPTO sender retired").into(),
            );
        }

        /// Preserve the first failure and wake the writer and any pending flush.
        pub fn on_error(&self, error: &Error) {
            let mut state = self.0.lock().unwrap();
            if let Ok(sender) = state.as_mut() {
                if let Some(waker) = sender.writable_waker.take() {
                    waker.wake();
                }
                if let Some(waker) = sender.flush_waker.take() {
                    waker.wake();
                }
                sender.tx_wakers.wake_all();
                *state = Err(error.clone());
            }
        }
    }

    /// Struct for crypto layer to send crypto data to the peer.
    ///
    /// To reduce the memory reallcation, if the internal buffer is filled, the [`write`] call will
    /// be blocked until the data sent been acknowledged by peer.
    ///
    /// [`write`]: tokio::io::AsyncWriteExt::write
    #[derive(Debug, Clone)]
    pub struct CryptoStreamWriter(pub(super) ArcSender);
    /// Struct for transport layer to send crypto data.
    #[derive(Debug, Clone)]
    pub struct CryptoStreamOutgoing(pub(super) ArcSender);

    /// Initial CRYPTO output that remains available until a handshake path is selected.
    #[derive(Debug, Clone)]
    pub struct CryptoStreamMultiOut(pub(super) ArcSender);

    impl AsyncWrite for CryptoStreamWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.0.0.lock().unwrap().as_mut() {
                Ok(sender) => sender.poll_write(cx, buf),
                Err(error) => Poll::Ready(Err(error.clone().into())),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.0.0.lock().unwrap().as_mut() {
                Ok(sender) => sender.poll_flush(cx),
                Err(error) => Poll::Ready(Err(error.clone().into())),
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(match self.0.0.lock().unwrap().as_mut() {
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "CRYPTO has no graceful shutdown; retire its sender instead",
                )),
                Err(error) => Err(error.clone().into()),
            })
        }
    }

    impl CryptoStreamOutgoing {
        /// Called when the crypto frame sent is acknowledged by peer.
        ///
        /// Acknowledgment of data may free up a segment in the [`SendBuf`], thus waking up the
        /// writing task,
        pub fn on_data_acked(&self, crypto_frame: &CryptoFrame) {
            if let Ok(sender) = self.0.0.lock().unwrap().as_mut() {
                sender.on_data_acked(crypto_frame);
            }
        }

        /// Called when the crypto frame sent may loss.
        pub fn may_loss_data(&self, crypto_frame: &CryptoFrame) {
            if let Ok(sender) = self.0.0.lock().unwrap().as_mut() {
                sender.may_loss_data(crypto_frame);
            }
        }
    }

    impl<B: BufMut + ?Sized> Package<B> for CryptoStreamOutgoing {
        fn poll_dump(
            &mut self,
            cx: &mut Context<'_>,
            buffer: &mut PacketBuffer<'_, B>,
        ) -> Poll<Result<usize, Error>> {
            let mut guard = self.0.0.lock().unwrap();
            let inner = match guard.as_mut() {
                Ok(inner) => inner,
                Err(_) => return Poll::Ready(Ok(0)),
            };
            inner.poll_dump(cx, buffer)
        }
    }

    impl UnregisterWaker for CryptoStreamOutgoing {
        fn unregister(&self, waker: &Waker) {
            if let Ok(inner) = self.0.0.lock().unwrap().as_ref() {
                inner.tx_wakers.unregister(waker);
            }
        }
    }

    impl<B: BufMut + ?Sized> Package<B> for CryptoStreamMultiOut {
        fn poll_dump(
            &mut self,
            cx: &mut Context<'_>,
            buffer: &mut PacketBuffer<'_, B>,
        ) -> Poll<Result<usize, Error>> {
            let mut guard = self.0.0.lock().unwrap();
            let inner = match guard.as_mut() {
                Ok(inner) => inner,
                Err(_) => return Poll::Ready(Ok(0)),
            };
            let result = inner.poll_dump(cx, buffer);
            inner.sndbuf.resend_flighting();
            result
        }
    }

    impl UnregisterWaker for CryptoStreamMultiOut {
        fn unregister(&self, waker: &Waker) {
            if let Ok(inner) = self.0.0.lock().unwrap().as_ref() {
                inner.tx_wakers.unregister(waker);
            }
        }
    }

    pub(super) fn create() -> ArcSender {
        ArcSender(Arc::new(Mutex::new(Ok(Sender {
            sndbuf: SendBuf::with_capacity(VARINT_MAX),
            writable_waker: None,
            flush_waker: None,
            tx_wakers: ArcSendWakers::default(),
        }))))
    }
}

mod recv {
    use std::{
        io,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
    };

    use bytes::{BufMut, Bytes};
    use qbase::{
        error::{Error, ErrorKind, QuicError},
        frame::{CryptoFrame, io::ReceiveFrame},
        varint::VARINT_MAX,
    };
    use tokio::io::{AsyncRead, ReadBuf};

    use crate::recv::RecvBuf;

    #[derive(Debug)]
    pub(super) struct Recver {
        rcvbuf: RecvBuf,
        read_waker: Option<Waker>,
    }

    impl Recver {
        fn recv(&mut self, offset: u64, data: Bytes) -> Result<(), Error> {
            assert!(offset + data.len() as u64 <= VARINT_MAX);
            // Bound sparse CRYPTO reassembly as well as contiguous TLS input.
            if offset.saturating_add(data.len() as u64)
                > self.rcvbuf.nread().saturating_add(256 * 1024)
                || self.rcvbuf.segment_count() >= 1024
            {
                return Err(QuicError::with_default_fty(
                    ErrorKind::CryptoBufferExceeded,
                    "CRYPTO reassembly budget exceeded",
                )
                .into());
            }
            self.rcvbuf.recv(offset, data);
            if self.rcvbuf.is_readable()
                && let Some(waker) = self.read_waker.take()
            {
                waker.wake()
            }
            Ok(())
        }

        fn poll_read<T: BufMut>(
            &mut self,
            cx: &mut Context<'_>,
            buf: &mut T,
        ) -> Poll<io::Result<()>> {
            assert!(
                self.read_waker.is_none()
                    || matches!(self.read_waker, Some(ref waker) if waker.will_wake(cx.waker()))
            );
            if self.rcvbuf.is_readable() {
                self.rcvbuf.try_read(buf);
                Poll::Ready(Ok(()))
            } else {
                self.read_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// Receiving half of a CRYPTO stream, independently retired from its sending half.
    #[derive(Debug, Clone)]
    pub struct ArcRecver(Arc<Mutex<Result<Recver, Error>>>);

    impl ArcRecver {
        /// End delivery to TLS and fail its reader with BrokenPipe.
        pub fn retire(&self) {
            self.on_error(
                &QuicError::with_default_fty(ErrorKind::None, "CRYPTO receiver retired").into(),
            );
        }

        /// Preserve the first failure and wake the pending reader.
        pub fn on_error(&self, error: &Error) {
            let mut state = self.0.lock().unwrap();
            if let Ok(recver) = state.as_mut() {
                if let Some(waker) = recver.read_waker.take() {
                    waker.wake();
                }
                *state = Err(error.clone());
            }
        }
    }

    /// Struct for crypto layer to read crypto data from the peer.
    #[derive(Debug, Clone)]
    pub struct CryptoStreamReader(pub(super) ArcRecver);
    /// Struct for transport layer to deliver the received crypto to crypto layer.
    #[derive(Debug, Clone)]
    pub struct CryptoStreamIncoming(pub(super) ArcRecver);

    impl AsyncRead for CryptoStreamReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.0.0.lock().unwrap().as_mut() {
                Ok(recver) => recver.poll_read(cx, buf),
                Err(error) => Poll::Ready(Err(error.clone().into())),
            }
        }
    }

    impl ReceiveFrame<(CryptoFrame, Bytes)> for CryptoStreamIncoming {
        type Output = ();

        fn recv_frame(&self, (frame, data): (CryptoFrame, Bytes)) -> Result<Self::Output, Error> {
            match self.0.0.lock().unwrap().as_mut() {
                Ok(recver) => recver.recv(frame.offset(), data),
                Err(_) => Ok(()),
            }
        }
    }

    pub(super) fn create() -> ArcRecver {
        ArcRecver(Arc::new(Mutex::new(Ok(Recver {
            rcvbuf: RecvBuf::default(),
            read_waker: None,
        }))))
    }
}

use qbase::{Close, error::Error};
pub use recv::{ArcRecver, CryptoStreamIncoming, CryptoStreamReader};
pub use send::{ArcSender, CryptoStreamMultiOut, CryptoStreamOutgoing, CryptoStreamWriter};

/// Crypto data stream.
#[derive(Debug, Clone)]
pub struct CryptoStream {
    pub sender: ArcSender,
    pub recver: ArcRecver,
}

impl Default for CryptoStream {
    fn default() -> Self {
        Self::new()
    }
}

impl Close for CryptoStream {
    fn close_with_error(&self, error: Error) {
        self.on_error(&error);
    }
}

impl CryptoStream {
    /// Fail both directions with the connection error.
    pub fn on_error(&self, error: &Error) {
        self.sender.on_error(error);
        self.recver.on_error(error);
    }

    /// Create a new instance of [`CryptoStream`] with the given buffer size.
    pub fn new() -> Self {
        Self {
            sender: send::create(),
            recver: recv::create(),
        }
    }

    /// Create a [`CryptoStreamWriter`] which belong to this crypto stream.
    pub fn writer(&self) -> CryptoStreamWriter {
        CryptoStreamWriter(self.sender.clone())
    }

    /// Create a [`CryptoStreamReader`] which belong to this crypto stream.
    pub fn reader(&self) -> CryptoStreamReader {
        CryptoStreamReader(self.recver.clone())
    }

    /// Create a [`CryptoStreamOutgoing`] which belong to this crypto stream.
    pub fn outgoing(&self) -> CryptoStreamOutgoing {
        CryptoStreamOutgoing(self.sender.clone())
    }

    /// Create Initial output for use before a handshake path is selected.
    pub fn multipath(&self) -> CryptoStreamMultiOut {
        CryptoStreamMultiOut(self.sender.clone())
    }

    /// Create a [`CryptoStreamIncoming`] which belong to this crypto stream.
    pub fn incoming(&self) -> CryptoStreamIncoming {
        CryptoStreamIncoming(self.recver.clone())
    }
}
