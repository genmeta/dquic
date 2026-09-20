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
        Epoch,
        error::{Error, ErrorKind, QuicError},
        frame::CryptoFrame,
        net::tx::{ArcSendWakers, Signals},
        packet::{Package, PacketContent},
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
        /// 不再长的像write，因为rust可以多返回值，因此在返回的结果里面将读到的数据返回.
        /// 调用者一定要自行将其写入到buffer中发送。
        /// 一旦这种函数成功使用，try_read_data就可以淘汰了
        fn try_load_data<P>(&mut self, packet: &mut P) -> Result<(), Signals>
        where
            P: BufMut + ?Sized,
            for<'b> (CryptoFrame, &'b [Bytes]): Package<P>,
        {
            let max_size = packet.remaining_mut();
            let predicate = |offset: u64| CryptoFrame::estimate_max_capacity(max_size, offset);
            self.sndbuf
                .pick_up(predicate, usize::MAX)
                .map(|(range, _is_fresh, data)| {
                    let frame = CryptoFrame::new(
                        VarInt::from_u64(range.start).unwrap(),
                        VarInt::try_from(range.end - range.start).unwrap(),
                    );
                    (frame, data.as_slice()).dump(packet).unwrap();
                })
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
            self.tx_wakers.wake_all_by(Signals::TRANSPORT);
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

            self.tx_wakers.wake_all_by(Signals::TRANSPORT);
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
                sender.tx_wakers.wake_all_by(Signals::TRANSPORT);
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
        /// Try to load the crypto data  into the `packet`.
        pub fn try_load_data_into<P>(&self, packet: &mut P, force: bool) -> Result<(), Signals>
        where
            P: BufMut + ?Sized,
            for<'b> (CryptoFrame, &'b [Bytes]): Package<P>,
        {
            use std::ops::ControlFlow::*;
            let mut inner = self.0.0.lock().unwrap();
            let Ok(inner) = inner.as_mut() else {
                return Err(Signals::empty());
            };
            if force {
                inner.sndbuf.resend_flighting();
            }
            let (Continue(result) | Break(result)) =
                core::iter::from_fn(|| Some(inner.try_load_data(packet))).try_fold(
                    Err(Signals::empty()),
                    |result, once| match (result, once) {
                        (Err(_empty), Ok(())) => Continue(Ok(())),
                        (Err(_empty), Err(signals)) => Break(Err(signals)),
                        (Ok(()), Ok(())) => Continue(Ok(())),
                        (Ok(()), Err(_no_more)) => Break(Ok(())),
                    },
                );
            result
        }

        pub fn package(self, epoch: Epoch) -> CryptoStreamPackage {
            CryptoStreamPackage {
                first_load: epoch == Epoch::Initial,
                outgoing: self,
            }
        }

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

    pub struct CryptoStreamPackage {
        first_load: bool,
        outgoing: CryptoStreamOutgoing,
    }

    impl<P> Package<P> for CryptoStreamPackage
    where
        P: BufMut + ?Sized,
        for<'b> (CryptoFrame, &'b [Bytes]): Package<P>,
    {
        fn dump(&mut self, packet: &mut P) -> Result<PacketContent, Signals> {
            let force = self.first_load;
            match self.outgoing.try_load_data_into(packet, force) {
                Ok(()) => {
                    self.first_load = false;
                    Ok(PacketContent::EffectivePayload)
                }
                Err(signals) => Err(signals),
            }
        }
    }

    pub(super) fn create(tx_wakers: ArcSendWakers) -> ArcSender {
        ArcSender(Arc::new(Mutex::new(Ok(Sender {
            sndbuf: SendBuf::with_capacity(VARINT_MAX),
            writable_waker: None,
            flush_waker: None,
            tx_wakers,
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

use qbase::{error::Error, net::tx::ArcSendWakers};
pub use recv::{ArcRecver, CryptoStreamIncoming, CryptoStreamReader};
pub use send::{ArcSender, CryptoStreamOutgoing, CryptoStreamWriter};

/// Crypto data stream.
#[derive(Debug, Clone)]
pub struct CryptoStream {
    pub sender: ArcSender,
    pub recver: ArcRecver,
}

impl CryptoStream {
    /// Fail both directions with the connection error.
    pub fn on_error(&self, error: &Error) {
        self.sender.on_error(error);
        self.recver.on_error(error);
    }

    /// Create a new instance of [`CryptoStream`] with the given buffer size.
    pub fn new(tx_wakers: ArcSendWakers) -> Self {
        Self {
            sender: send::create(tx_wakers),
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

    /// Create a [`CryptoStreamIncoming`] which belong to this crypto stream.
    pub fn incoming(&self) -> CryptoStreamIncoming {
        CryptoStreamIncoming(self.recver.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Wake, Waker},
    };

    use qbase::{
        error::{Error, ErrorKind, QuicError},
        frame::{CryptoFrame, io::ReceiveFrame},
        varint::VarInt,
    };
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    use super::CryptoStream;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct TestPacket(bytes::BytesMut);

    // Safety: delegate storage and initialized-length updates to BytesMut.
    unsafe impl bytes::BufMut for TestPacket {
        fn remaining_mut(&self) -> usize {
            64 - self.0.len()
        }

        unsafe fn advance_mut(&mut self, count: usize) {
            unsafe { self.0.advance_mut(count) }
        }

        fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
            self.0.chunk_mut()
        }
    }

    impl<D: qbase::util::Buffer> qbase::packet::RecordFrame<qbase::frame::Frame<D>, D> for TestPacket {
        fn record_frame(&mut self, _: &qbase::frame::Frame<D>) {}
    }

    #[tokio::test]
    async fn receiver_retirement_wakes_reader_and_preserves_crypto_retransmission() {
        let stream = CryptoStream::new(Default::default());
        let mut reader = stream.reader();
        let mut writer = stream.writer();
        writer.write_all(b"ServerHello").await.unwrap();
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut bytes = [0; 8];
        assert!(
            Pin::new(&mut reader)
                .poll_read(&mut cx, &mut ReadBuf::new(&mut bytes))
                .is_pending()
        );
        assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
        let mut packet = TestPacket(bytes::BytesMut::with_capacity(64));
        stream
            .outgoing()
            .try_load_data_into(&mut packet, false)
            .unwrap();

        stream.recver.retire();
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        assert_eq!(
            reader.read(&mut bytes).await.unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
        let frame = CryptoFrame::new(0u32.into(), 11u32.into());
        stream.outgoing().may_loss_data(&frame);
        let mut retransmission = TestPacket(bytes::BytesMut::with_capacity(64));
        stream
            .outgoing()
            .try_load_data_into(&mut retransmission, false)
            .unwrap();
        assert_eq!(retransmission.0, packet.0);
        stream.outgoing().on_data_acked(&frame);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 2);
        writer.flush().await.unwrap();
        stream
            .incoming()
            .recv_frame((
                CryptoFrame::new(0u32.into(), 4u32.into()),
                bytes::Bytes::from_static(b"late"),
            ))
            .unwrap();
        assert!(reader.read(&mut bytes).await.is_err());
    }

    #[tokio::test]
    async fn sender_retirement_wakes_flush_and_leaves_receiver_running() {
        let stream = CryptoStream::new(Default::default());
        let mut writer = stream.writer();
        writer.write_all(b"pending").await.unwrap();
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
        stream.sender.retire();
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        assert_eq!(
            writer.flush().await.unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            stream.writer().write(b"late").await.unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        let mut packet = TestPacket(bytes::BytesMut::with_capacity(64));
        assert!(
            stream
                .outgoing()
                .try_load_data_into(&mut packet, true)
                .is_err()
        );
        stream
            .outgoing()
            .on_data_acked(&CryptoFrame::new(0u32.into(), 7u32.into()));
        stream
            .outgoing()
            .may_loss_data(&CryptoFrame::new(0u32.into(), 7u32.into()));
        assert!(packet.0.is_empty());
        stream
            .incoming()
            .recv_frame((
                CryptoFrame::new(0u32.into(), 4u32.into()),
                bytes::Bytes::from_static(b"peer"),
            ))
            .unwrap();
        let mut bytes = [0; 4];
        stream.reader().read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"peer");
    }

    #[tokio::test]
    async fn connection_error_wakes_both_sides_and_preserves_the_cause() {
        let stream = CryptoStream::new(Default::default());
        let mut reader = stream.reader();
        let mut writer = stream.writer();
        writer.write_all(b"pending").await.unwrap();
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut bytes = [0; 8];
        assert!(
            Pin::new(&mut reader)
                .poll_read(&mut cx, &mut ReadBuf::new(&mut bytes))
                .is_pending()
        );
        assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());

        let error = Error::from(QuicError::with_default_fty(
            ErrorKind::Crypto(40),
            "handshake failed",
        ));
        stream.on_error(&error);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 2);
        stream.on_error(&QuicError::with_default_fty(ErrorKind::Internal, "late error").into());
        stream.sender.retire();
        stream.recver.retire();
        for failure in [
            reader.read(&mut bytes).await.unwrap_err(),
            stream.writer().write(b"late").await.unwrap_err(),
            writer.flush().await.unwrap_err(),
            writer.shutdown().await.unwrap_err(),
        ] {
            let cause = failure.get_ref().unwrap().downcast_ref::<Error>().unwrap();
            assert_eq!(cause, &error);
        }
        let mut packet = TestPacket(bytes::BytesMut::with_capacity(64));
        assert!(
            stream
                .outgoing()
                .try_load_data_into(&mut packet, true)
                .is_err()
        );
        assert!(packet.0.is_empty());
    }

    #[tokio::test]
    async fn shutdown_is_unsupported_and_keeps_unacknowledged_data() {
        let stream = CryptoStream::new(Default::default());
        stream.writer().write_all(b"outgoing").await.unwrap();
        assert_eq!(
            stream.writer().shutdown().await.unwrap_err().kind(),
            std::io::ErrorKind::Unsupported,
        );
        let mut packet = TestPacket(bytes::BytesMut::with_capacity(64));
        stream
            .outgoing()
            .try_load_data_into(&mut packet, false)
            .unwrap();
        assert!(packet.0.ends_with(b"outgoing"));
        stream.writer().write_all(b"still open").await.unwrap();
    }

    #[tokio::test]
    async fn acknowledging_crypto_wakes_flush() {
        let stream = CryptoStream::new(Default::default());
        let mut writer = stream.writer();
        writer.write_all(b"hello").await.unwrap();
        let mut packet = TestPacket(bytes::BytesMut::with_capacity(64));
        stream
            .outgoing()
            .try_load_data_into(&mut packet, false)
            .unwrap();
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
        stream
            .outgoing()
            .on_data_acked(&CryptoFrame::new(0u32.into(), 5u32.into()));
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        writer.flush().await.unwrap();
    }

    #[test]
    fn sparse_crypto_cannot_allocate_an_unbounded_handshake_buffer() {
        let stream = CryptoStream::new(Default::default());
        let result = stream.incoming().recv_frame((
            CryptoFrame::new(VarInt::from_u32(256 * 1024), VarInt::from_u32(1)),
            bytes::Bytes::from_static(b"x"),
        ));
        assert!(
            matches!(result, Err(error) if error.kind() == qbase::error::ErrorKind::CryptoBufferExceeded)
        );
    }

    #[tokio::test]
    async fn test_read() {
        let crypto_stream: CryptoStream = CryptoStream::new(Default::default());
        crypto_stream
            .writer()
            .write_all(b"hello world")
            .await
            .unwrap();

        crypto_stream
            .incoming()
            .recv_frame((
                CryptoFrame::new(VarInt::from_u32(0), VarInt::from_u32(11)),
                bytes::Bytes::copy_from_slice(b"hello world"),
            ))
            .unwrap();
        let mut buf = [0u8; 11];
        crypto_stream.reader().read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..], b"hello world");
    }
}
