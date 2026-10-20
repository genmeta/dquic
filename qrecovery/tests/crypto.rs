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
        packet::Package,
        varint::VarInt,
    };
    use qrecovery::crypto::CryptoStream;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

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

    impl TestPacket {
        fn load(&mut self, source: &mut impl Package<Self>) -> Result<usize, ()> {
            use qbase::packet::{
                Constraints, PacketBuffer, Type,
                r#type::long::{Type as Long, Ver1},
            };
            let mut limits = Constraints {
                flow_ctrl: 0,
                send_quota: 64,
                credit: 64,
                min_size: 0,
                max_size: 64,
                ..Default::default()
            };
            let written = self.0.len();
            let mut frames = Vec::new();
            let mut buffer = PacketBuffer::new(
                self,
                &mut limits,
                &mut frames,
                Type::Long(Long::V1(Ver1::INITIAL)),
                written,
                0,
            );
            match source.poll_dump(&mut Context::from_waker(Waker::noop()), &mut buffer) {
                std::task::Poll::Ready(Ok(n)) if n > 0 => Ok(n),
                _ => Err(()),
            }
        }
    }

    #[tokio::test]
    async fn disjoint_lost_crypto_ranges_share_one_packet() {
        use qbase::{
            frame::{Frame, FrameReader},
            packet::{
                Type,
                r#type::long::{Type as Long, Ver1},
            },
        };

        let stream = CryptoStream::new();
        stream.writer().write_all(&[42; 20]).await.unwrap();
        let mut first = TestPacket(bytes::BytesMut::with_capacity(64));
        first.load(&mut stream.outgoing()).unwrap();
        for offset in [5u32, 15] {
            stream
                .outgoing()
                .on_data_acked(&CryptoFrame::new(offset.into(), 5u32.into()));
        }
        stream
            .outgoing()
            .may_loss_data(&CryptoFrame::new(0u32.into(), 20u32.into()));

        let mut packet = TestPacket(bytes::BytesMut::with_capacity(64));
        packet.load(&mut stream.outgoing()).unwrap();
        let ranges = FrameReader::new(packet.0.freeze(), Type::Long(Long::V1(Ver1::INITIAL)))
            .map(|frame| {
                let Frame::Crypto(frame, bytes) = frame.unwrap().0 else {
                    panic!("expected CRYPTO")
                };
                assert_eq!(bytes.as_ref(), &[42; 5]);
                frame.range()
            })
            .collect::<Vec<_>>();
        assert_eq!(ranges, [0..5, 10..15]);
    }

    #[tokio::test]
    async fn multipath_leaves_data_available_for_the_selected_path_and_acknowledgment() {
        let stream = CryptoStream::new();
        stream.writer().write_all(b"ClientHello").await.unwrap();
        let mut multipath = stream.multipath();
        let mut first = TestPacket(bytes::BytesMut::with_capacity(64));
        first.load(&mut multipath).unwrap();

        let mut second = TestPacket(bytes::BytesMut::with_capacity(64));
        second.load(&mut stream.multipath()).unwrap();
        assert_eq!(second.0, first.0);

        let mut selected = TestPacket(bytes::BytesMut::with_capacity(64));
        selected.load(&mut stream.outgoing()).unwrap();
        assert_eq!(selected.0, first.0);
        let mut blocked = TestPacket(bytes::BytesMut::with_capacity(64));
        assert!(blocked.load(&mut stream.outgoing()).is_err());

        stream
            .outgoing()
            .on_data_acked(&CryptoFrame::new(0u32.into(), 11u32.into()));
        assert!(blocked.load(&mut multipath).is_err());
        stream.writer().flush().await.unwrap();
    }

    #[tokio::test]
    async fn multipath_marks_flighting_lost_after_loading_and_lost_data_can_be_acked() {
        use qbase::{
            frame::{Frame, FrameReader},
            packet::{
                Type,
                r#type::long::{Type as Long, Ver1},
            },
        };

        let crypto_frame = |packet: &TestPacket| {
            let mut frames = FrameReader::new(
                packet.0.clone().freeze(),
                Type::Long(Long::V1(Ver1::INITIAL)),
            );
            let Frame::Crypto(frame, _) = frames.next().unwrap().unwrap().0 else {
                panic!("expected CRYPTO")
            };
            frame
        };

        let stream = CryptoStream::new();
        stream.writer().write_all(&[42; 100]).await.unwrap();
        let mut first = TestPacket(bytes::BytesMut::with_capacity(64));
        first.load(&mut stream.outgoing()).unwrap();
        let prefix = crypto_frame(&first);

        let mut second = TestPacket(bytes::BytesMut::with_capacity(64));
        second.load(&mut stream.multipath()).unwrap();
        let suffix = crypto_frame(&second);
        assert_eq!(suffix.offset(), prefix.range().end);
        assert_eq!(suffix.range().end, 100);

        // Both the previously flighting prefix and the newly loaded suffix remain ACKable.
        stream.outgoing().on_data_acked(&prefix);
        stream.outgoing().on_data_acked(&suffix);
        let mut empty = TestPacket(bytes::BytesMut::with_capacity(64));
        assert!(empty.load(&mut stream.multipath()).is_err());
        stream.writer().flush().await.unwrap();
    }

    #[tokio::test]
    async fn receiver_retirement_wakes_reader_and_preserves_crypto_retransmission() {
        let stream = CryptoStream::new();
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
        packet.load(&mut stream.outgoing()).unwrap();

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
        retransmission.load(&mut stream.outgoing()).unwrap();
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
        let stream = CryptoStream::new();
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
        assert!(packet.load(&mut stream.multipath()).is_err());
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
        let stream = CryptoStream::new();
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
        assert!(packet.load(&mut stream.multipath()).is_err());
        assert!(packet.0.is_empty());
    }

    #[tokio::test]
    async fn shutdown_is_unsupported_and_keeps_unacknowledged_data() {
        let stream = CryptoStream::new();
        stream.writer().write_all(b"outgoing").await.unwrap();
        assert_eq!(
            stream.writer().shutdown().await.unwrap_err().kind(),
            std::io::ErrorKind::Unsupported,
        );
        let mut packet = TestPacket(bytes::BytesMut::with_capacity(64));
        packet.load(&mut stream.outgoing()).unwrap();
        assert!(packet.0.ends_with(b"outgoing"));
        stream.writer().write_all(b"still open").await.unwrap();
    }

    #[tokio::test]
    async fn acknowledging_crypto_wakes_flush() {
        let stream = CryptoStream::new();
        let mut writer = stream.writer();
        writer.write_all(b"hello").await.unwrap();
        let mut packet = TestPacket(bytes::BytesMut::with_capacity(64));
        packet.load(&mut stream.outgoing()).unwrap();
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
        let stream = CryptoStream::new();
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
        let crypto_stream: CryptoStream = CryptoStream::new();
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

mod poll_tests {
    use std::task::{Context, Poll, Waker};

    use bytes::BytesMut;
    use qbase::packet::{Constraints, GetType, LongHeaderBuilder, Package, PacketBuffer};
    use qrecovery::crypto::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn multipath_repeats_then_normal_outgoing_advances() {
        let stream = CryptoStream::new();
        stream.writer().write_all(b"client hello").await.unwrap();
        let ty = LongHeaderBuilder::with_cid(Default::default(), Default::default())
            .initial(vec![])
            .get_type();
        let mut cx = Context::from_waker(Waker::noop());
        let mut previous = None;
        for pass in 0..4 {
            let mut bytes = BytesMut::new();
            let mut frames = Vec::new();
            let mut limits = Constraints {
                flow_ctrl: 0,
                send_quota: 100,
                credit: 100,
                min_size: 0,
                max_size: 100,
                ..Default::default()
            };
            let mut buffer = PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0);
            let result = if pass < 2 {
                stream.multipath().poll_dump(&mut cx, &mut buffer)
            } else {
                stream.outgoing().poll_dump(&mut cx, &mut buffer)
            };
            if pass == 3 {
                assert!(result.is_pending());
                assert!(frames.is_empty());
            } else {
                assert!(matches!(result, Poll::Ready(Ok(1))));
                assert!(matches!(
                    frames.as_slice(),
                    [qbase::frame::GuaranteedFrame::Crypto(_)]
                ));
                if let Some(previous) = &previous {
                    assert_eq!(&bytes, previous);
                }
                previous = Some(bytes);
            }
        }
    }
}
