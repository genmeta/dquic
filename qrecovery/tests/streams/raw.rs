use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::BytesMut;
use qbase::{
    frame::{GuaranteedFrame, io::SendFrame},
    net::tx::UnregisterWaker,
    packet::{Package, PacketContent},
    param::{ArcParameters, ClientParameters, ServerParameters},
    role::Role,
    sid::{Dir, handy::DemandConcurrency},
};
use qrecovery::streams::ArcDataStreams;
use tokio::io::AsyncWrite;

#[derive(Clone, Copy)]
struct MockFrameSender;

impl<F> SendFrame<F> for MockFrameSender {
    fn send_frame<I: IntoIterator<Item = F>>(&self, _iter: I) {}
}

fn packet_frames(streams: &mut ArcDataStreams<MockFrameSender>, waker: &std::task::Waker) -> Vec<GuaranteedFrame> {
    packet_frames_with_capacity(streams, waker, 1200)
}

fn packet_frames_with_capacity(
    streams: &mut ArcDataStreams<MockFrameSender>,
    waker: &std::task::Waker,
    capacity: usize,
) -> Vec<GuaranteedFrame> {
    use qbase::packet::{GetType, OneRttHeader, PacketBuffer};

    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let limits_quota = capacity;
    let limits_length = capacity;
    let mut writer_0 = bytes::BufMut::limit(&mut bytes, limits_length);
    let result = streams.poll_dump(
        &mut Context::from_waker(waker),
        &mut PacketBuffer::new(
            &mut writer_0,
            limits_quota,
            &mut frames,
            OneRttHeader::new(Default::default(), Default::default()).get_type(),
            0,
            0,
        ),
    );
    assert!(matches!(result, Poll::Ready(Ok(n)) if n > 0));
    frames
}

#[test]
fn busy_streams_take_turns_before_either_exhausts_its_window() {
    use qrecovery::send::CancelStream;

    let mut streams = ArcDataStreams::new(
        ArcParameters::new(Role::Client, Arc::new(ClientParameters::default()), Arc::new(ServerParameters::default())),
        Box::new(DemandConcurrency),
        MockFrameSender,
        Default::default(),
    );
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut writers = Vec::new();
    for _ in 0..2 {
        let Poll::Ready(Ok(Some((id, mut writer)))) = std::pin::pin!(streams.open_uni()).poll(&mut cx) else {
            panic!("stream should open");
        };
        writer.write(bytes::Bytes::from(vec![7; 64 * 1024])).unwrap();
        writers.push((id, writer));
    }
    let mut sent = std::collections::HashMap::new();
    assert_eq!(streams.fresh_bytes_up_to(0), 0);
    assert_eq!(streams.fresh_bytes_up_to(1200), 1200);
    assert_eq!(streams.fresh_bytes(), 128 * 1024);
    for _ in 0..10 {
        for frame in packet_frames(&mut streams, cx.waker()) {
            if let GuaranteedFrame::Stream(frame) = frame {
                *sent.entry(frame.stream_id()).or_insert(0usize) += frame.len();
            }
        }
    }
    assert_eq!(streams.fresh_bytes(), 128 * 1024 - sent.values().sum::<usize>());
    for (_, writer) in &mut writers {
        writer.cancel(0);
    }
    assert_eq!(sent.len(), 2, "one busy stream must not starve the other");
    let bytes = sent.values().copied().collect::<Vec<_>>();
    assert!(bytes[0].abs_diff(bytes[1]) <= 4096, "{sent:?}");
}

#[test]
fn busy_streams_share_byte_turns_across_packets_and_paths() {
    use qrecovery::send::CancelStream;

    let streams = ArcDataStreams::new(
        ArcParameters::new(Role::Client, Arc::new(ClientParameters::default()), Arc::new(ServerParameters::default())),
        Box::new(DemandConcurrency),
        MockFrameSender,
        Default::default(),
    );
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut writers = Vec::new();
    let mut sent = std::collections::HashMap::new();
    for _ in 0..3 {
        let Poll::Ready(Ok(Some((sid, mut writer)))) = std::pin::pin!(streams.open_uni()).poll(&mut cx) else {
            panic!("stream should open");
        };
        writer.write(bytes::Bytes::from(vec![7; 64 * 1024])).unwrap();
        sent.insert(sid, 0usize);
        writers.push(writer);
    }
    let mut paths = [streams.clone(), streams];
    for (index, capacity) in [1200, 9000, 128, 7000, 900, 20000, 1200, 9000].into_iter().enumerate() {
        for frame in packet_frames_with_capacity(&mut paths[index % 2], cx.waker(), capacity) {
            if let GuaranteedFrame::Stream(frame) = frame {
                assert!(frame.len() <= 4096);
                *sent.get_mut(&frame.stream_id()).unwrap() += frame.len();
            }
        }
        assert!(sent.values().max().unwrap() - sent.values().min().unwrap() <= 4096, "{sent:?}");
    }
    assert!(sent.values().all(|&bytes| bytes > 4096), "every busy stream must receive multiple turns");
    assert_eq!(paths[0].fresh_bytes(), 3 * 64 * 1024 - sent.values().sum::<usize>());
    for writer in &mut writers {
        writer.cancel(0);
    }
}

#[test]
fn retransmissions_spend_stream_turn_without_spending_flow_credit() {
    use qrecovery::send::CancelStream;

    let mut streams = ArcDataStreams::new(
        ArcParameters::new(Role::Client, Arc::new(ClientParameters::default()), Arc::new(ServerParameters::default())),
        Box::new(DemandConcurrency),
        MockFrameSender,
        Default::default(),
    );
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut writers = Vec::new();
    for _ in 0..2 {
        let Poll::Ready(Ok(Some((_, mut writer)))) = std::pin::pin!(streams.open_uni()).poll(&mut cx) else {
            panic!("stream should open");
        };
        writer.write(bytes::Bytes::from(vec![7; 64 * 1024])).unwrap();
        writers.push(writer);
    }
    let first = packet_frames(&mut streams, cx.waker());
    let [GuaranteedFrame::Stream(frame)] = first.as_slice() else {
        panic!("expected one STREAM frame");
    };
    streams.may_loss_data(frame);
    let fresh = streams.fresh_bytes();
    assert_eq!(packet_frames(&mut streams, cx.waker()), first);
    assert_eq!(streams.fresh_bytes(), fresh);

    let mut current_bytes = 2 * frame.len();
    let mut other_bytes = 0;
    for next in packet_frames_with_capacity(&mut streams, cx.waker(), 4096) {
        if let GuaranteedFrame::Stream(next) = next {
            if next.stream_id() == frame.stream_id() {
                current_bytes += next.len();
            } else {
                other_bytes += next.len();
            }
        }
    }
    assert_eq!(current_bytes, 4096, "retransmissions consume the same turn as new data");
    assert!(other_bytes > 0, "the other stream must run when that turn is exhausted");
    for writer in &mut writers {
        writer.cancel(0);
    }
}

#[test]
fn removed_current_stream_and_blocked_stream_do_not_stop_other_streams() {
    use qbase::frame::{MaxStreamDataFrame, StreamCtlFrame};
    use qrecovery::send::CancelStream;

    let mut streams = ArcDataStreams::new(
        ArcParameters::new(Role::Client, Arc::new(ClientParameters::default()), Arc::new(ServerParameters::default())),
        Box::new(DemandConcurrency),
        MockFrameSender,
        Default::default(),
    );
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut writers = Vec::new();
    for window in [0, 100, 100] {
        let Poll::Ready(Ok(Some((sid, writer)))) = streams.poll_open_uni_with_limit(&mut cx, window) else {
            panic!("stream should open");
        };
        writers.push((sid, writer));
    }
    writers[0].1.write(bytes::Bytes::from_static(b"zero")).unwrap();
    writers[1].1.write(bytes::Bytes::from_static(b"middle")).unwrap();
    writers[2].1.write(bytes::Bytes::from_static(b"last")).unwrap();
    assert!(writers[2].1.poll_shutdown(&mut cx).is_pending());

    let frames = packet_frames_with_capacity(&mut streams, cx.waker(), 6);
    let [GuaranteedFrame::Stream(frame)] = frames.as_slice() else {
        panic!("expected one STREAM frame");
    };
    assert_eq!(frame.stream_id(), writers[2].0);
    assert!(frame.is_fin());
    streams.on_data_acked(*frame);
    let frames = packet_frames(&mut streams, cx.waker());
    assert!(frames.iter().all(|frame| matches!(frame, GuaranteedFrame::Stream(frame) if frame.stream_id() == writers[1].0)));

    streams.recv_stream_control(StreamCtlFrame::MaxStreamData(MaxStreamDataFrame::new(writers[0].0, 100u32.into()))).unwrap();
    let frames = packet_frames(&mut streams, cx.waker());
    assert!(frames.iter().all(|frame| matches!(frame, GuaranteedFrame::Stream(frame) if frame.stream_id() == writers[0].0)));
    for (_, writer) in &mut writers {
        writer.cancel(0);
    }
}

#[test]
fn full_packet_does_not_subscribe_to_idle_streams() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Wake, Waker},
    };

    use qrecovery::send::CancelStream;

    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let mut streams = ArcDataStreams::new(
        ArcParameters::new(Role::Client, Arc::new(ClientParameters::default()), Arc::new(ServerParameters::default())),
        Box::new(DemandConcurrency),
        MockFrameSender,
        Default::default(),
    );
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    let mut writers = Vec::new();
    for _ in 0..32 {
        let Poll::Ready(Ok(Some((_, writer)))) = std::pin::pin!(streams.open_uni()).poll(&mut cx) else {
            panic!("stream should open");
        };
        writers.push(writer);
    }
    // The highest ID is visited first and fills the packet completely.
    writers.last_mut().unwrap().write(bytes::Bytes::from(vec![7; 4096])).unwrap();
    packet_frames(&mut streams, &waker);
    for writer in &mut writers[..31] {
        writer.write(bytes::Bytes::from_static(b"next")).unwrap();
    }
    let wakes = counter.0.load(Ordering::Relaxed);
    for writer in &mut writers {
        writer.cancel(0);
    }
    assert_eq!(wakes, 0, "a full packet must not poll and subscribe idle streams");
}

#[test]
fn idle_stream_resumes_for_writes_retransmission_and_fin() {
    let metrics = qbase::metric::ArcConnectionMetrics::default();
    let mut streams = ArcDataStreams::new(
        ArcParameters::new(Role::Client, Arc::new(ClientParameters::default()), Arc::new(ServerParameters::default())),
        Box::new(DemandConcurrency),
        MockFrameSender,
        metrics.clone(),
    );
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let Poll::Ready(Ok(Some((_, mut writer)))) = std::pin::pin!(streams.open_uni()).poll(&mut cx) else {
        panic!("stream should open")
    };
    writer.write(bytes::Bytes::from_static(b"first")).unwrap();
    assert_eq!(metrics.pending_bytes(), 5);
    let frames = packet_frames(&mut streams, cx.waker());
    let GuaranteedFrame::Stream(first) = frames[0] else {
        panic!("expected stream data")
    };
    assert_eq!(streams.fresh_bytes(), 0);
    assert_eq!(metrics.pending_bytes(), 0);
    assert_eq!(metrics.inflight_bytes(), 5);

    streams.may_loss_data(&first);
    assert_eq!(streams.fresh_bytes(), 0, "retransmissions use no new flow credit");
    let frames = packet_frames(&mut streams, cx.waker());
    let GuaranteedFrame::Stream(resent) = frames[0] else {
        panic!("expected retransmission")
    };
    assert_eq!(resent.range(), first.range());
    assert_eq!(metrics.pending_bytes(), 0);
    assert_eq!(metrics.inflight_bytes(), 5);
    streams.on_data_acked(resent);
    assert_eq!(metrics.inflight_bytes(), 0);
    assert_eq!(metrics.acked_bytes(), 5);

    writer.write(bytes::Bytes::from_static(b"next")).unwrap();
    assert_eq!(metrics.pending_bytes(), 4);
    assert_eq!(streams.fresh_bytes(), 4);
    let frames = packet_frames(&mut streams, cx.waker());
    let GuaranteedFrame::Stream(next) = frames[0] else {
        panic!("expected new data")
    };
    assert_eq!(next.range(), 5..9);
    streams.on_data_acked(next);

    assert!(writer.poll_shutdown(&mut cx).is_pending());
    let frames = packet_frames(&mut streams, cx.waker());
    let GuaranteedFrame::Stream(fin) = frames[0] else {
        panic!("expected FIN")
    };
    assert!(fin.is_fin());
    assert_eq!(fin.range(), 9..9);
    streams.may_loss_data(&fin);
    let frames = packet_frames(&mut streams, cx.waker());
    let GuaranteedFrame::Stream(resent_fin) = frames[0] else {
        panic!("expected FIN retransmission")
    };
    assert!(resent_fin.is_fin());
    assert_eq!(resent_fin.range(), fin.range());
    streams.on_data_acked(resent_fin);
    assert_eq!(metrics.pending_bytes(), 0);
    assert_eq!(metrics.inflight_bytes(), 0);
    assert_eq!(metrics.acked_bytes(), 9);
    assert!(matches!(writer.poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
}

#[test]
fn exhausted_connection_credit_keeps_retransmission_available_with_fresh_data_queued() {
    let mut remote = ServerParameters::default();
    remote.set(qbase::param::ParameterId::InitialMaxData, 5u32).unwrap();
    let mut streams = ArcDataStreams::new(
        ArcParameters::new(Role::Client, Arc::new(ClientParameters::default()), Arc::new(remote)),
        Box::new(DemandConcurrency),
        MockFrameSender,
        Default::default(),
    );
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let Poll::Ready(Ok(Some((_, mut writer)))) = std::pin::pin!(streams.open_uni()).poll(&mut cx) else {
        panic!("stream should open")
    };
    writer.write(bytes::Bytes::from_static(b"first")).unwrap();
    let first = packet_frames(&mut streams, cx.waker());
    let GuaranteedFrame::Stream(first) = first[0] else {
        panic!("expected stream data")
    };
    writer.write(bytes::Bytes::from_static(b"next")).unwrap();
    streams.may_loss_data(&first);
    let retransmitted = packet_frames(&mut streams, cx.waker());
    let GuaranteedFrame::Stream(retransmitted) = retransmitted[0] else {
        panic!("expected retransmission")
    };
    assert_eq!(retransmitted.range(), first.range());
    assert_eq!(streams.fresh_bytes(), 4, "fresh data still needs connection credit");
}

#[test]
fn receive_limits_follow_the_local_stream_direction() {
    use qbase::{error::ErrorKind, frame::StreamFrame, param::ParameterId, sid::StreamId};
    use qrecovery::send::CancelStream;

    for role in [Role::Client, Role::Server] {
        for (local, dir, limit) in [(true, Dir::Bi, 3), (false, Dir::Bi, 5), (false, Dir::Uni, 7)] {
            let mut client = ClientParameters::default();
            let mut server = ServerParameters::default();
            for (id, value) in [
                (ParameterId::InitialMaxStreamDataBidiLocal, 3u32),
                (ParameterId::InitialMaxStreamDataBidiRemote, 5),
                (ParameterId::InitialMaxStreamDataUni, 7),
            ] {
                client.set(id, if role == Role::Client { value } else { 100 }).unwrap();
                server.set(id, if role == Role::Server { value } else { 100 }).unwrap();
            }
            let streams = ArcDataStreams::new(
                ArcParameters::new(role, Arc::new(client), Arc::new(server)),
                Box::new(DemandConcurrency),
                MockFrameSender,
                Default::default(),
            );
            let sid = if local {
                let mut cx = Context::from_waker(futures::task::noop_waker_ref());
                let Poll::Ready(Ok(Some((sid, (_, mut writer))))) = streams.poll_open_bi_with_limit(&mut cx, 0) else {
                    panic!("peer must allow a bidirectional stream");
                };
                writer.cancel(0);
                sid
            } else {
                StreamId::new(!role, dir, 0)
            };
            assert_eq!(streams.recv_data((StreamFrame::new(sid, limit - 1, 1), bytes::Bytes::from_static(b"x"),)), Ok(limit as usize));
            let error = streams.recv_data((StreamFrame::new(sid, limit, 1), bytes::Bytes::from_static(b"x"))).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::FlowControl);
        }
    }
}

#[test]
fn open_uni_uses_the_remote_unidirectional_limit() {
    use qbase::param::ParameterId;
    use qrecovery::send::CancelStream;

    let mut client = ClientParameters::default();
    client.set(ParameterId::InitialMaxStreamDataUni, 0u32).unwrap();
    let server = ServerParameters::default();
    let streams = ArcDataStreams::new(
        ArcParameters::new(Role::Server, Arc::new(client), Arc::new(server)),
        Box::new(DemandConcurrency),
        MockFrameSender,
        Default::default(),
    );
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    let Poll::Ready(Ok(Some((_, mut writer)))) = std::pin::pin!(streams.open_uni()).poll(&mut cx) else {
        panic!("ready parameters must allow opening the stream immediately");
    };
    let ready = writer.poll_ready(&mut cx);
    writer.cancel(0);
    assert!(ready.is_pending(), "zero uni limit must block writing");
}

#[test]
fn ready_streams_use_current_parameters_even_with_remembered_limits() {
    use qrecovery::send::CancelStream;

    let client = ClientParameters::default();
    let server = ServerParameters::default();
    // Missing remembered limits prohibit writing; current parameters permit it.
    let parameters =
        ArcParameters::new(Role::Client, Arc::new(client), Arc::new(server)).with_remembered(Some(Arc::new(ServerParameters::new())));
    let streams = ArcDataStreams::new(parameters, Box::new(DemandConcurrency), MockFrameSender, Default::default());
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    let Poll::Ready(Ok(Some((_, (_, mut bi))))) = std::pin::pin!(streams.open_bi()).poll(&mut cx) else {
        panic!("ready parameters must allow opening the bidirectional stream");
    };
    let Poll::Ready(Ok(Some((_, mut uni)))) = std::pin::pin!(streams.open_uni()).poll(&mut cx) else {
        panic!("ready parameters must allow opening the unidirectional stream");
    };
    let bi_ready = bi.poll_ready(&mut cx);
    let uni_ready = uni.poll_ready(&mut cx);
    bi.cancel(0);
    uni.cancel(0);
    assert!(matches!(bi_ready, Poll::Ready(Ok(()))));
    assert!(matches!(uni_ready, Poll::Ready(Ok(()))));
}

#[tokio::test]
async fn empty_collection_wakes_for_new_stream_and_cancels_stream_waiters() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Wake, Waker},
    };

    use tokio::io::AsyncWriteExt;
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let streams = ArcDataStreams::new(
        ArcParameters::new(Role::Client, Arc::new(ClientParameters::default()), Arc::new(ServerParameters::default())),
        Box::new(DemandConcurrency),
        MockFrameSender,
        Default::default(),
    );
    let a = Arc::new(Counter(AtomicUsize::new(0)));
    let b = Arc::new(Counter(AtomicUsize::new(0)));
    let wa = Waker::from(a.clone());
    let wb = Waker::from(b.clone());
    let mut source = streams.clone();
    let mut poll = |waker: &Waker| {
        use qbase::packet::{GetType, OneRttHeader};
        let mut bytes = BytesMut::new();
        let mut frames = Vec::new();
        let limits_quota = 128;
        let limits_length = 128;
        let mut writer_1 = bytes::BufMut::limit(&mut bytes, limits_length);
        source.poll_dump(
            &mut Context::from_waker(waker),
            &mut qbase::packet::PacketBuffer::new(
                &mut writer_1,
                limits_quota,
                &mut frames,
                OneRttHeader::new(Default::default(), Default::default()).get_type(),
                0,
                0,
            ),
        )
    };
    assert!(poll(&wa).is_pending());
    assert!(poll(&wb).is_pending());
    let Poll::Ready(Ok(Some((_, mut writer)))) = streams.poll_open_uni_with_limit(&mut Context::from_waker(Waker::noop()), 100) else {
        panic!("stream should open");
    };
    assert_eq!(a.0.load(Ordering::Relaxed), 1);
    assert_eq!(b.0.load(Ordering::Relaxed), 1);
    // Re-polling discovers the new stream and subscribes both paths to its state.
    assert!(poll(&wa).is_pending());
    assert!(poll(&wb).is_pending());
    streams.unregister(&wa);
    writer.write_all(b"data").await.unwrap();
    assert_eq!(a.0.load(Ordering::Relaxed), 1);
    assert_eq!(b.0.load(Ordering::Relaxed), 2);
    assert!(matches!(poll(&wb), Poll::Ready(Ok(n)) if n > 0));
    streams.unregister(&wb);
    writer.write_all(b"more").await.unwrap();
    assert_eq!(b.0.load(Ordering::Relaxed), 2);
    let c = Arc::new(Counter(AtomicUsize::new(0)));
    let wc = Waker::from(c.clone());
    assert!(matches!(poll(&wc), Poll::Ready(Ok(n)) if n > 0));
    let Poll::Ready(Ok(Some((_, mut next)))) = streams.poll_open_uni_with_limit(&mut Context::from_waker(Waker::noop()), 100) else {
        panic!("stream should open");
    };
    assert_eq!(a.0.load(Ordering::Relaxed), 1);
    assert_eq!(b.0.load(Ordering::Relaxed), 2);
    assert_eq!(c.0.load(Ordering::Relaxed), 0);
    streams.unregister(&wc);
    use qrecovery::send::CancelStream;
    writer.cancel(0);
    next.cancel(0);
}

#[test]
fn closed_collection_releases_cancelled_waiters() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Wake, Waker},
    };

    struct Waiter(AtomicUsize);
    impl Wake for Waiter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let mut streams = ArcDataStreams::new(
        ArcParameters::new(Role::Client, Arc::new(ClientParameters::default()), Arc::new(ServerParameters::default())),
        Box::new(DemandConcurrency),
        MockFrameSender,
        Default::default(),
    );
    let waiter = Arc::new(Waiter(AtomicUsize::new(0)));
    let waker = Waker::from(waiter.clone());
    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let mut buffer = bytes::BufMut::limit(&mut bytes, 128);
    use qbase::packet::{GetType, OneRttHeader, PacketBuffer};
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    assert!(
        streams.poll_dump(&mut Context::from_waker(&waker), &mut PacketBuffer::new(&mut buffer, 128, &mut frames, ty, 0, 0)).is_pending()
    );

    streams.on_error(&qbase::error::AppError::new(42u32.into(), "closed").into());
    assert_eq!(waiter.0.load(Ordering::Relaxed), 1, "closing must wake the blocked sender");
    streams.unregister(&waker);
    assert_eq!(Arc::strong_count(&waiter), 2, "only the test and its waker may retain the cancelled waiter");
}

#[test]
fn connection_error_preserves_received_but_unread_stream() {
    use qbase::{
        error::{Error, ErrorKind, QuicError},
        frame::StreamFrame,
    };

    let streams = ArcDataStreams::new(
        ArcParameters::new(Role::Client, Arc::new(ClientParameters::default()), Arc::new(ServerParameters::default())),
        Box::new(DemandConcurrency),
        MockFrameSender,
        Default::default(),
    );
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let Poll::Ready(Ok(Some((sid, (mut reader, mut writer))))) = std::pin::pin!(streams.open_bi()).poll(&mut cx) else {
        panic!("stream should open")
    };
    use qrecovery::send::CancelStream;
    writer.cancel(0);
    let mut frame = StreamFrame::new(sid, 0, 4);
    frame.set_eos_flag(true);
    streams.recv_data((frame, bytes::Bytes::from_static(b"data"))).unwrap();
    let error: Error = QuicError::with_default_fty(ErrorKind::Internal, "closed").into();
    streams.on_error(&error);
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    let mut buf = BytesMut::with_capacity(4);
    assert!(matches!(reader.poll_read(&mut cx, &mut buf), Poll::Ready(Ok(()))));
    assert_eq!(&buf[..], b"data");
    buf.clear();
    assert!(matches!(reader.poll_read(&mut cx, &mut buf), Poll::Ready(Ok(()))));
    assert!(buf.is_empty());
}

#[test]
fn empty_stream_fin_is_effective_packet_content() {
    let mut streams = ArcDataStreams::new(
        ArcParameters::new(Role::Client, Arc::new(ClientParameters::default()), Arc::new(ServerParameters::default())),
        Box::new(DemandConcurrency),
        MockFrameSender,
        Default::default(),
    );
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    let Poll::Ready(Ok(Some((_, mut writer)))) = std::pin::pin!(streams.open_uni()).poll(&mut cx) else {
        panic!("stream should open")
    };
    assert!(Pin::new(&mut writer).poll_shutdown(&mut cx).is_pending());

    let mut packet = BytesMut::with_capacity(128);
    let limits_quota = 128;
    let limits_length = 128;
    use qbase::packet::GetType;
    let mut frames = Vec::new();
    let mut writer_2 = bytes::BufMut::limit(&mut packet, limits_length);
    let mut buffer = qbase::packet::PacketBuffer::new(
        &mut writer_2,
        limits_quota,
        &mut frames,
        qbase::packet::OneRttHeader::new(Default::default(), Default::default()).get_type(),
        0,
        0,
    );
    assert!(matches!(streams.poll_dump(&mut cx, &mut buffer), Poll::Ready(Ok(n)) if n > 0));
    assert_eq!(buffer.meta.content, PacketContent::EffectivePayload);
    assert!(frames.iter().any(|frame| matches!(frame, GuaranteedFrame::Stream(frame) if frame.is_fin())));
}
