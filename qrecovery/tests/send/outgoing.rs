use std::task::{Context, Poll, Waker};

use bytes::BytesMut;
use qbase::{
    frame::{FrameType, GuaranteedFrame, Len, StreamFrame},
    net::tx::UnregisterWaker,
    packet::{GetType, OneRttHeader, Package, PacketBuffer},
    role::Role,
    sid::{Dir, StreamId},
};
use qrecovery::{send::CancelStream, streams::DataStreams};
use tokio::io::AsyncWriteExt;

use super::sender::{Broker, stream};

#[tokio::test]
async fn closed_stream_outgoing_is_empty_but_its_writer_keeps_the_error() {
    let (mut outgoing, mut writer) = stream(100);
    writer.write_all(b"queued").await.unwrap();
    let error = qbase::error::AppError::new(42u32.into(), "closed").into();
    outgoing.on_error(&error);
    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let limits_quota = 128;
    let limits_length = 128;
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    for _ in 0..2 {
        let mut writer_0 = bytes::BufMut::limit(&mut bytes, limits_length);
        let mut buffer = PacketBuffer::new(&mut writer_0, limits_quota, &mut frames, ty, 0, 0);
        assert_eq!(
            outgoing.poll_dump(&mut Context::from_waker(Waker::noop()), &mut buffer),
            Poll::Ready(Ok(0))
        );
    }
    assert!(bytes.is_empty());
    assert!(frames.is_empty());
    assert_eq!(
        writer.poll_ready(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(qrecovery::streams::error::StreamError::Connection(
            error
        ))),
    );
    assert!(writer.write_all(b"late").await.is_err());
}

#[derive(Default)]
struct Counter(std::sync::atomic::AtomicUsize);
impl std::task::Wake for Counter {
    fn wake(self: std::sync::Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[tokio::test]
async fn streams_own_waiters_across_states_and_cancel_each_path() {
    use std::sync::{Arc, atomic::Ordering};
    let (mut source, mut writer) = stream(100);
    let (mut other, mut other_writer) = stream(100);
    let a = Arc::new(Counter::default());
    let b = Arc::new(Counter::default());
    let c = Arc::new(Counter::default());
    let wa = Waker::from(a.clone());
    let wb = Waker::from(b.clone());
    let wc = Waker::from(c.clone());
    let poll = |source: &mut DataStreams<Broker>, waker: &Waker| {
        let mut bytes = BytesMut::new();
        let mut frames = Vec::new();
        let limits_quota = 128;
        let limits_length = 128;
        let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
        let mut writer_1 = bytes::BufMut::limit(&mut bytes, limits_length);
        source.poll_dump(
            &mut Context::from_waker(waker),
            &mut PacketBuffer::new(&mut writer_1, limits_quota, &mut frames, ty, 0, 0),
        )
    };
    assert!(poll(&mut source, &wa).is_pending());
    assert!(poll(&mut source, &wb).is_pending());
    assert!(poll(&mut other, &wc).is_pending());
    writer.write_all(b"first").await.unwrap();
    assert_eq!(a.0.load(Ordering::Relaxed), 1);
    assert_eq!(b.0.load(Ordering::Relaxed), 1);
    assert_eq!(c.0.load(Ordering::Relaxed), 0);
    assert!(matches!(poll(&mut source, &wa), Poll::Ready(Ok(1))));
    source.unregister(&wa);
    writer.write_all(b"next").await.unwrap();
    assert_eq!(a.0.load(Ordering::Relaxed), 1);
    assert_eq!(b.0.load(Ordering::Relaxed), 2);
    assert!(futures::poll!(Box::pin(writer.shutdown())).is_pending());
    assert!(matches!(poll(&mut source, &wb), Poll::Ready(Ok(1))));
    let before = b.0.load(Ordering::Relaxed);
    let frame = StreamFrame::new(StreamId::new(Role::Client, Dir::Bi, 0), 0, 5);
    source.may_loss_data(&frame);
    assert_eq!(b.0.load(Ordering::Relaxed), before + 1);
    source.unregister(&wb);
    source.may_loss_data(&frame);
    assert_eq!(b.0.load(Ordering::Relaxed), before + 1);
    other_writer.write_all(b"other").await.unwrap();
    assert_eq!(c.0.load(Ordering::Relaxed), 1);
    writer.cancel(0);
    other_writer.cancel(0);
}

#[tokio::test]
async fn retransmissions_need_no_fresh_credit_and_fin_waits_for_space() {
    let (mut source, mut writer) = stream(100);
    writer.write_all(b"0123456789").await.unwrap();
    assert!(futures::poll!(Box::pin(writer.shutdown())).is_pending());
    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let mut limits_quota = 12;
    let limits_length = 12;
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let mut cx = Context::from_waker(Waker::noop());
    let mut writer_2 = bytes::BufMut::limit(&mut bytes, limits_length);
    let mut buffer = PacketBuffer::new(&mut writer_2, limits_quota, &mut frames, ty, 0, 0);
    assert!(matches!(
        source.poll_dump(&mut cx, &mut buffer),
        Poll::Ready(Ok(1))
    ));
    let GuaranteedFrame::Stream(frame) = buffer.frames[0] else {
        panic!()
    };
    assert_eq!(frame.len(), 10);
    assert!(matches!(
        qbase::frame::GetFrameType::frame_type(&frame),
        FrameType::Stream(_, Len::Omit, _)
    ));
    assert!(frame.is_fin());
    let mut ack = qbase::frame::AckFrame::new(0u32.into(), 0u32.into(), 0u32.into(), vec![], None);
    assert!(matches!(
        ack.poll_dump(&mut cx, &mut buffer),
        Poll::Ready(Ok(0))
    ));
    source.may_loss_data(&frame);
    bytes.clear();
    frames.clear();
    limits_quota = 0;
    let mut writer_3 = bytes::BufMut::limit(&mut bytes, limits_length);
    let mut buffer = PacketBuffer::new(&mut writer_3, limits_quota, &mut frames, ty, 0, 0);
    assert!(matches!(
        source.poll_dump(&mut cx, &mut buffer),
        Poll::Ready(Ok(0))
    ));
    assert!(buffer.frames.is_empty());
    limits_quota = 12;
    let mut writer_4 = bytes::BufMut::limit(&mut bytes, limits_length);
    let mut buffer = PacketBuffer::new(&mut writer_4, limits_quota, &mut frames, ty, 0, 0);
    assert!(matches!(
        source.poll_dump(&mut cx, &mut buffer),
        Poll::Ready(Ok(1))
    ));
    assert_eq!(frames, vec![GuaranteedFrame::Stream(frame)]);
    writer.cancel(0);
}
