use std::{
    sync::Arc,
    task::{Context, Poll, Waker},
};

use bytes::{Bytes, BytesMut};
use qbase::{
    frame::{GuaranteedFrame, MaxStreamDataFrame, StreamCtlFrame, io::SendFrame},
    packet::{Constraints, GetType, OneRttHeader, Package, PacketBuffer},
    param::{ArcParameters, ClientParameters, ParameterId, ServerParameters},
    role::Role,
    sid::{Dir, StreamId, handy::DemandConcurrency},
};
use qrecovery::{
    send::{CancelStream, Writer},
    streams::{DataStreams, Ext},
};

#[derive(Clone)]
pub(super) struct Broker;
impl<T> SendFrame<T> for Broker {
    fn send_frame<I: IntoIterator<Item = T>>(&self, _: I) {}
}

pub(super) fn stream(window: u64) -> (DataStreams<Broker>, Writer<Ext<Broker>>) {
    let streams = DataStreams::new(
        ArcParameters::new(
            Role::Client,
            Arc::new(ClientParameters::default()),
            Arc::new(ServerParameters::default()),
        ),
        Box::new(DemandConcurrency),
        Broker,
        None,
    );
    let Poll::Ready(Ok(Some((_, (_, writer))))) =
        streams.poll_open_bi_with_limit(&mut Context::from_waker(Waker::noop()), window)
    else {
        panic!("stream should open")
    };
    (streams, writer)
}

fn send(streams: &mut DataStreams<Broker>) -> Vec<GuaranteedFrame> {
    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let mut limits = Constraints {
        flow_ctrl: 1000,
        send_quota: 1200,
        credit: 1200,
        max_size: 1200,
        ..Default::default()
    };
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let _ = streams
        .poll_dump(
            &mut Context::from_waker(Waker::noop()),
            &mut PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0),
        )
        .map(Result::unwrap);
    frames
}

#[test]
fn test_ready_sender_new() {
    let (mut streams, mut writer) = stream(1000);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(writer.poll_ready(&mut cx), Poll::Ready(Ok(()))));
    writer.write(Bytes::from(vec![0; 1000])).unwrap();
    assert!(writer.poll_ready(&mut cx).is_pending());
    let frames = send(&mut streams);
    assert!(
        matches!(&frames[..], [GuaranteedFrame::Stream(frame)] if frame.stream_id() == StreamId::new(Role::Client, Dir::Bi, 0) && frame.len() == 1000)
    );
    writer.cancel(0);
}

#[test]
fn test_ready_sender_write() {
    let (_, mut writer) = stream(10);
    assert!(writer.write(Bytes::from_static(b"hello")).is_ok());
    assert!(writer.write(Bytes::from(vec![0; 1000])).is_ok());
    writer.cancel(0);
}

#[test]
fn test_ready_sender_poll_write() {
    let (streams, mut writer) = stream(10);
    writer.write(Bytes::from_static(b"test")).unwrap();
    let mut params = ServerParameters::default();
    params
        .set(ParameterId::InitialMaxStreamDataBidiRemote, 0u32)
        .unwrap();
    streams.revise_params(true, &params);
    assert!(
        writer
            .poll_ready(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    writer.cancel(0);
}

#[test]
fn test_sender_state_transitions() {
    let (mut streams, mut writer) = stream(1000);
    let mut cx = Context::from_waker(Waker::noop());
    writer.write(Bytes::from_static(b"data")).unwrap();
    let frames = send(&mut streams);
    let GuaranteedFrame::Stream(frame) = frames[0] else {
        panic!("expected STREAM")
    };
    assert_eq!(frame.stream_id(), StreamId::new(Role::Client, Dir::Bi, 0));
    assert!(!frame.is_fin());
    streams.on_data_acked(frame);
    assert!(writer.poll_shutdown(&mut cx).is_pending());
    let frames = send(&mut streams);
    let GuaranteedFrame::Stream(fin) = frames[0] else {
        panic!("expected FIN")
    };
    assert_eq!(fin.stream_id(), frame.stream_id());
    assert!(fin.is_fin());
    streams.on_data_acked(fin);
    assert!(matches!(writer.poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
}

#[test]
fn test_arc_sender() {
    let (streams, mut writer) = stream(1000);
    let sid = StreamId::new(Role::Client, Dir::Bi, 0);
    streams
        .recv_stream_control(StreamCtlFrame::MaxStreamData(MaxStreamDataFrame::new(
            sid,
            2000u32.into(),
        )))
        .unwrap();
    writer.write(Bytes::from(vec![0; 1000])).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(writer.poll_ready(&mut cx), Poll::Ready(Ok(()))));
    writer.write(Bytes::from(vec![0; 1000])).unwrap();
    assert!(writer.poll_ready(&mut cx).is_pending());
    writer.cancel(0);
}

#[test]
fn test_data_sent_sender() {
    let (mut streams, mut writer) = stream(1000);
    assert!(
        writer
            .poll_shutdown(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let frames = send(&mut streams);
    assert!(
        matches!(&frames[..], [GuaranteedFrame::Stream(frame)] if frame.is_fin() && frame.is_empty())
    );
    assert!(send(&mut streams).is_empty());
    writer.cancel(0);
}

#[test]
fn test_data_sent_sender_polling() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Default)]
    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let (mut streams, mut writer) = stream(1000);
    assert!(
        writer
            .poll_shutdown(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let frames = send(&mut streams);
    let GuaranteedFrame::Stream(fin) = frames[0] else {
        panic!("expected FIN")
    };
    let count = Arc::new(Counter::default());
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(writer.poll_flush(&mut cx).is_pending());
    assert!(writer.poll_shutdown(&mut cx).is_pending());
    streams.on_data_acked(fin);
    assert!(count.0.load(Ordering::Relaxed) > 0);
    assert!(matches!(writer.poll_flush(&mut cx), Poll::Ready(Ok(()))));
    assert!(matches!(writer.poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
}
