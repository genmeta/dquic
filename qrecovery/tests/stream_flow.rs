use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Wake, Waker},
};

use bytes::{Bytes, BytesMut};
use futures::FutureExt;
use qbase::{
    error::ErrorKind,
    frame::{
        DataBlockedFrame, GuaranteedFrame, MaxDataFrame, ResetStreamFrame, StreamCtlFrame, StreamFrame,
        io::{ReceiveFrame, SendFrame},
    },
    packet::{GetType, OneRttHeader, Package, PacketBuffer},
    param::{ArcParameters, ClientParameters, ParameterId, ServerParameters},
    role::Role,
    sid::{Dir, StreamId, handy::DemandConcurrency},
};
use qrecovery::{send::CancelStream, streams::ArcDataStreams};
use tokio::io::AsyncWriteExt;

#[derive(Clone, Default)]
struct Broker(Arc<std::sync::Mutex<Vec<StreamCtlFrame>>>);

impl SendFrame<StreamCtlFrame> for Broker {
    fn send_frame<I: IntoIterator<Item = StreamCtlFrame>>(&self, frames: I) {
        self.0.lock().unwrap().extend(frames);
    }
}

fn streams(send_window: u32, recv_window: u32) -> ArcDataStreams<Broker> {
    let mut local = ClientParameters::default();
    let mut peer = ServerParameters::default();
    local.set(ParameterId::InitialMaxData, recv_window).unwrap();
    peer.set(ParameterId::InitialMaxData, send_window).unwrap();
    ArcDataStreams::new(
        ArcParameters::new(Role::Client, Arc::new(local), Arc::new(peer)),
        Box::new(DemandConcurrency),
        Broker::default(),
        Default::default(),
    )
}

fn collect(streams: ArcDataStreams<Broker>, waker: &Waker) -> Vec<GuaranteedFrame> {
    collect_with_quota(streams, waker, 128)
}

fn collect_with_quota(mut streams: ArcDataStreams<Broker>, waker: &Waker, quota: usize) -> Vec<GuaranteedFrame> {
    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let limits_quota = quota;
    let limits_length = 128;
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let mut writer_0 = bytes::BufMut::limit(&mut bytes, limits_length);
    let result =
        streams.poll_dump(&mut Context::from_waker(waker), &mut PacketBuffer::new(&mut writer_0, limits_quota, &mut frames, ty, 0, 0));
    assert!(!matches!(result, std::task::Poll::Ready(Err(_))));
    frames
}

#[tokio::test]
async fn restored_flow_credit_does_not_wake_a_packet_that_cannot_fit_stream_data() {
    let streams = streams(0, 100);
    let (_, mut writer) = streams.open_uni().now_or_never().unwrap().unwrap().unwrap();
    writer.write_all(b"data").await.unwrap();
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(counter.clone());
    assert!(collect(streams.clone(), &waker).is_empty());
    streams.recv_frame(StreamCtlFrame::MaxData(MaxDataFrame::new(7u32.into()))).unwrap();
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    assert!(collect_with_quota(streams.clone(), &waker, 1).is_empty());
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    assert_eq!(stream_bytes(&collect(streams, &waker)), 4);
    writer.cancel(0);
}

fn stream_bytes(frames: &[GuaranteedFrame]) -> usize {
    frames
        .iter()
        .map(|frame| match frame {
            GuaranteedFrame::Stream(frame) => frame.len(),
            _ => 0,
        })
        .sum()
}

#[derive(Default)]
struct Counter(AtomicUsize);

impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn paths_share_credit_and_retransmit_without_fresh_credit() {
    let streams = streams(7, 100);
    let mut writers = Vec::new();
    for _ in 0..2 {
        let (_, mut writer) = streams.open_uni().now_or_never().unwrap().unwrap().unwrap();
        writer.write_all(b"data").await.unwrap();
        writers.push(writer);
    }
    let frames = std::thread::scope(|scope| {
        let sends = (0..4)
            .map(|_| {
                let streams = streams.clone();
                scope.spawn(move || collect(streams, Waker::noop()))
            })
            .collect::<Vec<_>>();
        sends.into_iter().flat_map(|send| send.join().unwrap()).collect::<Vec<_>>()
    });
    assert_eq!(stream_bytes(&frames), 7);
    assert_eq!(streams.fresh_bytes(), 1);
    for frame in frames {
        if let GuaranteedFrame::Stream(frame) = frame {
            streams.may_loss_data(&frame);
        }
    }
    assert_eq!(stream_bytes(&collect(streams.clone(), Waker::noop())), 7);
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(counter.clone());
    assert!(collect(streams.clone(), &waker).is_empty());
    assert_eq!(counter.0.load(Ordering::Relaxed), 0);
    streams.recv_frame(StreamCtlFrame::MaxData(MaxDataFrame::new(8u32.into()))).unwrap();
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    assert_eq!(stream_bytes(&collect(streams, &waker)), 1);
    for writer in &mut writers {
        writer.cancel(0);
    }
}

#[test]
fn receive_credit_deduplicates_data_and_counts_reset_final_size() {
    let streams = streams(100, 8);
    let sid = StreamId::new(Role::Server, Dir::Uni, 0);
    let frame = (StreamFrame::new(sid, 0, 3), Bytes::from_static(b"abc"));
    assert_eq!(streams.recv_frame(frame.clone()).unwrap(), 3);
    assert_eq!(streams.recv_frame(frame).unwrap(), 0);
    let reset = StreamCtlFrame::ResetStream(ResetStreamFrame::new(sid, 0u32.into(), 9u32.into()));
    assert_eq!(streams.recv_frame(reset).unwrap_err().kind(), ErrorKind::FlowControl);
}

#[tokio::test]
async fn connection_flow_frames_use_the_stream_control_broker() {
    let broker = Broker::default();
    let mut local = ClientParameters::default();
    let mut peer = ServerParameters::default();
    local.set(ParameterId::InitialMaxData, 8u32).unwrap();
    peer.set(ParameterId::InitialMaxData, 0u32).unwrap();
    let streams = ArcDataStreams::new(
        ArcParameters::new(Role::Client, Arc::new(local), Arc::new(peer)),
        Box::new(DemandConcurrency),
        broker.clone(),
        Default::default(),
    );
    let (_, mut writer) = streams.open_uni().now_or_never().unwrap().unwrap().unwrap();
    writer.write_all(b"data").await.unwrap();
    assert!(collect(streams.clone(), Waker::noop()).is_empty());
    assert!(broker.0.lock().unwrap().iter().any(|frame| { matches!(frame, StreamCtlFrame::DataBlocked(frame) if frame.limit() == 0) }));
    streams.recv_frame(StreamCtlFrame::DataBlocked(DataBlockedFrame::new(8u32.into()))).unwrap();
    streams.recv_frame(StreamCtlFrame::MaxData(MaxDataFrame::new(4u32.into()))).unwrap();
    assert_eq!(stream_bytes(&collect(streams.clone(), Waker::noop())), 4);
    let sid = StreamId::new(Role::Server, Dir::Uni, 0);
    streams.recv_frame((StreamFrame::new(sid, 0, 4), Bytes::from_static(b"data"))).unwrap();
    assert!(broker.0.lock().unwrap().iter().any(|frame| { matches!(frame, StreamCtlFrame::MaxData(frame) if frame.max_data() == 12) }));
    writer.cancel(0);
}
