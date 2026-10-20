use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    error::Error,
    packet::{Constraints, GetType, OneRttHeader, Package, PacketBuffer, PacketContent},
    time::heartbeat::*,
};
use tokio::time::Instant;

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl std::task::Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn poll(
    heartbeat: &mut impl Package<BytesMut>,
    quota: usize,
    waker: &Waker,
) -> Poll<Result<usize, Error>> {
    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let mut limits = Constraints {
        send_quota: quota,
        credit: 1,
        max_size: 1,
        ..Default::default()
    };
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let result = heartbeat.poll_dump(
        &mut Context::from_waker(waker),
        &mut PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0),
    );
    if matches!(result, Poll::Ready(Ok(1))) {
        assert_eq!(&bytes[..], &[0x01]);
        assert!(frames.is_empty());
    } else {
        assert!(bytes.is_empty());
        assert!(frames.is_empty());
    }
    result
}

#[tokio::test(start_paused = true)]
async fn background_rechecks_activity_and_wakes_only_the_current_sender() {
    let mut heartbeat = ArcHeartbeat::new(Duration::from_secs(60), Duration::from_secs(10));
    heartbeat
        .on_sent_at(PacketContent::EffectivePayload, Instant::now())
        .unwrap();
    let old = Arc::new(WakeCount::default());
    let current = Arc::new(WakeCount::default());
    let old_waker = Waker::from(old.clone());
    let current_waker = Waker::from(current.clone());
    assert!(poll(&mut heartbeat, 1, &old_waker).is_pending());
    assert!(poll(&mut heartbeat, 1, &current_waker).is_pending());
    tokio::task::yield_now().await;
    tokio::time::advance(DEFAULT_HEARTBEAT_INTERVAL / 2).await;
    heartbeat
        .on_rcvd_at(PacketContent::EffectivePayload, Instant::now())
        .unwrap();
    heartbeat
        .on_sent_at(PacketContent::EffectivePayload, Instant::now())
        .unwrap();
    assert_eq!(current.0.load(Ordering::Relaxed), 0);
    tokio::time::advance(DEFAULT_HEARTBEAT_INTERVAL / 2).await;
    tokio::task::yield_now().await;
    assert_eq!(current.0.load(Ordering::Relaxed), 0);
    tokio::time::advance(DEFAULT_HEARTBEAT_INTERVAL / 2).await;
    tokio::task::yield_now().await;
    assert_eq!(current.0.load(Ordering::Relaxed), 1);
    assert_eq!(old.0.load(Ordering::Relaxed), 0);
    tokio::task::yield_now().await;
    assert_eq!(current.0.load(Ordering::Relaxed), 1);
    assert_eq!(poll(&mut heartbeat, 1, &current_waker), Poll::Ready(Ok(1)));
    assert!(poll(&mut heartbeat, 1, &current_waker).is_pending());
    tokio::time::advance(DEFAULT_HEARTBEAT_INTERVAL).await;
    tokio::task::yield_now().await;
    assert_eq!(current.0.load(Ordering::Relaxed), 2);
    heartbeat.stop();
}
