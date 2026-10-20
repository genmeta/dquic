use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use qbase::ArcReceiving;
//use qbase::frame::io::ReceiveFrame;

#[derive(Default)]
struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn poll<T: Unpin>(
    future: &mut ArcReceiving<T>,
    waker: &Waker,
) -> Poll<Result<Option<T>, qbase::Cancelled>> {
    Future::poll(Pin::new(future), &mut Context::from_waker(waker))
}

#[test]
fn received_frame_wakes_waiter() {
    let mut receiving = ArcReceiving::<u8>::default();
    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(wake_counter.clone());

    assert!(poll(&mut receiving, &waker).is_pending());
    receiving.obtain(7);

    assert_eq!(wake_counter.0.load(Ordering::Relaxed), 1);
    assert!(matches!(
        poll(&mut receiving, &waker),
        Poll::Ready(Ok(Some(7)))
    ));
}

#[test]
fn repoll_replaces_cancelled_waiter() {
    let mut receiving = ArcReceiving::<u8>::default();
    let first_counter = Arc::new(WakeCounter::default());
    let first_waker = Waker::from(first_counter.clone());
    let second_counter = Arc::new(WakeCounter::default());
    let second_waker = Waker::from(second_counter.clone());

    assert!(poll(&mut receiving, &first_waker).is_pending());
    assert!(poll(&mut receiving, &second_waker).is_pending());
    receiving.obtain(7);

    assert_eq!(first_counter.0.load(Ordering::Relaxed), 0);
    assert_eq!(second_counter.0.load(Ordering::Relaxed), 1);
}

#[test]
fn duplicate_frame_does_not_discard_first_frame() {
    let mut receiving = ArcReceiving::default();
    let waker = Waker::noop();

    receiving.obtain(7);
    receiving.obtain(9);

    assert!(matches!(
        poll(&mut receiving, waker),
        Poll::Ready(Ok(Some(7)))
    ));
}

#[test]
fn assignment_wakes_waiter_only_when_guard_is_dropped() {
    let receiving = ArcReceiving::default();
    let mut reader = receiving.clone();
    let counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(counter.clone());
    let mut guard = receiving.as_mut();
    *guard = Some(7);

    assert!(poll(&mut reader, &waker).is_pending());
    assert_eq!(counter.0.load(Ordering::Relaxed), 0);
    drop(guard);

    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    assert!(matches!(
        poll(&mut reader, &waker),
        Poll::Ready(Ok(Some(7)))
    ));
    receiving.set(9);
    assert!(matches!(poll(&mut reader, &waker), Poll::Ready(Ok(None))));
}

#[test]
fn empty_assignment_keeps_waiting() {
    let mut receiving = ArcReceiving::default();
    let counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(counter.clone());
    assert!(poll(&mut receiving, &waker).is_pending());

    assert!(receiving.as_mut().is_none());
    assert_eq!(counter.0.load(Ordering::Relaxed), 0);
    assert!(poll(&mut receiving, &waker).is_pending());

    receiving.set(7);
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    assert!(matches!(
        poll(&mut receiving, &waker),
        Poll::Ready(Ok(Some(7)))
    ));
}

#[test]
fn assignment_does_not_overwrite_a_concurrent_submission() {
    let receiving = ArcReceiving::default();
    let mut guard = receiving.as_mut();
    *guard = Some(9);
    receiving.set(7);
    drop(guard);
    receiving.with(11);

    assert_eq!(futures::executor::block_on(receiving).unwrap(), Some(7));
}

#[test]
fn assignment_does_not_reopen_cancelled_receiver() {
    let receiving = ArcReceiving::default();
    let mut guard = receiving.as_mut();
    *guard = Some(7);
    receiving.cancel();
    drop(guard);

    assert!(futures::executor::block_on(receiving).is_err());
}

#[tokio::test]
async fn with_wakes_async_receiver() {
    let receiving = ArcReceiving::default();
    let writer = receiving.clone();
    let (result, ()) = tokio::join!(receiving, async {
        tokio::task::yield_now().await;
        writer.with(7);
    });

    assert_eq!(result.unwrap(), Some(7));
}
