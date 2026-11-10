use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use qbase::util::{WakerGroup, Wakers};

#[derive(Debug)]
struct CountedWake {
    wakes: Arc<AtomicUsize>,
}

impl Wake for CountedWake {
    fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
    }
}

fn counted_waker() -> (Waker, std::sync::Weak<CountedWake>) {
    let wake = Arc::new(CountedWake { wakes: Arc::new(AtomicUsize::new(0)) });
    let weak = Arc::downgrade(&wake);
    (Waker::from(wake), weak)
}

#[test]
fn group_consumes_deduplicated_waiters_and_can_be_rearmed() {
    let mut group = WakerGroup::<4>::new();
    let (a, first) = counted_waker();
    let (b, second) = counted_waker();
    group.add(&a);
    group.add(&a);
    group.add(&b);
    group.wake_all();
    group.wake_all();
    assert_eq!(first.upgrade().unwrap().wakes.load(Ordering::Relaxed), 1);
    assert_eq!(second.upgrade().unwrap().wakes.load(Ordering::Relaxed), 1);
    group.add(&a);
    group.add(&b);
    group.remove(&b);
    group.wake_all();
    assert_eq!(first.upgrade().unwrap().wakes.load(Ordering::Relaxed), 2);
    assert_eq!(second.upgrade().unwrap().wakes.load(Ordering::Relaxed), 1);
    drop(a);
    drop(b);
    assert!(first.upgrade().is_none());
    assert!(second.upgrade().is_none());
}

#[test]
fn clearing_a_group_does_not_notify_on_drop() {
    let (waker, weak) = counted_waker();
    {
        let mut group = WakerGroup::<4>::new();
        group.add(&waker);
        group.clear();
    }
    assert_eq!(weak.upgrade().unwrap().wakes.load(Ordering::Relaxed), 0);
    drop(waker);
    assert!(weak.upgrade().is_none());
}

#[test]
fn combine_with_does_not_retain_ready_waker() {
    let wakers = Arc::new(Wakers::<4>::new());
    let (waker, weak) = counted_waker();

    {
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(wakers.combine_with(&mut cx, |_| Poll::Ready(())), Poll::Ready(())));
    }

    drop(waker);

    assert!(weak.upgrade().is_none(), "ready polls must not leave completed task wakers retained");
}

#[test]
fn combine_with_retains_pending_waker_until_woken() {
    let wakers = Arc::new(Wakers::<4>::new());
    let (waker, weak) = counted_waker();

    {
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(wakers.combine_with(&mut cx, |_| Poll::<()>::Pending), Poll::Pending));
    }

    drop(waker);
    assert!(weak.upgrade().is_some(), "pending polls must keep the waker available for wake_all");

    wakers.wake_all();

    assert!(weak.upgrade().is_none(), "wake_all should release retained pending wakers");
}
