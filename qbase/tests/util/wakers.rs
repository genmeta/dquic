use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use qbase::util::Wakers;

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
    let wake = Arc::new(CountedWake {
        wakes: Arc::new(AtomicUsize::new(0)),
    });
    let weak = Arc::downgrade(&wake);
    (Waker::from(wake), weak)
}

#[test]
fn combine_with_does_not_retain_ready_waker() {
    let wakers = Arc::new(Wakers::<4>::new());
    let (waker, weak) = counted_waker();

    {
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            wakers.combine_with(&mut cx, |_| Poll::Ready(())),
            Poll::Ready(())
        ));
    }

    drop(waker);

    assert!(
        weak.upgrade().is_none(),
        "ready polls must not leave completed task wakers retained"
    );
}

#[test]
fn combine_with_retains_pending_waker_until_woken() {
    let wakers = Arc::new(Wakers::<4>::new());
    let (waker, weak) = counted_waker();

    {
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            wakers.combine_with(&mut cx, |_| Poll::<()>::Pending),
            Poll::Pending
        ));
    }

    drop(waker);
    assert!(
        weak.upgrade().is_some(),
        "pending polls must keep the waker available for wake_all"
    );

    wakers.wake_all();

    assert!(
        weak.upgrade().is_none(),
        "wake_all should release retained pending wakers"
    );
}
