use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Waker,
};

use qbase::net::tx::*;
struct Counter(AtomicUsize);
impl std::task::Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn subscriptions_are_deduplicated_persistent_and_removable() {
    let wakers = ArcSendWakers::default();
    let first = Arc::new(Counter(AtomicUsize::new(0)));
    let second = Arc::new(Counter(AtomicUsize::new(0)));
    let a = Waker::from(first.clone());
    let b = Waker::from(second.clone());
    wakers.register(&a);
    wakers.register(&a);
    wakers.register(&b);
    wakers.wake_all();
    wakers.wake_all();
    assert_eq!(first.0.load(Ordering::Relaxed), 2);
    assert_eq!(second.0.load(Ordering::Relaxed), 2);
    wakers.unregister(&a);
    wakers.wake_all();
    assert_eq!(first.0.load(Ordering::Relaxed), 2);
    assert_eq!(second.0.load(Ordering::Relaxed), 3);
    let remaining = wakers.drain();
    assert_eq!(remaining.len(), 1);
    assert!(remaining[0].will_wake(&b));
    wakers.wake_all();
    assert_eq!(second.0.load(Ordering::Relaxed), 3);
    assert!(wakers.drain().is_empty());
}
