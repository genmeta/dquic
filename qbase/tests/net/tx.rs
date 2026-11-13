use std::{
    sync::{
        Arc, Barrier, Weak,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    task::{Wake, Waker},
    time::Duration,
};

use qbase::net::tx::{SendWaker, WakerGroup};

#[derive(Default)]
struct Counter(AtomicUsize);

impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn native_waker() -> (Arc<Counter>, Waker) {
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(counter.clone());
    (counter, waker)
}

#[test]
fn running_notifications_are_discarded_on_ready_and_at_the_next_collection() {
    let sender = Arc::new(SendWaker::default());
    let proxy = Waker::from(sender.clone());
    let (counter, native) = native_waker();
    sender.as_ref().wake();
    sender.register(&native);
    proxy.wake_by_ref();
    let owned = proxy.clone();
    owned.wake();
    assert_eq!(counter.0.load(Ordering::Relaxed), 0);
    sender.refresh(true);
    assert_eq!(counter.0.load(Ordering::Relaxed), 0);

    // Ordinary notifications during an I/O wait must not contaminate the next poll.
    proxy.wake_by_ref();
    sender.register(&native);
    sender.refresh(false);
    assert_eq!(counter.0.load(Ordering::Relaxed), 0);
    proxy.wake_by_ref();
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
}

#[test]
fn pending_notifications_consume_the_native_waiter_and_rearm_on_register() {
    let sender = Arc::new(SendWaker::default());
    let proxy = Waker::from(sender.clone());
    let (counter, native) = native_waker();
    for expected in 1..=64 {
        sender.register(&native);
        sender.refresh(false);
        assert_eq!(counter.0.load(Ordering::Relaxed), expected - 1);
        let owned = proxy.clone();
        owned.wake();
        proxy.wake_by_ref();
        sender.as_ref().wake();
        assert_eq!(counter.0.load(Ordering::Relaxed), expected);
    }
}

#[test]
fn notifications_received_while_collecting_wake_once_when_pending_is_committed() {
    let sender = Arc::new(SendWaker::default());
    let (counter, native) = native_waker();
    for expected in 1..=64 {
        sender.register(&native);
        sender.as_ref().wake();
        sender.as_ref().wake();
        assert_eq!(counter.0.load(Ordering::Relaxed), expected - 1);
        sender.refresh(false);
        sender.as_ref().wake();
        sender.refresh(false);
        assert_eq!(counter.0.load(Ordering::Relaxed), expected);
    }
}

#[test]
fn replacing_the_native_task_keeps_the_source_identity_and_releases_the_old_task() {
    let sender = Arc::new(SendWaker::default());
    let first_proxy = Waker::from(sender.clone());
    let (first, first_native) = native_waker();
    let old_task = Arc::downgrade(&first);
    sender.register(&first_native);
    sender.refresh(false);
    drop(first_native);
    drop(first);
    assert!(old_task.upgrade().is_some());

    let (second, second_native) = native_waker();
    sender.register(&second_native);
    assert!(old_task.upgrade().is_none());
    let second_proxy = Waker::from(sender.clone());
    assert!(first_proxy.will_wake(&second_proxy));
    sender.refresh(false);
    first_proxy.wake();
    assert_eq!(second.0.load(Ordering::Relaxed), 1);
}

#[test]
fn shared_sources_deduplicate_and_unregister_paths_independently() {
    let first = Arc::new(SendWaker::default());
    let second = Arc::new(SendWaker::default());
    let (first_count, first_native) = native_waker();
    let (second_count, second_native) = native_waker();
    let mut group = WakerGroup::<2>::new();
    for _ in 0..64 {
        group.add(&Waker::from(first.clone()));
        group.add(&Waker::from(second.clone()));
    }
    // One path handle and one subscription per path, independent of poll count.
    assert_eq!(Arc::strong_count(&first), 2);
    assert_eq!(Arc::strong_count(&second), 2);
    first.register(&first_native);
    second.register(&second_native);
    first.refresh(false);
    second.refresh(false);
    group.remove(&Waker::from(first.clone()));
    assert_eq!(Arc::strong_count(&first), 1);
    group.wake_all();
    assert_eq!(first_count.0.load(Ordering::Relaxed), 0);
    assert_eq!(second_count.0.load(Ordering::Relaxed), 1);
    assert_eq!(Arc::strong_count(&second), 1);
}

#[test]
fn sources_consume_running_subscriptions_until_registered_again() {
    let sender = Arc::new(SendWaker::default());
    let proxy = Waker::from(sender.clone());
    let (counter, native) = native_waker();
    let mut group = WakerGroup::<1>::new();
    group.add(&proxy);
    sender.register(&native);
    group.wake_all();
    group.wake_all();
    assert_eq!(counter.0.load(Ordering::Relaxed), 0);
    sender.refresh(false);
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);

    sender.register(&native);
    group.wake_all();
    sender.refresh(false);
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    group.add(&proxy);
    group.wake_all();
    assert_eq!(counter.0.load(Ordering::Relaxed), 2);
}

#[test]
fn ready_refresh_releases_the_native_task_even_when_sources_keep_the_proxy() {
    let sender = Arc::new(SendWaker::default());
    let mut group = WakerGroup::<1>::new();
    group.add(&Waker::from(sender.clone()));
    let (counter, native) = native_waker();
    let task = Arc::downgrade(&counter);
    sender.register(&native);
    sender.as_ref().wake();
    drop(counter);
    drop(native);
    assert!(task.upgrade().is_some());
    sender.refresh(true);
    assert!(task.upgrade().is_none());
    group.wake_all();
}

#[test]
fn dropping_and_clearing_source_groups_preserve_their_notification_semantics() {
    let sender = Arc::new(SendWaker::default());
    let (counter, native) = native_waker();
    sender.register(&native);
    {
        let mut group = WakerGroup::<1>::new();
        group.add(&Waker::from(sender.clone()));
    }
    sender.refresh(false);
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);

    sender.register(&native);
    {
        let mut group = WakerGroup::<1>::new();
        group.add(&Waker::from(sender.clone()));
        group.clear();
    }
    sender.refresh(false);
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    sender.as_ref().wake();
    assert_eq!(counter.0.load(Ordering::Relaxed), 2);
}

#[test]
fn concurrent_sources_cannot_pass_the_pending_transition_or_schedule_twice() {
    let sender = Arc::new(SendWaker::default());
    let (counter, native) = native_waker();
    for expected in 1..=64 {
        sender.register(&native);
        let barrier = Arc::new(Barrier::new(5));
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let sender = sender.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    sender.as_ref().wake();
                    sender.as_ref().wake();
                });
            }
            barrier.wait();
            sender.refresh(false);
        });
        assert_eq!(counter.0.load(Ordering::Relaxed), expected);
    }
}

struct Reentrant {
    sender: Weak<SendWaker>,
    done: mpsc::Sender<()>,
}

impl Wake for Reentrant {
    fn wake(self: Arc<Self>) {
        self.sender.upgrade().unwrap().refresh(true);
        self.done.send(()).unwrap();
    }
}

#[test]
fn native_wake_runs_outside_the_state_lock_for_both_notification_paths() {
    for during_collection in [false, true] {
        let sender = Arc::new(SendWaker::default());
        let (done, notified) = mpsc::channel();
        sender.register(&Waker::from(Arc::new(Reentrant { sender: Arc::downgrade(&sender), done })));
        if during_collection {
            sender.as_ref().wake();
        } else {
            sender.refresh(false);
        }
        let notify = std::thread::spawn(move || {
            if during_collection {
                sender.refresh(false);
            } else {
                sender.as_ref().wake();
            }
        });
        notified.recv_timeout(Duration::from_secs(3)).expect("native wake must be able to reenter SendWaker");
        notify.join().unwrap();
    }
}
