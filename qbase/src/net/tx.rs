use std::{
    sync::{Arc, Mutex},
    task::Waker,
};

/// Removes a path send task's subscription from a shared data source.
pub trait UnregisterWaker {
    /// Unregister this waiter without waking it or affecting other waiters.
    fn unregister(&self, waker: &Waker);
}

/// Persistent subscriptions for path send tasks. Readiness does not unregister a path.
#[derive(Debug, Default, Clone)]
pub struct ArcSendWakers(Arc<Mutex<Vec<Waker>>>);

impl ArcSendWakers {
    pub fn register(&self, waker: &Waker) {
        let mut waiters = self.0.lock().unwrap();
        if !waiters.iter().any(|old| old.will_wake(waker)) {
            waiters.push(waker.clone());
        }
    }

    pub fn unregister(&self, waker: &Waker) {
        self.0.lock().unwrap().retain(|old| !old.will_wake(waker));
    }

    /// Remove subscriptions without waking them, for task-exit cleanup.
    pub fn drain(&self) -> Vec<Waker> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }

    pub fn wake_all(&self) {
        let waiters = self.0.lock().unwrap().clone();
        for waker in waiters {
            waker.wake();
        }
    }
}

#[cfg(test)]
mod waiter_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
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
        assert!(wakers.0.lock().unwrap().is_empty());
    }
}
