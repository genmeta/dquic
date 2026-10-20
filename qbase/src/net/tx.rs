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
