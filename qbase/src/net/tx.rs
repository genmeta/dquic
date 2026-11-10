use std::task::Waker;

/// Removes a path send task's subscription from a shared data source.
pub trait UnregisterWaker {
    /// Unregister this waiter without waking it or affecting other waiters.
    fn unregister(&self, waker: &Waker);
}
