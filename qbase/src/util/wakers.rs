use std::{
    mem,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Wake, Waker},
    usize,
};

use smallvec::SmallVec;

#[derive(Debug, Clone)]
pub struct WakerGroup<const N: usize = 4> {
    wakers: SmallVec<[Waker; N]>,
}

impl<const N: usize> Default for WakerGroup<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> WakerGroup<N> {
    pub const fn new() -> Self {
        Self {
            wakers: SmallVec::new_const(),
        }
    }

    pub fn add(&mut self, waker: &Waker) {
        if !self.wakers.iter().any(|w| w.will_wake(waker)) {
            self.wakers.push(waker.clone());
        }
    }

    pub fn remove(&mut self, waker: &Waker) {
        self.wakers
            .retain(|registered| !registered.will_wake(waker));
    }

    pub fn wake_all(&mut self) {
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }
}

impl<const N: usize> Drop for WakerGroup<N> {
    fn drop(&mut self) {
        self.wake_all();
    }
}

#[derive(Debug)]
pub struct Wakers<const N: usize = 4> {
    inner: Mutex<WakerGroup<N>>,
}

impl<const N: usize> Wake for Wakers<N> {
    fn wake(self: Arc<Self>) {
        self.wake_all();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all();
    }
}

impl<const N: usize> Default for Wakers<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Wakers<N> {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(WakerGroup::new()),
        }
    }

    fn lock_guard(&self) -> MutexGuard<'_, WakerGroup<N>> {
        self.inner.lock().expect("Wakers mutex poisoned")
    }

    pub fn add(&self, waker: &Waker) {
        self.lock_guard().add(waker)
    }

    pub fn remove(&self, waker: &Waker) {
        self.lock_guard().remove(waker)
    }

    pub fn together_with(self: &Arc<Self>, waker: &Waker) -> Waker {
        let mut guard = self.lock_guard();
        guard.add(waker);
        Waker::from(self.clone())
    }

    pub fn wake_all(&self) {
        { mem::replace(&mut *self.lock_guard(), WakerGroup::new()) }.wake_all()
    }

    pub fn to_waker(self: &Arc<Self>) -> Waker {
        Waker::from(self.clone())
    }

    pub fn combine_with<T>(
        self: &Arc<Self>,
        cx: &mut Context<'_>,
        poll: impl FnOnce(&mut Context<'_>) -> Poll<T>,
    ) -> Poll<T> {
        self.add(cx.waker());
        let result = poll(&mut Context::from_waker(&self.to_waker()));
        if result.is_ready() {
            self.remove(cx.waker());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };

    use super::Wakers;

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
}
