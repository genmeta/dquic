use std::{
    mem,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Wake, Waker},
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
