use std::{
    collections::BTreeMap,
    future::poll_fn,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use super::route::Pathway;

type SignalsBits = u16;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy,PartialEq, Eq)]
    pub struct Signals: SignalsBits {
        const CONGESTION    = 1 << 0; // cc
        const FLOW_CONTROL  = 1 << 1; // flow
        const TRANSPORT     = 1 << 2; // ack/retran/reliable....
        const WRITTEN       = 1 << 3; // fresh stream
        const CONNECTION_ID = 1 << 4; // cid
        const CREDIT        = 1 << 5; // aa
        const KEYS          = 1 << 6; // key(no waker in SendWaker)
        const PING          = 1 << 7; // packet which contains ping frames only
        const TLS_FIN       = 1 << 8; // TLS handshake is required to send and receive 1rtt data
        const PATH_VALIDATE = 1 << 9; // path validated
    }
}

#[derive(Default, Debug)]
pub struct SendWaker {
    waker: Option<Waker>,
    // Signals 对应的bit设置为1意为该位的条件已经满足，为0表示需要该条件满足
    state: SignalsBits,
}

impl SendWaker {
    pub fn new() -> Self {
        Self::default()
    }

    const WAITING: SignalsBits = 0;

    #[inline]
    pub fn poll_wait_for(&mut self, cx: &mut Context, signals: Signals) -> Poll<()> {
        if self.state & signals.bits() == 0 {
            self.state = !signals.bits();
            match self.waker.as_ref() {
                Some(old_waker) if old_waker.will_wake(cx.waker()) => {}
                _ => self.waker = Some(cx.waker().clone()),
            }
            Poll::Pending
        } else {
            self.state = Self::WAITING;
            Poll::Ready(())
        }
    }

    #[inline]
    fn wake_by(&mut self, signals: Signals) {
        if self.state | signals.bits() != self.state {
            if let Some(waker) = self.waker.as_ref() {
                waker.wake_by_ref();
            }
        }
        self.state |= signals.bits();
    }
}

unsafe impl Send for SendWaker {}
unsafe impl Sync for SendWaker {}

#[derive(Debug, Default, Clone)]
pub struct ArcSendWaker(Arc<Mutex<SendWaker>>);

impl ArcSendWaker {
    #[inline]
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(SendWaker::new())))
    }

    #[inline]
    pub async fn wait_for(&self, signals: Signals) {
        poll_fn(|cx| self.0.lock().unwrap().poll_wait_for(cx, signals)).await
    }

    #[inline]
    pub fn wake_by(&self, signals: Signals) {
        self.0.lock().unwrap().wake_by(signals);
    }
}

/// connection level send wakers
#[derive(Debug, Default)]
pub struct SendWakers {
    last_woken: Option<Pathway>,
    paths: BTreeMap<Pathway, ArcSendWaker>,
}

impl SendWakers {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn insert(&mut self, pathway: Pathway, waker: &ArcSendWaker) {
        self.paths.entry(pathway).or_insert_with(|| waker.clone());
    }

    #[inline]
    pub fn remove(&mut self, pathway: &Pathway) {
        self.paths.remove(pathway);
    }

    #[inline]
    pub fn wake_all_by(&mut self, signals: Signals) {
        fn wake_all_by<'a>(
            paths: impl IntoIterator<Item = (&'a Pathway, &'a ArcSendWaker)>,
            signals: Signals,
        ) -> Option<Pathway> {
            let mut paths = paths.into_iter().peekable();
            let first_path = paths.peek().map(|(pathway, _)| pathway).copied().copied();

            paths.for_each(|(_, waker)| {
                waker.wake_by(signals);
            });

            first_path
        }

        use std::ops::Bound::*;

        self.last_woken = match self.last_woken {
            Some(last_woken) => wake_all_by(
                self.paths
                    .range((Excluded(last_woken), Unbounded))
                    .chain(self.paths.range((Unbounded, Included(last_woken)))),
                signals,
            ),
            None => wake_all_by(self.paths.range(..), signals),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct ArcSendWakers(Arc<Mutex<SendWakers>>);

impl ArcSendWakers {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_guard(&self) -> MutexGuard<'_, SendWakers> {
        self.0.lock().unwrap()
    }

    #[inline]
    pub fn insert(&self, pathway: Pathway, waker: &ArcSendWaker) {
        self.lock_guard().insert(pathway, waker);
    }

    #[inline]
    pub fn remove(&self, pathway: &Pathway) {
        self.lock_guard().remove(pathway);
    }

    #[inline]
    pub fn wake_all_by(&self, signals: Signals) {
        self.lock_guard().wake_all_by(signals);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering::*};

    impl ArcSendWaker {
        fn state(&self) -> SignalsBits {
            self.0.lock().unwrap().state
        }
    }

    use tracing::Instrument as _;

    use super::*;

    #[tokio::test]
    async fn single_condition() {
        let waker = ArcSendWaker::new();
        let woken_times = Arc::new(AtomicUsize::new(0));

        tokio::spawn({
            let waker = waker.clone();
            let wake_times = woken_times.clone();
            async move {
                loop {
                    waker.wait_for(Signals::CONGESTION).await;
                    wake_times.fetch_add(1, Release);
                }
            }
            .in_current_span()
        });

        waker.wake_by(Signals::FLOW_CONTROL);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 0); // not woken

        waker.wake_by(Signals::TRANSPORT);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 0); // not woken

        waker.wake_by(Signals::CONGESTION);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); // woken
    }

    #[tokio::test]
    async fn all_condition() {
        let waker = ArcSendWaker::new();
        let woken_times = Arc::new(AtomicUsize::new(0));

        tokio::spawn({
            let waker = waker.clone();
            let wake_times = woken_times.clone();
            async move {
                loop {
                    waker.wait_for(Signals::all()).await;
                    wake_times.fetch_add(1, Release);
                }
            }
            .in_current_span()
        });

        let wait_for_all_cond_state = !Signals::all().bits();

        waker.wake_by(Signals::FLOW_CONTROL);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); // woken
        assert_eq!(waker.state(), wait_for_all_cond_state);

        waker.wake_by(Signals::TRANSPORT);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 2); // woken
        assert_eq!(waker.state(), wait_for_all_cond_state);

        waker.wake_by(Signals::CONGESTION);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 3); // woken
        assert_eq!(waker.state(), wait_for_all_cond_state);
    }

    #[tokio::test]
    async fn wake_before_register() {
        let waker = ArcSendWaker::new();
        let woken_times = Arc::new(AtomicUsize::new(0));

        waker.wake_by(Signals::CONGESTION); // pre set woken state

        tokio::spawn({
            let waker = waker.clone();
            let wake_times = woken_times.clone();
            async move {
                loop {
                    waker.wait_for(Signals::CONGESTION).await;
                    wake_times.fetch_add(1, Release);
                }
            }
            .in_current_span()
        });

        let wait_for_quota_state = !Signals::CONGESTION.bits();

        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); // woken
        assert_eq!(waker.state(), wait_for_quota_state);
    }

    #[tokio::test]
    async fn state_change() {
        let waker = ArcSendWaker::new();
        let woken_times = Arc::new(AtomicUsize::new(0));

        tokio::spawn({
            let waker = waker.clone();
            let wake_times = woken_times.clone();

            let wait_for = move |r#for| {
                let wake_times = wake_times.clone();
                let waker = waker.clone();
                async move {
                    waker.wait_for(r#for).await;
                    wake_times.fetch_add(1, Release);
                }
            };

            async move {
                wait_for(Signals::all()).await;
                wait_for(Signals::CONGESTION | Signals::TRANSPORT).await;
                wait_for(Signals::TRANSPORT).await;
            }
            .in_current_span()
        });

        let wait_for_all_cond_state = !Signals::all().bits();

        let wait_for_quota_state = !(Signals::CONGESTION | Signals::TRANSPORT).bits();

        let wait_for_data_state = !Signals::TRANSPORT.bits();

        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 0); // not woken
        assert_eq!(waker.state(), wait_for_all_cond_state);

        waker.wake_by(Signals::TRANSPORT); // all condition will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); // woken
        assert_eq!(waker.state(), wait_for_quota_state);

        waker.wake_by(Signals::CONGESTION); // quota\data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 2); // woken
        assert_eq!(waker.state(), wait_for_data_state);

        waker.wake_by(Signals::CONGESTION); // only data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 2); // not woken

        waker.wake_by(Signals::FLOW_CONTROL); // only data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 2); // not woken

        waker.wake_by(Signals::TRANSPORT); // only data will be met
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 3); // woken
        assert_eq!(waker.state(), SendWaker::WAITING); // state reset 
    }

    #[tokio::test]
    async fn mult_wake_signals() {
        let waker = ArcSendWaker::new();
        let woken_times = Arc::new(AtomicUsize::new(0));

        tokio::spawn({
            let waker = waker.clone();
            let wake_times = woken_times.clone();
            async move {
                loop {
                    wake_times.fetch_add(1, Release);
                    waker.wait_for(Signals::TRANSPORT).await;
                }
            }
            .in_current_span()
        });

        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); //  wake
        assert_eq!(waker.state(), !Signals::TRANSPORT.bits());

        waker.wake_by(Signals::TRANSPORT);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 2); // enter + wake
        assert_eq!(waker.state(), !Signals::TRANSPORT.bits());

        waker.wake_by(Signals::CONGESTION | Signals::TRANSPORT);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 3); // enter + wake * 2
        assert_eq!(waker.state(), !Signals::TRANSPORT.bits());
    }

    #[tokio::test]
    async fn not_wake() {
        let waker = ArcSendWaker::new();
        let woken_times = Arc::new(AtomicUsize::new(0));

        tokio::spawn({
            let waker = waker.clone();
            let wake_times = woken_times.clone();
            async move {
                loop {
                    wake_times.fetch_add(1, Release);
                    waker.wait_for(Signals::CONGESTION).await;
                }
            }
            .in_current_span()
        });

        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); // not woken

        waker.wake_by(Signals::FLOW_CONTROL);
        tokio::task::yield_now().await;
        assert_eq!(woken_times.load(Acquire), 1); // not woken
    }
}
