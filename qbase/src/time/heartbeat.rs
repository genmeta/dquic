use std::{
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::BufMut;
use tokio::time::{Instant, sleep};

use crate::{
    Cancelled,
    error::Error,
    frame::{Frame, PingFrame},
    packet::{ConstraintBuffer, Package, PacketContent},
    time::IdleSince,
};

pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);

/// Sends periodic PINGs within the deferral window following effective activity.
/// Only the first effective send after initialization or an effective receive
/// restarts the schedule. Zero durations disable heartbeats.
#[derive(Debug)]
pub struct Heartbeat {
    metric: IdleSince,
    counter: usize,
    defer_idle_timeout: Duration,
    heartbeat_interval: Duration,
    waker: Option<Waker>,
}

impl Heartbeat {
    pub fn new(defer_idle_timeout: Duration, max_idle_timeout: Duration) -> Self {
        let heartbeat_interval = if max_idle_timeout == Duration::ZERO {
            DEFAULT_HEARTBEAT_INTERVAL
        } else {
            max_idle_timeout
                .div_f32(3.0)
                .min(Duration::from_secs(1))
                .max(DEFAULT_HEARTBEAT_INTERVAL)
        };
        Self {
            metric: IdleSince::new(),
            counter: 0,
            defer_idle_timeout,
            heartbeat_interval,
            waker: None,
        }
    }

    pub fn adapt_max_idle_timeout(&mut self, max_idle_timeout: Duration) {
        if max_idle_timeout != Duration::ZERO {
            self.heartbeat_interval = max_idle_timeout
                .div_f32(3.0)
                .max(Duration::from_secs(1))
                .min(self.heartbeat_interval);

            if let Some(waker) = self.waker.take() {
                waker.wake();
            }
        }
    }

    pub fn on_sent_at(&mut self, content: PacketContent, now: Instant) {
        if content == PacketContent::EffectivePayload && self.metric.on_sent_at(now) {
            self.counter = 0;
        }
    }

    pub fn on_rcvd_at(&mut self, content: PacketContent, now: Instant) {
        if content == PacketContent::EffectivePayload && self.metric.on_rcvd_at(now) {
            self.counter = 0;
        }
    }

    pub fn time_to_heartbeat(&self) -> Duration {
        let now = Instant::now();
        if self.defer_idle_timeout.is_zero()
            || self.heartbeat_interval.is_zero()
            || self.metric.timeout_after(now, self.defer_idle_timeout)
        {
            return Duration::from_millis(100);
        }
        let next = u32::try_from(self.counter.saturating_add(1)).unwrap_or(u32::MAX);
        self.metric
            .expires_in(now, self.heartbeat_interval.saturating_mul(next))
    }

    pub fn stop(&mut self) {
        self.waker = None;
    }
}

#[derive(Debug, Clone)]
pub struct ArcHeartbeat(Arc<Mutex<Result<Heartbeat, Cancelled>>>);

impl<B: BufMut + ?Sized> Package<B> for Heartbeat {
    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ConstraintBuffer<'_, B>,
        frames: &mut Vec<Frame>,
    ) -> Poll<Result<usize, Error>> {
        if !self.time_to_heartbeat().is_zero() {
            self.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        self.waker = None;
        let result = PingFrame.poll_dump(cx, buffer, frames);
        if matches!(result, Poll::Ready(Ok(1))) {
            self.counter += 1;
        }
        result
    }
}

impl ArcHeartbeat {
    /// Starts a detached heartbeat task. Requires a Tokio runtime with time enabled.
    pub fn new(defer_idle_timeout: Duration, max_idle_timeout: Duration) -> Self {
        let heartbeat = Self(Arc::new(Mutex::new(Ok(Heartbeat::new(
            defer_idle_timeout,
            max_idle_timeout,
        )))));
        tokio::spawn(heartbeat.clone().run());
        heartbeat
    }

    pub fn stop(&self) {
        let mut guard = self.0.lock().unwrap();
        if let Ok(heartbeat) = guard.as_mut() {
            heartbeat.stop();
            *guard = Err(Cancelled);
        }
    }

    pub fn adapt_max_idle_timeout(&self, max_idle_timeout: Duration) {
        let mut guard = self.0.lock().unwrap();
        match guard.as_mut() {
            Ok(heartbeat) => {
                heartbeat.adapt_max_idle_timeout(max_idle_timeout);
            }
            Err(_) => (),
        }
    }

    pub fn on_sent_at(&self, content: PacketContent, now: Instant) -> Result<(), Cancelled> {
        let mut guard = self.0.lock().unwrap();
        match guard.as_mut() {
            Ok(heartbeat) => {
                heartbeat.on_sent_at(content, now);
                Ok(())
            }
            Err(_) => Err(Cancelled),
        }
    }

    pub fn on_rcvd_at(&self, content: PacketContent, now: Instant) -> Result<(), Cancelled> {
        let mut guard = self.0.lock().unwrap();
        match guard.as_mut() {
            Ok(heartbeat) => {
                heartbeat.on_rcvd_at(content, now);
                Ok(())
            }
            Err(_) => Err(Cancelled),
        }
    }

    /// Runs one background timer for the single sender registered by `poll_dump`.
    /// Activity and cancellation are observed after the current sleep finishes.
    async fn run(self) -> Result<(), Cancelled> {
        loop {
            let (delay, waker) = {
                let mut guard = self.0.lock().unwrap();
                let heartbeat = guard.as_mut().map_err(|_| Cancelled)?;
                let delay = heartbeat.time_to_heartbeat();
                if delay.is_zero() {
                    // Give the sender an interval to consume the pending PING.
                    (heartbeat.heartbeat_interval, heartbeat.waker.take())
                } else {
                    (delay, None)
                }
            };
            if let Some(waker) = waker {
                waker.wake();
            }
            sleep(delay).await;
        }
    }
}

impl<B: BufMut + ?Sized> Package<B> for ArcHeartbeat {
    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ConstraintBuffer<'_, B>,
        frames: &mut Vec<Frame>,
    ) -> Poll<Result<usize, Error>> {
        let mut guard = self.0.lock().unwrap();
        match guard.as_mut() {
            Ok(heartbeat) => heartbeat.poll_dump(cx, buffer, frames),
            Err(_) => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::BytesMut;

    use super::*;
    use crate::packet::{Constraints, GetType, OneRttHeader};

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn poll(
        heartbeat: &mut impl Package<BytesMut>,
        quota: usize,
        waker: &Waker,
    ) -> Poll<Result<usize, Error>> {
        let mut bytes = BytesMut::new();
        let mut frames = Vec::new();
        let mut limits = Constraints {
            send_quota: quota,
            credit: 1,
            max_size: 1,
            ..Default::default()
        };
        let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
        let result = heartbeat.poll_dump(
            &mut Context::from_waker(waker),
            &mut ConstraintBuffer::new(&mut bytes, &mut limits, ty, 0, 0),
            &mut frames,
        );
        if matches!(result, Poll::Ready(Ok(1))) {
            assert_eq!(&bytes[..], &[0x01]);
            assert!(matches!(&frames[..], [Frame::Ping(_)]));
        } else {
            assert!(bytes.is_empty());
            assert!(frames.is_empty());
        }
        result
    }

    fn heartbeat(defer: u64, interval: u64) -> Heartbeat {
        Heartbeat {
            heartbeat_interval: Duration::from_secs(interval),
            ..Heartbeat::new(Duration::from_secs(defer), Duration::ZERO)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn only_effective_payload_starts_or_extends_heartbeat() {
        let mut heartbeat = heartbeat(30, 10);
        for content in [PacketContent::JustPing, PacketContent::NonAckEliciting] {
            heartbeat.on_sent_at(content, Instant::now());
            heartbeat.on_rcvd_at(content, Instant::now());
        }
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(poll(&mut heartbeat, 1, Waker::noop()).is_pending());
        heartbeat.on_sent_at(PacketContent::EffectivePayload, Instant::now());
        tokio::time::advance(Duration::from_secs(5)).await;
        for content in [PacketContent::JustPing, PacketContent::NonAckEliciting] {
            heartbeat.on_rcvd_at(content, Instant::now());
            heartbeat.on_sent_at(content, Instant::now());
        }
        // Neither ACK nor PING rearms IdleSince's one allowed send update.
        heartbeat.on_sent_at(PacketContent::EffectivePayload, Instant::now());
        assert_eq!(heartbeat.time_to_heartbeat(), Duration::from_secs(5));
        heartbeat.on_rcvd_at(PacketContent::EffectivePayload, Instant::now());
        assert_eq!(heartbeat.time_to_heartbeat(), Duration::from_secs(10));
        tokio::time::advance(Duration::from_secs(2)).await;
        heartbeat.on_sent_at(PacketContent::EffectivePayload, Instant::now());
        assert_eq!(heartbeat.time_to_heartbeat(), Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn ping_is_consumed_only_after_it_fits_and_activity_resets_the_schedule() {
        let mut heartbeat = heartbeat(30, 10);
        heartbeat.on_sent_at(PacketContent::EffectivePayload, Instant::now());
        assert!(poll(&mut heartbeat, 1, Waker::noop()).is_pending());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(poll(&mut heartbeat, 0, Waker::noop()), Poll::Ready(Ok(0)));
        assert_eq!(heartbeat.time_to_heartbeat(), Duration::ZERO);
        assert_eq!(poll(&mut heartbeat, 1, Waker::noop()), Poll::Ready(Ok(1)));
        assert!(poll(&mut heartbeat, 1, Waker::noop()).is_pending());
        tokio::time::advance(Duration::from_secs(5)).await;
        heartbeat.on_rcvd_at(PacketContent::EffectivePayload, Instant::now());
        assert_eq!(heartbeat.time_to_heartbeat(), Duration::from_secs(10));
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(poll(&mut heartbeat, 1, Waker::noop()), Poll::Ready(Ok(1)));
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_stops_at_the_deferral_boundary_and_can_restart() {
        let mut heartbeat = heartbeat(30, 10);
        heartbeat.on_sent_at(PacketContent::EffectivePayload, Instant::now());
        for _ in 0..2 {
            tokio::time::advance(Duration::from_secs(10)).await;
            assert_eq!(poll(&mut heartbeat, 1, Waker::noop()), Poll::Ready(Ok(1)));
        }
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(poll(&mut heartbeat, 1, Waker::noop()).is_pending());
        heartbeat.on_rcvd_at(PacketContent::EffectivePayload, Instant::now());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(poll(&mut heartbeat, 1, Waker::noop()), Poll::Ready(Ok(1)));
    }

    #[tokio::test(start_paused = true)]
    async fn zero_durations_disable_heartbeats() {
        for (defer, interval) in [(0, 10), (30, 0)] {
            let mut heartbeat = heartbeat(defer, interval);
            heartbeat.on_sent_at(PacketContent::EffectivePayload, Instant::now());
            tokio::time::advance(Duration::from_secs(100)).await;
            assert!(poll(&mut heartbeat, 1, Waker::noop()).is_pending());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn background_rechecks_activity_and_wakes_only_the_current_sender() {
        let mut heartbeat = ArcHeartbeat::new(Duration::from_secs(60), Duration::from_secs(10));
        heartbeat
            .on_sent_at(PacketContent::EffectivePayload, Instant::now())
            .unwrap();
        let old = Arc::new(WakeCount::default());
        let current = Arc::new(WakeCount::default());
        let old_waker = Waker::from(old.clone());
        let current_waker = Waker::from(current.clone());
        assert!(poll(&mut heartbeat, 1, &old_waker).is_pending());
        assert!(poll(&mut heartbeat, 1, &current_waker).is_pending());
        tokio::task::yield_now().await;
        tokio::time::advance(DEFAULT_HEARTBEAT_INTERVAL / 2).await;
        heartbeat
            .on_rcvd_at(PacketContent::EffectivePayload, Instant::now())
            .unwrap();
        heartbeat
            .on_sent_at(PacketContent::EffectivePayload, Instant::now())
            .unwrap();
        assert_eq!(current.0.load(Ordering::Relaxed), 0);
        tokio::time::advance(DEFAULT_HEARTBEAT_INTERVAL / 2).await;
        tokio::task::yield_now().await;
        assert_eq!(current.0.load(Ordering::Relaxed), 0);
        tokio::time::advance(DEFAULT_HEARTBEAT_INTERVAL / 2).await;
        tokio::task::yield_now().await;
        assert_eq!(current.0.load(Ordering::Relaxed), 1);
        assert_eq!(old.0.load(Ordering::Relaxed), 0);
        tokio::task::yield_now().await;
        assert_eq!(current.0.load(Ordering::Relaxed), 1);
        assert_eq!(poll(&mut heartbeat, 1, &current_waker), Poll::Ready(Ok(1)));
        assert!(poll(&mut heartbeat, 1, &current_waker).is_pending());
        tokio::time::advance(DEFAULT_HEARTBEAT_INTERVAL).await;
        tokio::task::yield_now().await;
        assert_eq!(current.0.load(Ordering::Relaxed), 2);
        heartbeat.stop();
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_is_permanent_and_the_task_stops_after_its_sleep() {
        let mut heartbeat = ArcHeartbeat::new(Duration::from_secs(30), Duration::from_secs(10));
        heartbeat
            .on_sent_at(PacketContent::EffectivePayload, Instant::now())
            .unwrap();
        let state = Arc::downgrade(&heartbeat.0);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        heartbeat.stop();
        assert!(
            heartbeat
                .on_sent_at(PacketContent::EffectivePayload, Instant::now())
                .is_err()
        );
        assert!(
            heartbeat
                .on_rcvd_at(PacketContent::EffectivePayload, Instant::now())
                .is_err()
        );
        assert!(poll(&mut heartbeat, 1, Waker::noop()).is_pending());
        tokio::task::yield_now().await;
        drop(heartbeat);
        assert!(state.upgrade().is_some());
        tokio::time::advance(DEFAULT_HEARTBEAT_INTERVAL - Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert!(state.upgrade().is_none());
    }
}
