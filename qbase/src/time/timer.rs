use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::time::{Instant, sleep};

use crate::{
    Cancelled,
    time::{IdleSince, Timeout},
};

pub struct IdleMetric {
    last_active: IdleSince,
}

impl IdleMetric {
    pub fn new() -> Self {
        Self {
            last_active: IdleSince::new(),
        }
    }

    pub fn on_sent_at(&mut self, now: Instant) -> bool {
        self.last_active.on_sent_at(now)
    }

    pub fn on_rcvd_at(&mut self, now: Instant) -> bool {
        self.last_active.on_rcvd_at(now)
    }
}

/// Tracks connection idle expiry.
/// Activity timestamps must be reported in nondecreasing order.
/// No timeout is started until the first reported send or receive.
pub struct IdleTimer {
    metric: IdleMetric,
    max_idle_timeout: Duration,
}

impl IdleTimer {
    pub fn new(max_idle_timeout: Duration) -> Self {
        Self {
            metric: IdleMetric::new(),
            max_idle_timeout,
        }
    }

    pub fn update_max_idle_timeout(&mut self, max_idle_timeout: Duration) {
        self.max_idle_timeout = max_idle_timeout;
    }

    /// Reports a successfully sent packet.
    pub fn on_sent_at(&mut self, now: Instant) -> Result<bool, Timeout> {
        if !self.timeout_after(now) {
            Ok(self.metric.on_sent_at(now))
        } else {
            Err(Timeout)
        }
    }

    /// Reports a successfully received and processed packet, including ACK-only packets.
    pub fn on_rcvd_at(&mut self, now: Instant) -> Result<bool, Timeout> {
        if !self.timeout_after(now) {
            Ok(self.metric.on_rcvd_at(now))
        } else {
            Err(Timeout)
        }
    }

    fn timeout_after(&self, now: Instant) -> bool {
        self.max_idle_timeout != Duration::ZERO
            && self
                .metric
                .last_active
                .timeout_after(now, self.max_idle_timeout)
    }

    fn time_to_live(&self, now: Instant) -> Duration {
        self.metric
            .last_active
            .expires_in(now, self.max_idle_timeout)
    }
}

/// A cancellable idle timer shared by activity producers and one waiting task.
#[derive(Clone)]
pub struct ArcIdleTimer(Arc<Mutex<Result<IdleTimer, Cancelled>>>);

impl ArcIdleTimer {
    pub fn new(max_idle_timeout: Duration) -> Self {
        Self(Arc::new(Mutex::new(Ok(IdleTimer::new(max_idle_timeout)))))
    }

    pub fn update_max_idle_timeout(&self, max_idle_timeout: Duration) {
        match self.0.lock().unwrap().as_mut() {
            Ok(timer) => timer.update_max_idle_timeout(max_idle_timeout),
            Err(_) => (),
        }
    }

    /// Returns cancellation, expiry, or whether the activity timestamp was updated.
    /// All successfully sent packets should be reported.
    pub fn on_sent_at(&self, now: Instant) -> Result<Result<bool, Timeout>, Cancelled> {
        let mut guard = self.0.lock().unwrap();
        match guard.as_mut() {
            Ok(timer) => Ok(timer.on_sent_at(now)),
            Err(_) => Err(Cancelled),
        }
    }

    /// Returns cancellation, expiry, or whether the activity timestamp was updated.
    pub fn on_rcvd_at(&self, now: Instant) -> Result<Result<bool, Timeout>, Cancelled> {
        let mut guard = self.0.lock().unwrap();
        match guard.as_mut() {
            Ok(timer) => Ok(timer.on_rcvd_at(now)),
            Err(_) => Err(Cancelled),
        }
    }

    /// Cancels the timer without interrupting an ongoing sleep.
    pub fn cancel(&self) {
        *self.0.lock().unwrap() = Err(Cancelled);
    }

    /// Waits for idle expiry, rechecking activity and cancellation after each sleep.
    /// Rechecks every 100ms before the first activity or while the timeout is zero.
    /// Requires Tokio's time driver when sleeping.
    pub async fn timeout(self) -> Result<Timeout, Cancelled> {
        loop {
            let ttl = {
                let guard = self.0.lock().unwrap();
                match guard.as_ref() {
                    Ok(timer) => timer.time_to_live(Instant::now()),
                    Err(_) => return Err(Cancelled),
                }
            };
            if ttl.is_zero() {
                return Ok(Timeout);
            }
            sleep(ttl).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Instant {
        Instant::now()
    }

    fn timer(max: u64) -> IdleTimer {
        IdleTimer::new(Duration::from_secs(max))
    }

    #[test]
    fn timeout_after_checks_elapsed_time_including_the_deadline() {
        let start = Instant::now();
        let duration = Duration::from_secs(10);
        assert!(!IdleSince::new().timeout_after(start + duration, duration));
        let idle = IdleSince::with_instant(start);
        assert!(!idle.timeout_after(start, duration));
        assert!(idle.timeout_after(start + duration, duration));
        assert!(idle.timeout_after(start + duration * 2, duration));
    }

    #[test]
    fn expires_in_saturates_at_zero_after_the_deadline() {
        let start = Instant::now();
        let duration = Duration::from_secs(10);
        let idle = IdleSince::with_instant(start);
        assert_eq!(idle.expires_in(start, duration), duration);
        assert_eq!(
            idle.expires_in(start + duration / 2, duration),
            duration / 2
        );
        assert_eq!(idle.expires_in(start + duration, duration), Duration::ZERO);
        assert_eq!(
            idle.expires_in(start + duration * 2, duration),
            Duration::ZERO
        );
    }

    #[test]
    fn expires_in_handles_unrepresentable_deadlines() {
        let start = Instant::now();
        let idle = IdleSince::with_instant(start);
        assert_eq!(idle.expires_in(start, Duration::MAX), Duration::MAX);
        assert_eq!(
            idle.expires_in(start + Duration::from_secs(1), Duration::MAX),
            Duration::MAX - Duration::from_secs(1)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn no_activity_waits_until_first_activity_starts_the_deadline() {
        let timer = ArcIdleTimer::new(Duration::from_secs(5));
        let start = now();
        let waiter = timer.clone().timeout();
        tokio::pin!(waiter);
        assert!(futures::poll!(&mut waiter).is_pending());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(futures::poll!(&mut waiter).is_pending());
        assert!(timer.on_sent_at(now()).unwrap().unwrap());
        assert!(matches!(waiter.await, Ok(Timeout)));
        assert_eq!(now() - start, Duration::from_secs(15));
    }

    #[tokio::test(start_paused = true)]
    async fn zero_max_idle_timeout_disables_expiry() {
        let timer = ArcIdleTimer::new(Duration::ZERO);
        assert!(timer.on_sent_at(now()).unwrap().unwrap());
        let waiter = timer.clone().timeout();
        tokio::pin!(waiter);
        assert!(futures::poll!(&mut waiter).is_pending());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(futures::poll!(&mut waiter).is_pending());
        assert!(timer.on_rcvd_at(now()).unwrap().unwrap());
        assert!(timer.on_sent_at(now()).unwrap().unwrap());
        timer.cancel();
        assert!(matches!(waiter.await, Err(Cancelled)));
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_is_observed_without_activity() {
        let timer = ArcIdleTimer::new(Duration::from_secs(5));
        let waiter = timer.clone().timeout();
        tokio::pin!(waiter);
        assert!(futures::poll!(&mut waiter).is_pending());
        timer.cancel();
        let start = now();
        assert!(matches!(waiter.await, Err(Cancelled)));
        assert_eq!(now() - start, Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn connection_expires_at_max_idle_timeout_without_an_extra_phase() {
        let timer = ArcIdleTimer::new(Duration::from_secs(5));
        let start = now();
        assert!(timer.on_rcvd_at(start).unwrap().unwrap());
        assert!(matches!(timer.timeout().await, Ok(Timeout)));
        assert_eq!(now() - start, Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_sends_without_receiving_do_not_extend_timeout() {
        let timer = ArcIdleTimer::new(Duration::from_secs(5));
        let start = now();
        assert!(timer.on_sent_at(start).unwrap().unwrap());
        for _ in 0..4 {
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(!timer.on_sent_at(now()).unwrap().unwrap());
        }
        assert!(matches!(timer.clone().timeout().await, Ok(Timeout)));
        assert_eq!(now() - start, Duration::from_secs(5));
        assert!(matches!(timer.on_sent_at(now()), Ok(Err(Timeout))));
    }

    #[tokio::test(start_paused = true)]
    async fn receive_extends_timeout_and_rearms_only_one_send() {
        let timer = ArcIdleTimer::new(Duration::from_secs(10));
        let start = now();
        assert!(timer.on_sent_at(start).unwrap().unwrap());
        let (result, ()) = tokio::join!(timer.clone().timeout(), async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            assert!(timer.on_rcvd_at(now()).unwrap().unwrap());
            tokio::time::sleep(Duration::from_secs(3)).await;
            assert!(timer.on_sent_at(now()).unwrap().unwrap());
            tokio::time::sleep(Duration::from_secs(9)).await;
            assert!(!timer.on_sent_at(now()).unwrap().unwrap());
        });
        assert!(matches!(result, Ok(Timeout)));
        assert_eq!(now() - start, Duration::from_secs(18));
    }

    #[test]
    fn activity_cannot_revive_an_expired_timer_without_waiting() {
        for update in [
            IdleTimer::on_sent_at as fn(&mut IdleTimer, Instant) -> Result<bool, Timeout>,
            IdleTimer::on_rcvd_at,
        ] {
            for elapsed in [5, 6] {
                let mut timer = timer(5);
                let start = Instant::now();
                assert!(timer.on_sent_at(start).unwrap());
                let now = start + Duration::from_secs(elapsed);
                assert!(matches!(update(&mut timer, now), Err(Timeout)));
                assert_eq!(timer.time_to_live(now), Duration::ZERO);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn late_wait_returns_timeout_without_sleeping() {
        let timer = ArcIdleTimer::new(Duration::from_secs(5));
        assert!(timer.on_sent_at(now()).unwrap().unwrap());
        tokio::time::advance(Duration::from_secs(20)).await;
        let start = now();
        assert!(matches!(timer.timeout().await, Ok(Timeout)));
        assert_eq!(now(), start);
    }

    #[tokio::test(start_paused = true)]
    async fn sleep_rechecks_receive_activity() {
        let timer = ArcIdleTimer::new(Duration::from_secs(5));
        let start = now();
        assert!(timer.on_sent_at(start).unwrap().unwrap());
        let (result, ()) = tokio::join!(timer.clone().timeout(), async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            assert!(timer.on_rcvd_at(now()).unwrap().unwrap());
        });
        assert!(matches!(result, Ok(Timeout)));
        assert_eq!(now() - start, Duration::from_secs(7));
    }

    #[tokio::test]
    async fn shared_activity_distinguishes_updates_expiry_and_cancellation() {
        let timer = ArcIdleTimer::new(Duration::from_secs(10));
        let start = Instant::now();
        assert!(matches!(timer.on_sent_at(start), Ok(Ok(true))));
        assert!(matches!(timer.on_sent_at(start), Ok(Ok(false))));
        assert!(matches!(
            timer.on_rcvd_at(start + Duration::from_secs(10)),
            Ok(Err(Timeout))
        ));
        timer.cancel();
        assert!(matches!(
            timer.on_rcvd_at(start + Duration::from_secs(11)),
            Err(Cancelled)
        ));
    }

    #[tokio::test]
    async fn cancelling_before_wait_is_permanent() {
        let timer = ArcIdleTimer::new(Duration::from_secs(10));
        timer.cancel();
        timer.cancel();
        assert!(timer.on_sent_at(Instant::now()).is_err());
        assert!(timer.on_rcvd_at(Instant::now()).is_err());
        assert!(matches!(timer.timeout().await, Err(Cancelled)));
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_is_observed_when_the_current_sleep_finishes() {
        let timer = ArcIdleTimer::new(Duration::from_secs(10));
        let start = now();
        assert!(timer.on_sent_at(start).unwrap().unwrap());
        let task = tokio::spawn(timer.clone().timeout());
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        timer.cancel();
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        assert!(matches!(task.await.unwrap(), Err(Cancelled)));
        assert_eq!(now() - start, Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn unrepresentable_deadline_does_not_panic() {
        let timer = ArcIdleTimer::new(Duration::MAX);
        assert!(timer.on_sent_at(now()).unwrap().unwrap());
        let waiter = timer.clone().timeout();
        tokio::pin!(waiter);
        assert!(futures::poll!(&mut waiter).is_pending());
        assert!(timer.on_rcvd_at(now()).unwrap().unwrap());
        assert!(futures::poll!(&mut waiter).is_pending());
    }

    #[tokio::test(start_paused = true)]
    async fn detached_timeout_task_stops_at_expiry_or_cancellation() {
        for cancelled in [false, true] {
            let timer = ArcIdleTimer::new(Duration::from_secs(10));
            timer.on_sent_at(now()).unwrap().unwrap();
            tokio::spawn(timer.clone().timeout());
            let state = Arc::downgrade(&timer.0);
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_secs(2)).await;
            if cancelled {
                timer.cancel();
            }
            drop(timer);
            tokio::task::yield_now().await;
            assert!(state.upgrade().is_some());
            tokio::time::advance(Duration::from_secs(8)).await;
            tokio::task::yield_now().await;
            assert!(state.upgrade().is_none());
        }
    }
}
