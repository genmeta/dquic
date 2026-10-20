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
