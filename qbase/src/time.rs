use thiserror::Error;
use tokio::time::{Duration, Instant};

pub mod heartbeat;
pub mod timer;

#[derive(Debug, Error)]
#[error("Connection has been idle for too long")]
pub struct Timeout;

#[derive(Debug)]
pub struct IdleSince {
    idle_since: Option<Instant>,
    // Allows one send update after initialization or a receive.
    can_update: bool,
}

impl IdleSince {
    pub fn new() -> Self {
        Self {
            idle_since: None,
            can_update: true,
        }
    }

    pub fn with_instant(now: Instant) -> Self {
        Self {
            idle_since: Some(now),
            can_update: true,
        }
    }

    pub fn on_sent_at(&mut self, now: Instant) -> bool {
        if self.can_update {
            self.idle_since = Some(now);
            self.can_update = false;
            return true;
        }
        false
    }

    pub fn on_rcvd_at(&mut self, now: Instant) -> bool {
        self.idle_since = Some(now);
        self.can_update = true;
        true
    }

    pub fn expires_in(&self, now: Instant, timeout: Duration) -> Duration {
        match (timeout, self.idle_since) {
            // check agagin later
            (Duration::ZERO, _) | (_, None) => Duration::from_millis(100),
            (_, Some(t)) => timeout.saturating_sub(now.saturating_duration_since(t)),
        }
    }

    pub fn timeout_after(&self, now: Instant, duration: Duration) -> bool {
        self.idle_since
            .and_then(|since| now.checked_duration_since(since))
            .is_some_and(|elapsed| elapsed >= duration)
    }
}
