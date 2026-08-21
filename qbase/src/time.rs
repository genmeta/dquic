use std::sync::{Arc, Mutex, RwLock};

use thiserror::Error;
use tokio::time::{Duration, Instant};

use crate::packet::PacketContent;

pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);

#[derive(Debug, Error)]
#[error("Path has been idle for too long")]
pub struct TimeOut;

#[derive(Debug)]
struct IdleConfig {
    max_idle_timeout: Duration,
    defer_idle_timeout: Duration,
    heartbeat_interval: Duration,
}

impl IdleConfig {
    fn new(
        max_idle_timeout: Duration,
        defer_idle_timeout: Duration,
        heartbeat_interval: Duration,
    ) -> Self {
        Self {
            max_idle_timeout,
            defer_idle_timeout,
            heartbeat_interval,
        }
    }

    fn negotiate_max_idle_timeout(&mut self, remote: Duration) {
        match (self.max_idle_timeout, remote) {
            (_, Duration::ZERO) => {}
            (Duration::ZERO, remote) => self.max_idle_timeout = remote,
            (local, remote) => self.max_idle_timeout = local.min(remote),
        }
    }
}

/// Negotiated idle policy and connection-wide idle activity.
#[derive(Debug, Clone)]
pub struct ArcConnIdle {
    config: Arc<RwLock<IdleConfig>>,
    idle_since: Arc<Mutex<Option<Instant>>>,
    die_since: Arc<Mutex<Instant>>,
}

impl ArcConnIdle {
    pub fn new(
        max_idle_timeout: Duration,
        defer_idle_timeout: Duration,
        heartbeat_interval: Duration,
    ) -> Self {
        Self {
            config: Arc::new(RwLock::new(IdleConfig::new(
                max_idle_timeout,
                defer_idle_timeout,
                heartbeat_interval,
            ))),
            idle_since: Arc::new(Mutex::new(None)),
            die_since: Arc::new(Mutex::new(Instant::now())),
        }
    }

    pub fn negotiate_max_idle_timeout(&self, remote: Duration) {
        self.config
            .write()
            .unwrap()
            .negotiate_max_idle_timeout(remote);
    }

    pub fn timer(&self) -> PathIdleTimer {
        PathIdleTimer {
            conn_idle: self.clone(),
            activity: Mutex::new(PathIdleActivity {
                path_die_since: Instant::now(),
                update_idle_on_send: true,
                update_die_on_send: true,
                last_sent_ack_eliciting: None,
            }),
        }
    }

    fn update_idle_since(&self, now: Instant) {
        *self.idle_since.lock().unwrap() = Some(now);
    }

    fn update_die_since(&self, now: Instant) {
        *self.die_since.lock().unwrap() = now;
    }

    fn keep_alive_allowed(&self, now: Instant) -> bool {
        let config = self.config.read().unwrap();
        if config.defer_idle_timeout == Duration::ZERO {
            return false;
        }
        self.idle_since.lock().unwrap().is_some_and(|last| {
            last.checked_add(config.defer_idle_timeout)
                .is_none_or(|deadline| now < deadline)
        })
    }
}

#[derive(Debug)]
struct PathIdleActivity {
    path_die_since: Instant,
    update_idle_on_send: bool,
    update_die_on_send: bool,
    last_sent_ack_eliciting: Option<Instant>,
}

/// Path-local KeepAlive and liveness state backed by connection-wide idle policy.
#[derive(Debug)]
pub struct PathIdleTimer {
    conn_idle: ArcConnIdle,
    activity: Mutex<PathIdleActivity>,
}

impl PathIdleTimer {
    pub fn on_sent(&self, packet_content: PacketContent) {
        let now = Instant::now();
        let mut activity = self.activity.lock().unwrap();
        if packet_content == PacketContent::EffectivePayload && activity.update_idle_on_send {
            self.conn_idle.update_idle_since(now);
            activity.update_idle_on_send = false;
        }
        if packet_content.is_ack_eliciting() {
            if activity.update_die_on_send {
                self.conn_idle.update_die_since(now);
                activity.path_die_since = now;
                activity.update_die_on_send = false;
            }
            activity.last_sent_ack_eliciting = Some(now);
        }
        drop(activity);
    }

    pub fn on_rcvd(&self, packet_content: PacketContent) {
        let now = Instant::now();
        let mut activity = self.activity.lock().unwrap();
        activity.path_die_since = now;
        activity.update_idle_on_send = true;
        activity.update_die_on_send = true;
        drop(activity);

        self.conn_idle.update_die_since(now);
        if packet_content == PacketContent::EffectivePayload {
            self.conn_idle.update_idle_since(now);
        }
    }

    pub fn keep_alive_due(&self, now: Instant) -> bool {
        if !self.conn_idle.keep_alive_allowed(now) {
            return false;
        }
        let heartbeat_interval = self.conn_idle.config.read().unwrap().heartbeat_interval;
        self.activity
            .lock()
            .unwrap()
            .last_sent_ack_eliciting
            .and_then(|last| last.checked_add(heartbeat_interval))
            .is_some_and(|deadline| now >= deadline)
    }

    /// Checks the connection-wide idle deadline.
    pub fn timed_out(&self, now: Instant, pto_base: Duration) -> bool {
        let max_idle_timeout = self.conn_idle.config.read().unwrap().max_idle_timeout;
        if max_idle_timeout == Duration::ZERO {
            return false;
        }
        let timeout = max_idle_timeout.max(pto_base.saturating_mul(3));
        let die_since = *self.conn_idle.die_since.lock().unwrap();
        let timed_out = now
            .checked_duration_since(die_since)
            .is_some_and(|elapsed| elapsed >= timeout);
        timed_out
    }

    /// Checks the path-local deadline used to retire an unresponsive path.
    pub fn path_timed_out(&self, now: Instant, pto_base: Duration) -> bool {
        let max_idle_timeout = self.conn_idle.config.read().unwrap().max_idle_timeout;
        if max_idle_timeout == Duration::ZERO {
            return false;
        }
        let timeout = max_idle_timeout.max(pto_base.saturating_mul(3));
        let path_die_since = self.activity.lock().unwrap().path_die_since;
        now.checked_duration_since(path_die_since)
            .is_some_and(|elapsed| elapsed >= timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn negotiated_timeout_applies_to_existing_path_timers() {
        let conn_idle = ArcConnIdle::new(
            Duration::from_secs(20),
            Duration::ZERO,
            DEFAULT_HEARTBEAT_INTERVAL,
        );
        let timer = conn_idle.timer();
        conn_idle.negotiate_max_idle_timeout(Duration::from_secs(12));

        tokio::time::advance(Duration::from_secs(11)).await;
        assert!(!timer.timed_out(Instant::now(), Duration::from_secs(1)));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(timer.timed_out(Instant::now(), Duration::from_secs(1)));
    }

    #[tokio::test(start_paused = true)]
    async fn path_idle_timeout_is_at_least_three_pto() {
        let timer = ArcConnIdle::new(
            Duration::from_secs(5),
            Duration::ZERO,
            DEFAULT_HEARTBEAT_INTERVAL,
        )
        .timer();

        tokio::time::advance(Duration::from_secs(14)).await;
        assert!(!timer.timed_out(Instant::now(), Duration::from_secs(5)));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(timer.timed_out(Instant::now(), Duration::from_secs(5)));
    }

    #[tokio::test(start_paused = true)]
    async fn only_first_ack_eliciting_send_after_receive_extends_connection_idle() {
        let timer = ArcConnIdle::new(
            Duration::from_secs(20),
            Duration::ZERO,
            DEFAULT_HEARTBEAT_INTERVAL,
        )
        .timer();

        tokio::time::advance(Duration::from_secs(10)).await;
        timer.on_sent(PacketContent::JustPing);
        tokio::time::advance(Duration::from_secs(10)).await;
        timer.on_sent(PacketContent::EffectivePayload);
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(!timer.timed_out(Instant::now(), Duration::ZERO));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(timer.timed_out(Instant::now(), Duration::ZERO));

        timer.on_rcvd(PacketContent::EffectivePayload);
        assert!(!timer.timed_out(Instant::now(), Duration::ZERO));
    }

    #[tokio::test(start_paused = true)]
    async fn effective_payload_on_one_path_opens_keep_alive_for_another() {
        let conn_idle = ArcConnIdle::new(
            Duration::from_secs(120),
            Duration::from_secs(40),
            DEFAULT_HEARTBEAT_INTERVAL,
        );
        let active_path = conn_idle.timer();
        let idle_path = conn_idle.timer();
        idle_path.on_sent(PacketContent::JustPing);

        active_path.on_sent(PacketContent::EffectivePayload);
        tokio::time::advance(Duration::from_secs(30)).await;

        assert!(idle_path.keep_alive_due(Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn effective_payload_restarts_the_same_path_heartbeat_interval() {
        let timer = ArcConnIdle::new(
            Duration::from_secs(20),
            Duration::from_secs(30),
            Duration::from_secs(10),
        )
        .timer();
        timer.on_sent(PacketContent::JustPing);

        tokio::time::advance(Duration::from_secs(9)).await;
        timer.on_sent(PacketContent::EffectivePayload);
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(!timer.keep_alive_due(Instant::now()));

        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(timer.keep_alive_due(Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_interval_is_fixed_at_twenty_seconds() {
        let short_idle = ArcConnIdle::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            DEFAULT_HEARTBEAT_INTERVAL,
        )
        .timer();
        short_idle.on_sent(PacketContent::EffectivePayload);

        tokio::time::advance(Duration::from_secs(19)).await;
        assert!(!short_idle.keep_alive_due(Instant::now()));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(short_idle.keep_alive_due(Instant::now()));

        let long_idle = ArcConnIdle::new(
            Duration::from_secs(120),
            Duration::from_secs(60),
            DEFAULT_HEARTBEAT_INTERVAL,
        )
        .timer();
        long_idle.on_sent(PacketContent::EffectivePayload);

        tokio::time::advance(Duration::from_secs(19)).await;
        assert!(!long_idle.keep_alive_due(Instant::now()));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(long_idle.keep_alive_due(Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn connection_idle_is_shared_but_path_liveness_is_local() {
        let conn_idle = ArcConnIdle::new(
            Duration::from_secs(20),
            Duration::ZERO,
            DEFAULT_HEARTBEAT_INTERVAL,
        );
        let active_path = conn_idle.timer();
        let idle_path = conn_idle.timer();

        tokio::time::advance(Duration::from_secs(10)).await;
        active_path.on_rcvd(PacketContent::EffectivePayload);
        tokio::time::advance(Duration::from_secs(10)).await;

        assert!(!active_path.timed_out(Instant::now(), Duration::ZERO));
        assert!(!idle_path.timed_out(Instant::now(), Duration::ZERO));
        assert!(!active_path.path_timed_out(Instant::now(), Duration::ZERO));
        assert!(idle_path.path_timed_out(Instant::now(), Duration::ZERO));
    }

    #[tokio::test(start_paused = true)]
    async fn retransmitted_effective_payload_does_not_extend_connection_keep_alive_window() {
        let conn_idle = ArcConnIdle::new(
            Duration::from_secs(120),
            Duration::from_secs(20),
            DEFAULT_HEARTBEAT_INTERVAL,
        );
        let active_path = conn_idle.timer();
        let idle_path = conn_idle.timer();
        idle_path.on_sent(PacketContent::JustPing);

        active_path.on_sent(PacketContent::EffectivePayload);
        tokio::time::advance(Duration::from_secs(15)).await;
        active_path.on_sent(PacketContent::EffectivePayload);
        tokio::time::advance(Duration::from_secs(15)).await;

        assert!(!conn_idle.keep_alive_allowed(Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn sent_effective_payload_updates_idle_since_only_once_until_receive() {
        let conn_idle = ArcConnIdle::new(
            Duration::from_secs(120),
            Duration::from_secs(20),
            DEFAULT_HEARTBEAT_INTERVAL,
        );
        let timer = conn_idle.timer();

        timer.on_sent(PacketContent::EffectivePayload);
        tokio::time::advance(Duration::from_secs(15)).await;
        timer.on_sent(PacketContent::EffectivePayload);
        tokio::time::advance(Duration::from_secs(6)).await;

        assert!(!conn_idle.keep_alive_allowed(Instant::now()));

        timer.on_rcvd(PacketContent::NonAckEliciting);
        timer.on_sent(PacketContent::EffectivePayload);
        assert!(conn_idle.keep_alive_allowed(Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn ping_does_not_open_connection_keep_alive_window() {
        let timer = ArcConnIdle::new(
            Duration::from_secs(20),
            Duration::from_secs(20),
            DEFAULT_HEARTBEAT_INTERVAL,
        )
        .timer();
        timer.on_sent(PacketContent::JustPing);

        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(!timer.keep_alive_due(Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn received_packets_do_not_restart_keep_alive_send_interval() {
        let timer = ArcConnIdle::new(
            Duration::from_secs(120),
            Duration::from_secs(120),
            DEFAULT_HEARTBEAT_INTERVAL,
        )
        .timer();
        timer.on_sent(PacketContent::EffectivePayload);

        tokio::time::advance(Duration::from_secs(30)).await;
        timer.on_rcvd(PacketContent::EffectivePayload);
        tokio::time::advance(Duration::from_secs(30)).await;

        assert!(timer.keep_alive_due(Instant::now()));
    }
}
