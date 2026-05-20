use std::sync::{Arc, Mutex, RwLock};

use thiserror::Error;
use tokio::time::{Duration, Instant};

use crate::{frame::PingFrame, packet::PacketContent};

#[derive(Debug, Error)]
#[error("Path has been idle for too long")]
pub struct TimeOut;

#[derive(Debug)]
pub struct IdleConfig {
    max_idle_timeout: Duration,
    defer_idle_timeout: Duration,
    heartbeat_interval: Duration,
}

impl IdleConfig {
    fn suitable_heartbeat_interval(max_idle_timeout: Duration) -> Duration {
        if max_idle_timeout == Duration::ZERO {
            Duration::from_secs(30)
        } else {
            (max_idle_timeout / 2)
                .max(Duration::from_secs(1))
                .min(Duration::from_secs(30))
        }
    }

    // Creates a new `IdleTimer` with the specified maximum idle timeout and defer idle timeout.
    pub fn new(max_idle_timeout: Duration, defer_idle_timeout: Duration) -> Self {
        let heartbeat_interval = Self::suitable_heartbeat_interval(max_idle_timeout);
        Self {
            max_idle_timeout,
            defer_idle_timeout,
            heartbeat_interval,
        }
    }

    // Each endpoint advertises a max_idle_timeout, but the effective value at an endpoint
    // is computed as the minimum of the two advertised values (or the sole advertised value,
    // if only one endpoint advertises a non-zero value).
    //
    // Idle timeout is disabled when both endpoints omit this transport parameter or specify a value of 0.
    pub fn negotiate_max_idle_timeout(&mut self, max_idle_timeout: Duration) {
        match (self.max_idle_timeout, max_idle_timeout) {
            (_, Duration::ZERO) => (),
            (Duration::ZERO, remote) => self.max_idle_timeout = remote,
            (local, remote) => self.max_idle_timeout = local.min(remote),
        }
        self.heartbeat_interval = Self::suitable_heartbeat_interval(self.max_idle_timeout);
    }

    // Sets the interval for sending heartbeat packets.
    pub fn set_heartbeat_interval(&mut self, interval: Duration) {
        self.heartbeat_interval = interval;
    }
}

#[derive(Debug, Clone)]
pub struct ArcIdleConfig(Arc<RwLock<IdleConfig>>);

impl ArcIdleConfig {
    // Creates a new `ArcIdleConfig` with the specified maximum idle timeout and defer idle timeout.
    pub fn new(max_idle_timeout: Duration, defer_idle_timeout: Duration) -> Self {
        ArcIdleConfig(Arc::new(RwLock::new(IdleConfig::new(
            max_idle_timeout,
            defer_idle_timeout,
        ))))
    }

    // Each endpoint advertises a max_idle_timeout, but the effective value at an endpoint
    // is computed as the minimum of the two advertised values (or the sole advertised value,
    // if only one endpoint advertises a non-zero value).
    //
    // Idle timeout is disabled when both endpoints omit this transport parameter or specify a value of 0.
    pub fn negotiate_max_idle_timeout(&self, max_idle_timeout: Duration) {
        self.0
            .write()
            .unwrap()
            .negotiate_max_idle_timeout(max_idle_timeout);
    }

    // Sets the interval for sending heartbeat packets.
    pub fn set_heartbeat_interval(&self, interval: Duration) {
        self.0.write().unwrap().set_heartbeat_interval(interval);
    }

    pub fn timer(&self) -> ArcIdleTimer {
        ArcIdleTimer(Arc::new(Mutex::new(IdleTimer {
            idle_config: self.clone(),
            heartbeat_times: 0,
            last_effective_comm: None,
            idle_begin_at: None,
        })))
    }

    fn defer_idle_timeout(&self) -> Duration {
        self.0.read().unwrap().defer_idle_timeout
    }

    fn heartbeat_interval(&self) -> Duration {
        self.0.read().unwrap().heartbeat_interval
    }

    fn timeout_after(&self, idle_at: Instant) -> bool {
        let max_idle_timeout = self.0.read().unwrap().max_idle_timeout;
        max_idle_timeout != Duration::ZERO && idle_at.elapsed() > max_idle_timeout
    }
}

// A timer for each path to determine when to send heartbeat packets
// and when to delete the path due to idle timeout.
#[derive(Debug)]
pub struct IdleTimer {
    idle_config: ArcIdleConfig,
    heartbeat_times: u32,
    last_effective_comm: Option<Instant>,
    idle_begin_at: Option<Instant>,
}

impl IdleTimer {
    pub fn on_sent(&mut self, _packet_content: PacketContent) {
        // Temporarily disabled.
        //
        // Sending a packet locally is not evidence that the peer is still reachable.  The previous
        // implementation reset `last_effective_comm`, `heartbeat_times`, and, most importantly,
        // `idle_begin_at` whenever an EffectivePayload packet was assembled for transmission.  If a
        // peer disappears while this endpoint still has ack-eliciting payload to retransmit, those
        // retransmissions repeatedly call this hook and keep clearing `idle_begin_at`.  The path can
        // then keep itself alive without receiving anything from the peer, which turns stale
        // connections into an unbounded send storm.
        //
        // Keep the hook as a compatibility stub for now so the per-path idle timer work from
        // 835b9e9566db04168a055ec04e2aeb2aa3a427e3 does not need to be reverted wholesale.  A
        // future cleanup should split heartbeat/defer-idle bookkeeping from max-idle liveness
        // tracking.  Until then, only receive-side activity may refresh this timer.
    }

    // Updates the timer when a packet is received.
    pub fn on_rcvd(&mut self, packet_content: PacketContent) {
        if packet_content == PacketContent::EffectivePayload {
            self.last_effective_comm = Some(Instant::now());
            self.heartbeat_times = 0;
            self.idle_begin_at = None;
        }
        if self.idle_begin_at.is_some() {
            self.idle_begin_at = Some(Instant::now());
        }
    }

    // Checks health of the path and
    // determines whether a heartbeat packet needs to be sent.
    pub fn health(&mut self) -> Result<Option<PingFrame>, TimeOut> {
        if let Some(t) = self.last_effective_comm {
            let elapsed = t.elapsed();
            if elapsed > self.idle_config.defer_idle_timeout() {
                if self.idle_begin_at.is_none() {
                    self.idle_begin_at = Some(Instant::now());
                    return Ok(Some(PingFrame)); // heartbeat for the last time
                }
            } else if elapsed > self.idle_config.heartbeat_interval() * (self.heartbeat_times + 1) {
                self.heartbeat_times += 1;
                return Ok(Some(PingFrame));
            }
        }
        if self
            .idle_begin_at
            .is_some_and(|t| self.idle_config.timeout_after(t))
        {
            return Err(TimeOut);
        }
        Ok(None)
    }
}

// A shared timer for each path to determine when to send heartbeat packets
// and when to delete the path due to idle timeout.
#[derive(Debug, Clone)]
pub struct ArcIdleTimer(Arc<Mutex<IdleTimer>>);

impl ArcIdleTimer {
    // Updates the timer when a packet is sent.
    pub fn on_sent(&self, packet_content: PacketContent) {
        self.0.lock().unwrap().on_sent(packet_content);
    }

    // Updates the timer when a packet is received.
    pub fn on_rcvd(&self, packet_content: PacketContent) {
        self.0.lock().unwrap().on_rcvd(packet_content);
    }

    // Checks health of the path and
    // determines whether a heartbeat packet needs to be sent.
    pub fn health(&self) -> Result<Option<PingFrame>, TimeOut> {
        self.0.lock().unwrap().health()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sent_effective_payload_does_not_extend_idle_timeout() {
        let mut timer = IdleTimer {
            idle_config: ArcIdleConfig::new(Duration::from_millis(10), Duration::ZERO),
            heartbeat_times: 0,
            last_effective_comm: None,
            idle_begin_at: None,
        };

        timer.on_rcvd(PacketContent::EffectivePayload);
        assert!(timer.health().expect("timer should be healthy").is_some());

        std::thread::sleep(Duration::from_millis(6));
        timer.on_sent(PacketContent::EffectivePayload);
        std::thread::sleep(Duration::from_millis(6));

        assert!(timer.health().is_err());
    }
}
