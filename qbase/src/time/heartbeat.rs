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
    frame::PingFrame,
    packet::{Package, PacketBuffer, PacketContent},
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
        buffer: &mut PacketBuffer<'_, B>,
    ) -> Poll<Result<usize, Error>> {
        if !self.time_to_heartbeat().is_zero() {
            self.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        self.waker = None;
        let result = PingFrame.poll_dump(cx, buffer);
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
        buffer: &mut PacketBuffer<'_, B>,
    ) -> Poll<Result<usize, Error>> {
        let mut guard = self.0.lock().unwrap();
        match guard.as_mut() {
            Ok(heartbeat) => heartbeat.poll_dump(cx, buffer),
            Err(_) => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;
    use crate::packet::{Constraints, GetType, OneRttHeader};

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
            &mut PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0),
        );
        if matches!(result, Poll::Ready(Ok(1))) {
            assert_eq!(&bytes[..], &[0x01]);
            assert!(frames.is_empty());
        } else {
            assert!(bytes.is_empty());
            assert!(frames.is_empty());
        }
        result
    }

    // The public constructor and adaptation clamp the interval above zero.
    #[tokio::test(start_paused = true)]
    async fn zero_interval_disables_heartbeats() {
        let mut heartbeat = Heartbeat {
            heartbeat_interval: Duration::ZERO,
            ..Heartbeat::new(Duration::from_secs(30), Duration::ZERO)
        };
        heartbeat.on_sent_at(PacketContent::EffectivePayload, Instant::now());
        tokio::time::advance(Duration::from_secs(100)).await;
        assert!(poll(&mut heartbeat, 1, Waker::noop()).is_pending());
    }
}
