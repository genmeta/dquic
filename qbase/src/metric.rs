use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// Metrics for tracking data volumes in a QUIC connection.
///
/// This struct provides atomic counters to track:
/// - Data written by application but not yet sent
/// - Data sent but not yet acknowledged
/// - Data sent and acknowledged
///
/// Pending and inflight data must each fit in `usize`. The cumulative acknowledged
/// counter wraps at `usize::MAX`; see [`Self::acked_bytes`] for sampling it.
#[derive(Debug, Default)]
pub struct ConnectionMetrics {
    /// Data written by application layer but not yet sent by transport layer
    pending_bytes: AtomicUsize,
    /// Data sent by transport layer but not yet acknowledged by peer
    inflight_bytes: AtomicUsize,
    /// Data sent and acknowledged by peer
    acked_bytes: AtomicUsize,
}

impl ConnectionMetrics {
    /// Increments the pending send bytes counter when application writes data.
    ///
    /// Called when application layer writes data to a stream.
    pub fn add_pending(&self, amount: usize) {
        self.pending_bytes.fetch_add(amount, Ordering::Relaxed);
    }

    /// Updates counters when transport layer sends new data.
    ///
    /// Increments sent_unacked_bytes and decrements pending_send_bytes.
    /// Called when transport layer sends new stream data.
    pub fn on_data_sent(&self, amount: usize) {
        self.inflight_bytes.fetch_add(amount, Ordering::Relaxed);
        self.pending_bytes.fetch_sub(amount, Ordering::Relaxed);
    }

    /// Updates counters when data is acknowledged by peer.
    ///
    /// Increments sent_acked_bytes and decrements sent_unacked_bytes.
    /// Called when receiving acknowledgment for stream data.
    pub fn on_data_acked(&self, amount: usize) {
        self.acked_bytes.fetch_add(amount, Ordering::Relaxed);
        self.inflight_bytes.fetch_sub(amount, Ordering::Relaxed);
    }

    /// Gets the current amount of data pending to be sent.
    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes.load(Ordering::Relaxed)
    }

    /// Gets the current amount of data sent but not acknowledged.
    pub fn inflight_bytes(&self) -> usize {
        self.inflight_bytes.load(Ordering::Relaxed)
    }

    /// Gets the cumulative acknowledged byte count, modulo `usize::MAX + 1`.
    ///
    /// Use `current.wrapping_sub(previous)` to get the bytes acknowledged between
    /// samples, provided fewer than `2^usize::BITS` bytes were acknowledged between
    /// them (less than 4 GiB on a 32-bit target). Snapshots cannot be compared with
    /// ordinary subtraction or ordering across a wrap.
    pub fn acked_bytes(&self) -> usize {
        self.acked_bytes.load(Ordering::Relaxed)
    }
}

/// Arc-wrapped ConnectionMetrics for shared ownership across the connection.
pub type ArcConnectionMetrics = Arc<ConnectionMetrics>;
