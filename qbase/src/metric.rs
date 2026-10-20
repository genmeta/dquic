use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// Metrics for tracking data volumes in a QUIC connection.
///
/// This struct provides atomic counters to track:
/// - Data written by application but not yet sent
/// - Data sent but not yet acknowledged
/// - Data sent and acknowledged
#[derive(Debug, Default)]
pub struct ConnectionMetrics {
    /// Data written by application layer but not yet sent by transport layer
    pending_bytes: AtomicU64,
    /// Data sent by transport layer but not yet acknowledged by peer
    inflight_bytes: AtomicU64,
    /// Data sent and acknowledged by peer
    acked_bytes: AtomicU64,
}

impl ConnectionMetrics {
    /// Increments the pending send bytes counter when application writes data.
    ///
    /// Called when application layer writes data to a stream.
    pub fn new_pending(&self, bytes: u64) {
        self.pending_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Updates counters when transport layer sends new data.
    ///
    /// Increments sent_unacked_bytes and decrements pending_send_bytes.
    /// Called when transport layer sends new stream data.
    pub fn on_data_sent(&self, bytes: u64) {
        self.inflight_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.pending_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Updates counters when data is acknowledged by peer.
    ///
    /// Increments sent_acked_bytes and decrements sent_unacked_bytes.
    /// Called when receiving acknowledgment for stream data.
    pub fn on_data_acked(&self, bytes: u64) {
        self.acked_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.inflight_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Gets the current amount of data pending to be sent.
    pub fn pending_bytes(&self) -> u64 {
        self.pending_bytes.load(Ordering::Relaxed)
    }

    /// Gets the current amount of data sent but not acknowledged.
    pub fn inflight_bytes(&self) -> u64 {
        self.inflight_bytes.load(Ordering::Relaxed)
    }

    /// Gets the total amount of data sent and acknowledged.
    pub fn acked_bytes(&self) -> u64 {
        self.acked_bytes.load(Ordering::Relaxed)
    }
}

/// Arc-wrapped ConnectionMetrics for shared ownership across the connection.
pub type ArcConnectionMetrics = Arc<ConnectionMetrics>;
