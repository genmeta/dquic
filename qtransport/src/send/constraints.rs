/// Fixed per-packet limits; assembly does not debit these values.
/// Flow credit remains in qbase's shared flow controller; STREAM sources acquire
/// it there, rather than copying it into each Path.
#[derive(Debug)]
pub struct Constraints {
    pub capacity: usize,
    pub congestion: usize,
    pub anti_amplification: usize,
}

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use qcongestion::PathStatus;

/// Shared with receive-side path accounting; only successful submissions debit credit.
pub struct AntiAmplifier {
    received: AtomicU64,
    sent: AtomicU64,
    validated: AtomicBool,
    status: PathStatus,
}

impl AntiAmplifier {
    pub fn new(status: PathStatus) -> Self {
        Self {
            received: 0.into(),
            sent: 0.into(),
            validated: false.into(),
            status,
        }
    }

    pub fn balance(&self) -> usize {
        if self.validated.load(Ordering::Acquire) {
            return usize::MAX;
        }
        self.received
            .load(Ordering::Acquire)
            .saturating_mul(3)
            .saturating_sub(self.sent.load(Ordering::Acquire))
            .min(usize::MAX as u64) as usize
    }

    pub fn on_received(&self, bytes: usize) {
        self.received.fetch_add(bytes as u64, Ordering::AcqRel);
        if self.balance() >= 1200 {
            self.status.release_anti_amplification_limit();
        }
    }

    pub fn grant(&self) {
        self.validated.store(true, Ordering::Release);
        self.status.release_anti_amplification_limit();
    }

    pub fn on_sent(&self, bytes: usize) {
        self.sent.fetch_add(bytes as u64, Ordering::AcqRel);
        if self.balance() < 1200 {
            self.status.enter_anti_amplification_limit();
        }
    }
}
