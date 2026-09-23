/// Fixed per-packet limits; assembly does not debit these values.
/// Flow credit remains in qbase's shared flow controller; STREAM sources acquire
/// it there, rather than copying it into each Path.
#[derive(Debug)]
pub struct Constraints {
    pub capacity: usize,
    pub congestion: usize,
    pub anti_amplification: usize,
}

use std::sync::Mutex;

use qcongestion::PathStatus;

use crate::path::PathState;

/// Shared path state; only successful submissions debit amplification credit.
pub struct AntiAmplifier {
    pub(crate) state: Mutex<PathState>,
    status: PathStatus,
}

impl AntiAmplifier {
    pub fn new(status: PathStatus) -> Self {
        Self {
            state: Mutex::new(PathState::AmplifyGuard {
                rcvd_bytes: 0,
                sent_bytes: 0,
            }),
            status,
        }
    }

    pub fn balance(&self) -> usize {
        match *self.state.lock().unwrap() {
            PathState::ClientHandshaking | PathState::Validated => usize::MAX,
            PathState::AmplifyGuard {
                rcvd_bytes,
                sent_bytes,
            } => rcvd_bytes.saturating_mul(3).saturating_sub(sent_bytes),
            PathState::Retired => 0,
        }
    }

    pub fn on_received(&self, bytes: usize) {
        let mut state = self.state.lock().unwrap();
        if let PathState::AmplifyGuard {
            rcvd_bytes,
            sent_bytes,
        } = &mut *state
        {
            *rcvd_bytes = rcvd_bytes.saturating_add(bytes);
            if rcvd_bytes.saturating_mul(3).saturating_sub(*sent_bytes) >= 1200 {
                self.status.release_anti_amplification_limit();
            }
        }
    }

    pub fn grant(&self) {
        let mut state = self.state.lock().unwrap();
        if *state != PathState::Retired {
            *state = PathState::Validated;
            self.status.release_anti_amplification_limit();
        }
    }

    pub fn on_sent(&self, bytes: usize) {
        let mut state = self.state.lock().unwrap();
        if let PathState::AmplifyGuard {
            rcvd_bytes,
            sent_bytes,
        } = &mut *state
        {
            *sent_bytes = sent_bytes.saturating_add(bytes);
            if rcvd_bytes.saturating_mul(3).saturating_sub(*sent_bytes) < 1200 {
                self.status.enter_anti_amplification_limit();
            }
        }
    }

    pub(crate) fn client_handshaking(&self) {
        let mut state = self.state.lock().unwrap();
        if matches!(*state, PathState::AmplifyGuard { .. }) {
            *state = PathState::ClientHandshaking;
            self.status.release_anti_amplification_limit();
        }
    }

    pub(crate) fn guard(&self) {
        let mut state = self.state.lock().unwrap();
        if *state == PathState::ClientHandshaking {
            *state = PathState::AmplifyGuard {
                rcvd_bytes: 0,
                sent_bytes: 0,
            };
            self.status.enter_anti_amplification_limit();
        }
    }
}
