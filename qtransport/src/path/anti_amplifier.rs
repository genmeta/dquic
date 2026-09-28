use std::{
    sync::Mutex,
    task::{Context, Poll, Waker},
};

use qbase::{
    error::{Error, ErrorKind, QuicError},
    net::tx::ArcSendWakers,
};
use qcongestion::PathStatus;

use crate::path::PathState;

/// Shared path state; only successful submissions debit amplification credit.
pub struct AntiAmplifier {
    pub(crate) state: Mutex<PathState>,
    status: PathStatus,
    wakers: ArcSendWakers,
}

impl AntiAmplifier {
    pub fn new(status: PathStatus) -> Self {
        Self {
            state: Mutex::new(PathState::AmplifyGuard {
                rcvd_bytes: 0,
                sent_bytes: 0,
            }),
            status,
            wakers: Default::default(),
        }
    }

    pub fn poll_credit(&self, cx: &mut Context<'_>) -> Poll<Result<usize, Error>> {
        self.wakers.register(cx.waker());
        if *self.state.lock().unwrap() == PathState::Retired {
            return Poll::Ready(Err(QuicError::with_default_fty(
                ErrorKind::NoViablePath,
                "path retired",
            )
            .into()));
        }
        Poll::Ready(Ok(self.balance()))
    }

    pub fn cancel(&self, waker: &Waker) {
        self.wakers.cancel(waker);
    }

    pub(crate) fn retire(&self) {
        *self.state.lock().unwrap() = PathState::Retired;
        self.wakers.wake_all();
    }

    pub fn balance(&self) -> usize {
        match *self.state.lock().unwrap() {
            PathState::ClientHandshaking | PathState::ClientValidating | PathState::Validated => {
                usize::MAX
            }
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
        drop(state);
        self.wakers.wake_all();
    }

    pub fn grant(&self) {
        let mut state = self.state.lock().unwrap();
        if *state != PathState::Retired {
            *state = PathState::Validated;
            self.status.release_anti_amplification_limit();
        }
        drop(state);
        self.wakers.wake_all();
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

    pub(crate) fn client_validating(&self) {
        let mut state = self.state.lock().unwrap();
        if matches!(
            *state,
            PathState::AmplifyGuard { .. } | PathState::ClientHandshaking
        ) {
            *state = PathState::ClientValidating;
            self.status.release_anti_amplification_limit();
        }
        drop(state);
        self.wakers.wake_all();
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
