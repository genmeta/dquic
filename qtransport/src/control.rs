//! Per-space permissions. Connection phases belong to the external lifecycle driver.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, Ordering},
};

use tokio::sync::Notify;

const DISABLED: u8 = 0;
const ENABLED: u8 = 1;
const STOPPED: u8 = 2;

pub struct Control {
    receiving: AtomicU8,
    sending: AtomicU8,
    pub(crate) submission: Arc<Mutex<()>>,
    changed: Notify,
}

impl Control {
    /// All spaces of a connection must share the same submission boundary.
    pub fn new(submission: Arc<Mutex<()>>) -> Self {
        Self {
            receiving: DISABLED.into(),
            sending: DISABLED.into(),
            submission,
            changed: Notify::new(),
        }
    }

    pub fn enable_receiving(&self) {
        self.enable(&self.receiving);
    }
    pub fn enable_sending(&self) {
        self.enable(&self.sending);
    }
    pub fn stop_receiving(&self) {
        self.stop(&self.receiving);
    }
    pub fn stop_sending(&self) {
        self.stop(&self.sending);
    }
    pub fn can_receive(&self) -> bool {
        self.receiving.load(Ordering::Acquire) == ENABLED
    }
    pub fn sending_stopped(&self) -> bool {
        self.sending.load(Ordering::Acquire) == STOPPED
    }
    pub fn can_send(&self) -> bool {
        self.sending.load(Ordering::Acquire) == ENABLED
    }

    pub(crate) fn retire_locked(&self) {
        self.receiving.store(STOPPED, Ordering::Release);
        self.sending.store(STOPPED, Ordering::Release);
        self.changed.notify_waiters();
    }

    fn enable(&self, state: &AtomicU8) {
        let _submission = self.submission.lock().unwrap();
        let _ = state.compare_exchange(DISABLED, ENABLED, Ordering::AcqRel, Ordering::Acquire);
        self.changed.notify_waiters();
    }

    fn stop(&self, state: &AtomicU8) {
        let _submission = self.submission.lock().unwrap();
        state.store(STOPPED, Ordering::Release);
        self.changed.notify_waiters();
    }

    /// Disabled waits; permanently stopped returns false. A stopped gate cannot reopen.
    pub async fn receiving(&self) -> bool {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match self.receiving.load(Ordering::Acquire) {
                ENABLED => return true,
                STOPPED => return false,
                _ => changed.await,
            }
        }
    }
}
