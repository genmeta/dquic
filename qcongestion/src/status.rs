use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU16, Ordering},
};

/// Connection-wide handshake facts shared by every path's recovery controller.
#[derive(Debug)]
pub struct HandshakeStatus {
    pub(crate) is_server: bool,
    pub(crate) has_handshake_key: AtomicBool,
    pub(crate) has_sent_handshake: AtomicBool,
    pub(crate) has_received_handshake: AtomicBool,
    pub(crate) has_received_handshake_ack: AtomicBool,
    is_handshake_confirmed: AtomicBool,
}

impl HandshakeStatus {
    pub fn new(is_server: bool) -> Self {
        Self {
            is_server,
            has_handshake_key: AtomicBool::new(false),
            has_sent_handshake: AtomicBool::new(false),
            has_received_handshake: AtomicBool::new(false),
            has_received_handshake_ack: AtomicBool::new(false),
            is_handshake_confirmed: AtomicBool::new(false),
        }
    }

    pub fn got_handshake_key(&self) {
        self.has_handshake_key.store(true, Ordering::Release);
    }

    pub(crate) fn received_handshake_ack(&self) {
        self.has_received_handshake_ack
            .store(true, Ordering::Release);
    }

    pub fn handshake_confirmed(&self) {
        self.is_handshake_confirmed.store(true, Ordering::Release);
    }

    pub fn on_handshake_sent(&self) {
        self.has_sent_handshake.store(true, Ordering::Release);
    }

    pub fn on_handshake_received(&self) {
        self.has_received_handshake.store(true, Ordering::Release);
    }

    pub fn is_handshake_confirmed(&self) -> bool {
        self.is_handshake_confirmed.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
pub struct PathStatus {
    pub(crate) handshake: Arc<HandshakeStatus>,
    is_at_anti_amplification_limit: Arc<AtomicBool>,
    pmtu: Arc<AtomicU16>,
}

impl PathStatus {
    pub fn new(handshake: Arc<HandshakeStatus>, pmut: Arc<AtomicU16>) -> Self {
        Self {
            handshake,
            is_at_anti_amplification_limit: Arc::new(AtomicBool::new(true)),
            pmtu: pmut,
        }
    }

    pub(crate) fn is_at_anti_amplification_limit(&self) -> bool {
        self.is_at_anti_amplification_limit.load(Ordering::Relaxed)
    }

    pub fn release_anti_amplification_limit(&self) {
        self.is_at_anti_amplification_limit
            .store(false, Ordering::Release);
    }

    pub fn enter_anti_amplification_limit(&self) {
        self.is_at_anti_amplification_limit
            .store(true, Ordering::Release);
    }

    pub(super) fn pmtu(&self) -> Arc<AtomicU16> {
        self.pmtu.clone()
    }

    pub(crate) fn mtu(&self) -> usize {
        self.pmtu.load(Ordering::Relaxed) as usize
    }
}
