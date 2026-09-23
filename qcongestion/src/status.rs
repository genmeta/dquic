use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU16, Ordering},
};

#[derive(Debug)]
pub struct HandshakeStatus {
    is_server: AtomicBool,
    has_handshake_key: AtomicBool,
    has_received_handshake_ack: AtomicBool,
    is_handshake_confirmed: AtomicBool,
}

impl HandshakeStatus {
    pub fn new(is_server: bool) -> Self {
        Self {
            is_server: AtomicBool::new(is_server),
            has_handshake_key: AtomicBool::new(false),
            has_received_handshake_ack: AtomicBool::new(false),
            is_handshake_confirmed: AtomicBool::new(false),
        }
    }
}

impl HandshakeStatus {
    pub fn got_handshake_key(&self) {
        self.has_handshake_key.store(true, Ordering::Relaxed);
    }

    pub fn received_handshake_ack(&self) {
        self.has_received_handshake_ack
            .store(true, Ordering::Relaxed);
    }

    pub fn handshake_confirmed(&self) {
        self.is_handshake_confirmed.store(true, Ordering::Relaxed);
    }

    pub fn is_handshake_confirmed(&self) -> bool {
        self.is_handshake_confirmed.load(Ordering::Relaxed)
    }
}

#[derive(Clone)]
pub struct PathStatus {
    handshake: Arc<HandshakeStatus>,
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

    pub(crate) fn is_server(&self) -> bool {
        self.handshake.is_server.load(Ordering::Relaxed)
    }

    pub(crate) fn has_handshake_key(&self) -> bool {
        self.handshake.has_handshake_key.load(Ordering::Relaxed)
    }

    pub(crate) fn has_received_handshake_ack(&self) -> bool {
        self.handshake
            .has_received_handshake_ack
            .load(Ordering::Relaxed)
    }

    pub(crate) fn is_handshake_confirmed(&self) -> bool {
        self.handshake
            .is_handshake_confirmed
            .load(Ordering::Relaxed)
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
