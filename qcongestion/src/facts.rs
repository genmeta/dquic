use std::sync::atomic::{AtomicBool, Ordering};

use qbase::role::Role;

/// Connection-wide handshake facts shared by every path's recovery controller.
/// Mutators return true only for the first false-to-true transition.
/// A set fact records the event, independently of its lifecycle callback's completion.
#[derive(Debug)]
pub struct HandshakeFacts {
    role: Role,
    path_selected: AtomicBool,
    has_received_initial: AtomicBool,
    got_handshake_key: AtomicBool,
    has_sent_handshake: AtomicBool,
    has_received_handshake: AtomicBool,
    has_handshake_acked: AtomicBool,
    is_tls_finished: AtomicBool,
    is_handshake_done: AtomicBool,
}

impl HandshakeFacts {
    pub fn with_role(role: Role) -> Self {
        Self {
            role,
            path_selected: AtomicBool::new(false),
            has_received_initial: AtomicBool::new(false),
            got_handshake_key: AtomicBool::new(false),
            has_sent_handshake: AtomicBool::new(false),
            has_received_handshake: AtomicBool::new(false),
            has_handshake_acked: AtomicBool::new(false),
            is_tls_finished: AtomicBool::new(false),
            is_handshake_done: AtomicBool::new(false),
        }
    }

    /// Record selection once, without retaining the selected path's identity.
    pub fn on_path_selected(&self) -> bool {
        !self.path_selected.swap(true, Ordering::AcqRel)
    }

    pub fn has_selected_path(&self) -> bool {
        self.path_selected.load(Ordering::Acquire)
    }

    pub fn on_initial_received(&self) -> bool {
        !self.has_received_initial.swap(true, Ordering::AcqRel)
    }

    pub fn has_received_initial(&self) -> bool {
        self.has_received_initial.load(Ordering::Acquire)
    }

    pub fn install_handshake_key(&self) -> bool {
        !self.got_handshake_key.swap(true, Ordering::AcqRel)
    }

    pub fn on_handshake_sent(&self) -> bool {
        !self.has_sent_handshake.swap(true, Ordering::AcqRel)
    }

    pub fn on_handshake_received(&self) -> bool {
        !self.has_received_handshake.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn on_handshake_acked(&self) -> bool {
        !self.has_handshake_acked.swap(true, Ordering::AcqRel)
    }

    pub fn on_tls_finished(&self) -> bool {
        !self.is_tls_finished.swap(true, Ordering::AcqRel)
    }

    pub fn on_handshake_done(&self) -> bool {
        !self.is_handshake_done.swap(true, Ordering::AcqRel)
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn has_handshake_key(&self) -> bool {
        self.got_handshake_key.load(Ordering::Acquire)
    }

    pub fn has_sent_handshake(&self) -> bool {
        self.has_sent_handshake.load(Ordering::Acquire)
    }

    pub fn has_received_handshake(&self) -> bool {
        self.has_received_handshake.load(Ordering::Acquire)
    }

    pub fn has_handshake_acked(&self) -> bool {
        self.has_handshake_acked.load(Ordering::Acquire)
    }

    pub fn is_initial_done(&self) -> bool {
        match self.role {
            Role::Client => self.has_sent_handshake(),
            Role::Server => self.has_received_handshake(),
        }
    }

    pub fn is_handshake_done(&self) -> bool {
        self.is_handshake_done.load(Ordering::Acquire)
    }
}
