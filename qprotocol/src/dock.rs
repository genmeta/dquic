use std::{
    io,
    net::SocketAddr,
    sync::{Arc, OnceLock, Weak},
};

use dashmap::{DashMap, mapref::entry::Entry};
use qbase::net::addr::EndpointAddr;
use tokio::task::{AbortHandle, Id, JoinHandle};

use crate::{socket::UdpSocket, topology::Topology};

struct SocketRegistration {
    socket: Weak<UdpSocket>,
    task: JoinHandle<()>,
}

pub struct Dock {
    sockets: DashMap<SocketAddr, SocketRegistration>,
    topology: Arc<Topology>,
}

impl Dock {
    /// Process-wide socket dock and its protocol topology.
    /// First initialization starts STUN DNS and requires a Tokio runtime.
    pub fn global() -> &'static Arc<Self> {
        static DOCK: OnceLock<Arc<Dock>> = OnceLock::new();
        DOCK.get_or_init(|| {
            Self::new(Arc::new(Topology::new(
                crate::StunProtocol::global().clone(),
                Arc::new(crate::ForwardProtocol::new()),
                Arc::new(crate::QuicProtocol::new()),
            )))
        })
    }

    pub fn new(topology: Arc<Topology>) -> Arc<Self> {
        Arc::new(Self {
            sockets: DashMap::new(),
            topology,
        })
    }

    pub fn topology(&self) -> &Arc<Topology> {
        &self.topology
    }

    /// Register reception and the direct QUIC address.
    /// The caller manages publication and withdrawal through [`crate::AddressBook`].
    /// The handle identifies this registration even after reception has stopped.
    pub fn add(self: &Arc<Self>, socket: Arc<UdpSocket>) -> io::Result<Option<AbortHandle>> {
        let bound = socket.local_addr()?;
        // Keep protocol registration and receiver installation under one entry
        // lock so immediate receiver failure cannot leave a partially added socket.
        let entry = self.sockets.entry(bound);
        if let Entry::Occupied(existing) = &entry {
            let registration = existing.get();
            if registration.socket.upgrade().is_some() {
                return Ok(None);
            }
            self.cleanup(bound, registration);
        }

        let registered = Arc::downgrade(&socket);
        self.topology.stun().register_socket(bound, &socket);
        let direct = EndpointAddr::direct(bound);
        if let Err(error) = self.topology.quic().register(direct, &socket) {
            self.topology.stun().unregister_socket(bound, &registered);
            if let Entry::Occupied(entry) = entry {
                entry.remove();
            }
            return Err(io::Error::new(io::ErrorKind::AddrInUse, error));
        }
        let dock = Arc::downgrade(self);
        let topology = self.topology.clone();
        let task = tokio::spawn(async move {
            // Retain the socket through cleanup so every QUIC alias can be revoked.
            if let Err(error) = topology.receive(socket.clone()).await {
                tracing::warn!(%bound, %error, "UDP reception stopped");
            }
            if let Some(dock) = dock.upgrade() {
                dock.remove_registration(bound, tokio::task::id());
            }
        });
        let handle = task.abort_handle();
        let registration = SocketRegistration {
            socket: registered,
            task,
        };
        match entry {
            Entry::Occupied(mut entry) => {
                entry.insert(registration);
            }
            Entry::Vacant(entry) => {
                entry.insert(registration);
            }
        }
        Ok(Some(handle))
    }

    /// Remove only the registration belonging to this socket.
    pub fn remove(&self, socket: &UdpSocket) -> bool {
        let Ok(bound) = socket.local_addr() else {
            return false;
        };
        let Some(registration) = self.sockets.get(&bound) else {
            return false;
        };
        if !std::ptr::eq(registration.socket.as_ptr(), socket) {
            return false;
        }
        let handle = registration.task.abort_handle();
        drop(registration);
        self.remove_registration(bound, handle.id())
    }

    pub fn remove_bound(&self, bound: SocketAddr) -> bool {
        let Some(handle) = self
            .sockets
            .get(&bound)
            .map(|registration| registration.task.abort_handle())
        else {
            return false;
        };
        self.remove_registration(bound, handle.id())
    }

    pub(crate) fn remove_registration(&self, bound: SocketAddr, id: Id) -> bool {
        self.sockets
            .remove_if(&bound, |_, registration| {
                if registration.task.id() != id {
                    return false;
                }
                // Hold the entry through cleanup: an old receiver must not revoke a
                // newer registration, even when it uses the same socket instance.
                self.cleanup(bound, registration);
                true
            })
            .is_some()
    }

    fn cleanup(&self, bound: SocketAddr, registration: &SocketRegistration) {
        self.topology.quic().unregister(bound);
        self.topology
            .stun()
            .unregister_socket(bound, &registration.socket);
        registration.task.abort();
    }

    /// Find the registered socket for a local binding.
    pub fn find_socket(&self, bound: SocketAddr) -> Option<Arc<UdpSocket>> {
        let registration = self.sockets.get(&bound)?;
        let socket = registration.socket.upgrade();
        let handle = registration.task.abort_handle();
        drop(registration);
        if socket.is_none() {
            self.remove_registration(bound, handle.id());
        }
        socket
    }

    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }

    pub fn shutdown(&self) {
        let tasks = self
            .sockets
            .iter()
            .map(|entry| (*entry.key(), entry.task.abort_handle()))
            .collect::<Vec<_>>();
        for (bound, handle) in tasks {
            self.remove_registration(bound, handle.id());
        }
    }
}

impl Drop for Dock {
    fn drop(&mut self) {
        self.shutdown();
    }
}
