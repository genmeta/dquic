use std::{
    io,
    net::SocketAddr,
    sync::{Arc, OnceLock, Weak},
};

use dashmap::{DashMap, mapref::entry::Entry};
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
    /// Process-wide socket dock and its single protocol topology.
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

    pub fn add(self: &Arc<Self>, socket: Arc<UdpSocket>) -> io::Result<bool> {
        self.register(socket)
            .map(|registration| registration.is_some())
    }

    /// Return a handle so the owner can revoke this registration. Keeping the
    /// handle alive prevents reuse of its task ID after reception has stopped.
    pub(crate) fn register(
        self: &Arc<Self>,
        socket: Arc<UdpSocket>,
    ) -> io::Result<Option<AbortHandle>> {
        let bound = socket.local_addr()?;
        // Hold the entry until the socket and task are installed together. A task
        // that finishes immediately must wait for this registration before cleanup.
        let entry = self.sockets.entry(bound);
        if let Entry::Occupied(existing) = &entry {
            let registration = existing.get();
            if registration.socket.upgrade().is_some() {
                return Ok(None);
            }
            self.topology
                .stun()
                .unregister_socket(bound, &registration.socket);
            registration.task.abort();
        }

        self.topology.stun().register_socket(bound, &socket);
        let registered = Arc::downgrade(&socket);
        let dock = Arc::downgrade(self);
        let topology = self.topology.clone();
        let task = tokio::spawn(async move {
            let _ = topology.receive(socket).await;
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
                // Unregister while holding the entry: the same socket may be added
                // again, so pointer identity alone cannot protect the new STUN entry.
                self.topology
                    .stun()
                    .unregister_socket(bound, &registration.socket);
                registration.task.abort();
                true
            })
            .is_some()
    }

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
        for socket in self.sockets.iter() {
            self.topology
                .stun()
                .unregister_socket(*socket.key(), &socket.socket);
            socket.task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::{forward::ForwardProtocol, quic::QuicProtocol, stun::StunProtocol},
        topology::Topology,
    };

    #[tokio::test]
    async fn one_socket_starts_one_task() {
        let quic = Arc::new(QuicProtocol::new());
        let topology = Arc::new(Topology::new(
            Arc::new(StunProtocol::new()),
            Arc::new(ForwardProtocol::new()),
            quic,
        ));
        let dock = Dock::new(topology);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());

        assert!(dock.add(socket.clone()).unwrap());
        assert!(!dock.add(socket.clone()).unwrap());
        assert_eq!(dock.len(), 1);
        assert!(dock.remove(&socket));
        assert!(dock.is_empty());
    }

    #[tokio::test]
    async fn concurrent_adds_register_one_receiver() {
        let dock = Dock::new(Arc::new(Topology::new(
            Arc::new(StunProtocol::new()),
            Arc::new(ForwardProtocol::new()),
            Arc::new(QuicProtocol::new()),
        )));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let barrier = std::sync::Barrier::new(2);
        let runtime = tokio::runtime::Handle::current();
        let results = std::thread::scope(|scope| {
            let workers = (0..2)
                .map(|_| {
                    scope.spawn(|| {
                        let _runtime = runtime.enter();
                        barrier.wait();
                        dock.add(socket.clone()).unwrap()
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.into_iter().filter(|added| *added).count(), 1);
        assert_eq!(dock.len(), 1);
        assert!(dock.remove(&socket));
    }

    #[tokio::test]
    async fn old_receiver_cleanup_preserves_a_new_registration_of_the_same_socket() {
        let stun = Arc::new(StunProtocol::new());
        let dock = Dock::new(Arc::new(Topology::new(
            stun.clone(),
            Arc::new(ForwardProtocol::new()),
            Arc::new(QuicProtocol::new()),
        )));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let bound = socket.local_addr().unwrap();
        let old = dock.register(socket.clone()).unwrap().unwrap();
        assert!(dock.remove(&socket));
        let current = dock.register(socket.clone()).unwrap().unwrap();
        assert_ne!(old.id(), current.id());

        // The first receive task finishes after this socket was registered again.
        assert!(!dock.remove_registration(bound, old.id()));
        assert!(Arc::ptr_eq(&dock.find_socket(bound).unwrap(), &socket));
        assert!(!dock.sockets.get(&bound).unwrap().task.is_finished());
        stun.set_change_server(
            bound,
            crate::protocol::stun::ChangeServer {
                outer_address: bound,
                change_port: bound.port() ^ 1,
                change_address: SocketAddr::from(([127, 0, 0, 2], bound.port() ^ 1)),
            },
        )
        .unwrap();
        assert!(dock.remove_registration(bound, current.id()));
        assert!(dock.is_empty());
    }
}
