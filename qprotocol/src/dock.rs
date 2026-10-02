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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AddressBook,
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

        assert!(dock.add(socket.clone()).unwrap().is_some());
        assert!(dock.add(socket.clone()).unwrap().is_none());
        assert_eq!(dock.len(), 1);
        assert!(dock.remove(&socket));
        assert!(dock.is_empty());
    }

    #[tokio::test]
    async fn concurrent_adds_register_one_receiver() {
        let dock = isolated_dock();
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
        assert_eq!(
            results.into_iter().filter(|added| added.is_some()).count(),
            1
        );
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
        let old = dock.add(socket.clone()).unwrap().unwrap();
        assert!(dock.remove(&socket));
        let current = dock.add(socket.clone()).unwrap().unwrap();
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

    fn isolated_dock() -> Arc<Dock> {
        Dock::new(Arc::new(Topology::new(
            Arc::new(StunProtocol::new()),
            Arc::new(ForwardProtocol::new()),
            Arc::new(QuicProtocol::new()),
        )))
    }

    #[tokio::test]
    async fn socket_registration_and_removal_leave_publication_to_the_address_book() {
        let dock = isolated_dock();
        let addresses = AddressBook::global();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let bound = socket.local_addr().unwrap();
        let direct = EndpointAddr::direct(bound);
        let outer = EndpointAddr::direct("8.8.8.8:4567".parse().unwrap());
        let relay = EndpointAddr::mediate("8.8.4.4:3478".parse().unwrap(), outer.addr());
        let mut events = addresses.subscribe_punch(qbase::net::route::Scopes::ALL);
        dock.add(socket.clone()).unwrap().unwrap();
        assert!(addresses.mdns_endpoints(bound).is_empty());
        addresses.insert_inner(&socket, direct).unwrap();
        assert_eq!(addresses.mdns_endpoints(bound).as_ref(), &[direct]);
        assert!(
            matches!(events.try_recv().unwrap(), crate::AddressEvent::Added { endpoint, .. } if endpoint == direct)
        );
        dock.topology.quic().register(outer, &socket).unwrap();
        dock.topology.quic().register(relay, &socket).unwrap();
        addresses.insert_outer(&socket, outer).unwrap();
        addresses.set_nat(bound, qbase::net::NatType::RestrictedCone);

        let other = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        dock.add(other.clone()).unwrap().unwrap();
        assert!(dock.remove_bound(bound));
        for alias in [direct, outer, relay] {
            assert!(dock.topology.quic().find_socket(alias).is_none());
        }
        assert_eq!(addresses.mdns_endpoints(bound).as_ref(), &[direct]);
        assert!(addresses.ddns_endpoints().contains(&outer));
        assert_eq!(
            addresses.nat(bound),
            Some(qbase::net::NatType::RestrictedCone)
        );
        assert!(Arc::ptr_eq(
            &dock.find_socket(other.local_addr().unwrap()).unwrap(),
            &other
        ));
        let error = dock
            .topology
            .stun()
            .detect_outer(bound, other.local_addr().unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(error, crate::protocol::stun::StunError::Io(error) if error.kind() == io::ErrorKind::NotFound)
        );
        addresses.remove_bound(bound);
        assert!(addresses.mdns_endpoints(bound).is_empty());
        assert!(!addresses.ddns_endpoints().contains(&outer));
        assert_eq!(addresses.nat(bound), None);
        let mut removed = false;
        while let Ok(event) = events.try_recv() {
            removed |= matches!(event, crate::AddressEvent::BoundRemoved { bound: candidate } if candidate == bound);
        }
        assert!(
            removed,
            "punch subscriptions must learn that the binding was removed"
        );
    }

    #[tokio::test]
    async fn failed_quic_registration_rolls_back_stun_and_preserves_the_existing_alias() {
        let dock = isolated_dock();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let bound = socket.local_addr().unwrap();
        let direct = EndpointAddr::direct(bound);
        let existing = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        dock.topology.quic().register(direct, &existing).unwrap();
        assert!(dock.add(socket.clone()).is_err());
        assert!(dock.is_empty());
        assert!(Arc::ptr_eq(
            &dock.topology.quic().find_socket(direct).unwrap(),
            &existing
        ));
        let error = dock
            .topology
            .stun()
            .detect_outer(bound, "127.0.0.1:9".parse().unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(error, crate::protocol::stun::StunError::Io(error) if error.kind() == io::ErrorKind::NotFound)
        );
        dock.topology
            .quic()
            .unregister(existing.local_addr().unwrap());
        assert!(dock.add(socket).unwrap().is_some());
    }

    #[tokio::test]
    async fn shutdown_and_drop_revoke_aliases_with_live_socket_handles() {
        for shutdown in [true, false] {
            let dock = isolated_dock();
            let topology = dock.topology.clone();
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
            let bound = socket.local_addr().unwrap();
            let direct = EndpointAddr::direct(bound);
            let handle = dock.add(socket.clone()).unwrap().unwrap();
            if shutdown {
                dock.shutdown();
            }
            drop(dock);
            assert!(topology.quic().find_socket(direct).is_none());
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while !handle.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn receive_task_exit_removes_the_registration_and_protocol_aliases() {
        use qbase::{datagram::forward::Payload, net::route::Pathway};
        let dock = isolated_dock();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let bound = socket.local_addr().unwrap();
        let direct = EndpointAddr::direct(bound);
        dock.add(socket.clone()).unwrap().unwrap();
        dock.topology.forward().serve(bound, &socket);
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Forwarding to an IPv6 destination from an IPv4 socket fails in the receive loop.
        let pathway: Pathway = Pathway::new(
            "[::1]:12345".parse::<SocketAddr>().unwrap().into(),
            "[::1]:9".parse::<SocketAddr>().unwrap().into(),
        );
        let offset = 2 + pathway.local().encoding_size() + pathway.remote().encoding_size();
        let mut bytes = bytes::BytesMut::zeroed(offset + 1);
        bytes[offset] = 0x40;
        let packet = Payload::from_raw(&pathway, bytes, offset).unwrap();
        peer.send_to(packet.as_ref(), bound).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !dock.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(dock.topology.quic().find_socket(direct).is_none());
        assert_eq!(socket.local_addr().unwrap(), bound);
    }
}
