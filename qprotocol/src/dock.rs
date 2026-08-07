use std::{io, net::SocketAddr, sync::Arc};

use dashmap::DashMap;
use tokio::task::JoinHandle;

use crate::{socket::UdpSocket, topology::Topology};

pub struct Dock {
    sockets: DashMap<SocketAddr, std::sync::Weak<UdpSocket>>,
    tasks: DashMap<SocketAddr, JoinHandle<()>>,
    topology: Arc<Topology>,
}

impl Dock {
    pub fn new(topology: Arc<Topology>) -> Arc<Self> {
        Arc::new(Self {
            sockets: DashMap::new(),
            tasks: DashMap::new(),
            topology,
        })
    }

    pub fn topology(&self) -> &Arc<Topology> {
        &self.topology
    }

    pub fn add(self: &Arc<Self>, socket: Arc<UdpSocket>) -> io::Result<bool> {
        let bound = socket.local_addr()?;
        if self.socket(bound).is_some() {
            return Ok(false);
        }

        self.sockets.insert(bound, Arc::downgrade(&socket));
        let dock = Arc::downgrade(self);
        let topology = self.topology.clone();
        let task = tokio::spawn(async move {
            let _ = topology.receive(socket).await;
            if let Some(dock) = dock.upgrade() {
                dock.sockets.remove(&bound);
                dock.tasks.remove(&bound);
            }
        });
        if let Some(old) = self.tasks.insert(bound, task) {
            old.abort();
        }
        Ok(true)
    }

    pub fn remove(&self, socket: &UdpSocket) -> bool {
        socket
            .local_addr()
            .ok()
            .is_some_and(|bound| self.remove_bound(bound))
    }

    pub fn remove_bound(&self, bound: SocketAddr) -> bool {
        self.sockets.remove(&bound);
        self.tasks.remove(&bound).is_some_and(|(_, task)| {
            task.abort();
            true
        })
    }

    pub fn socket(&self, bound: SocketAddr) -> Option<Arc<UdpSocket>> {
        let socket = self.sockets.get(&bound)?.upgrade();
        if socket.is_none() {
            self.sockets.remove(&bound);
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
            .tasks
            .iter()
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        for bound in tasks {
            self.remove_bound(bound);
        }
    }
}

impl Drop for Dock {
    fn drop(&mut self) {
        for task in self.tasks.iter() {
            task.abort();
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
            Arc::new(ForwardProtocol::new(quic.clone())),
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
}
