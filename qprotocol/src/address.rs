use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use qbase::net::addr::{EndpointAddr, Kind};
use thiserror::Error;
use tokio::sync::watch;

use crate::{UdpSocket, quic::QuicSocket};

#[derive(Debug, Error)]
pub enum AddressBookError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0} is already present in the address book")]
    Duplicate(EndpointAddr),
    #[error("expected a Direct endpoint")]
    ExpectedDirect,
    #[error("expected an Agent endpoint")]
    ExpectedMediate,
    #[error("a raw UDP socket can publish at most three Agent endpoints")]
    TooManyAgents,
}

#[derive(Default)]
struct Addresses {
    inner: HashMap<EndpointAddr, Arc<QuicSocket>>,
    outer: HashMap<EndpointAddr, Arc<QuicSocket>>,
    agents: HashMap<EndpointAddr, Arc<QuicSocket>>,
}

pub struct AddressBook {
    addresses: RwLock<Addresses>,
    ddns: watch::Sender<Arc<[EndpointAddr]>>,
    mdns: RwLock<HashMap<SocketAddr, watch::Sender<Arc<[EndpointAddr]>>>>,
}

impl Default for AddressBook {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressBook {
    pub fn new() -> Self {
        let (ddns, _) = watch::channel(Arc::from([]));
        Self {
            addresses: RwLock::new(Addresses::default()),
            ddns,
            mdns: RwLock::new(HashMap::new()),
        }
    }

    pub fn insert_inner(&self, socket: Arc<QuicSocket>) -> Result<(), AddressBookError> {
        ensure_direct(socket.endpoint_addr())?;
        let bound = socket.udp_socket().local_addr()?;
        self.insert(socket, |addresses| &mut addresses.inner)?;
        self.publish_mdns(bound);
        Ok(())
    }

    pub fn insert_outer(&self, socket: Arc<QuicSocket>) -> Result<(), AddressBookError> {
        ensure_direct(socket.endpoint_addr())?;
        self.insert(socket, |addresses| &mut addresses.outer)?;
        self.publish_ddns();
        Ok(())
    }

    pub fn insert_agent(&self, socket: Arc<QuicSocket>) -> Result<(), AddressBookError> {
        if socket.endpoint_addr().kind() != Kind::Mediate {
            return Err(AddressBookError::ExpectedMediate);
        }

        let mut addresses = self.addresses.write().unwrap();
        self.ensure_absent(&addresses, socket.endpoint_addr())?;
        let agent_count = addresses
            .agents
            .values()
            .filter(|candidate| Arc::ptr_eq(candidate.udp_socket(), socket.udp_socket()))
            .count();
        if agent_count >= 3 {
            return Err(AddressBookError::TooManyAgents);
        }
        addresses.agents.insert(socket.endpoint_addr(), socket);
        drop(addresses);
        self.publish_ddns();
        Ok(())
    }

    pub fn remove_socket(&self, socket: &UdpSocket) {
        let mut addresses = self.addresses.write().unwrap();
        addresses
            .inner
            .retain(|_, candidate| !std::ptr::eq(candidate.udp_socket().as_ref(), socket));
        addresses
            .outer
            .retain(|_, candidate| !std::ptr::eq(candidate.udp_socket().as_ref(), socket));
        addresses
            .agents
            .retain(|_, candidate| !std::ptr::eq(candidate.udp_socket().as_ref(), socket));
        drop(addresses);
        self.publish_ddns();
        self.publish_all_mdns();
    }

    pub fn subscribe_ddns(&self) -> watch::Receiver<Arc<[EndpointAddr]>> {
        self.ddns.subscribe()
    }

    pub fn subscribe_mdns(&self, bound: SocketAddr) -> watch::Receiver<Arc<[EndpointAddr]>> {
        if let Some(sender) = self.mdns.read().unwrap().get(&bound) {
            return sender.subscribe();
        }

        let snapshot = self.mdns_snapshot(bound);
        let mut publishers = self.mdns.write().unwrap();
        publishers
            .entry(bound)
            .or_insert_with(|| watch::channel(snapshot).0)
            .subscribe()
    }

    pub fn ddns_endpoints(&self) -> Arc<[EndpointAddr]> {
        self.ddns_snapshot()
    }

    pub fn mdns_endpoints(&self, bound: SocketAddr) -> Arc<[EndpointAddr]> {
        self.mdns_snapshot(bound)
    }

    fn insert(
        &self,
        socket: Arc<QuicSocket>,
        select: impl FnOnce(&mut Addresses) -> &mut HashMap<EndpointAddr, Arc<QuicSocket>>,
    ) -> Result<(), AddressBookError> {
        let mut addresses = self.addresses.write().unwrap();
        self.ensure_absent(&addresses, socket.endpoint_addr())?;
        select(&mut addresses).insert(socket.endpoint_addr(), socket);
        Ok(())
    }

    fn ensure_absent(
        &self,
        addresses: &Addresses,
        endpoint: EndpointAddr,
    ) -> Result<(), AddressBookError> {
        if addresses.inner.contains_key(&endpoint)
            || addresses.outer.contains_key(&endpoint)
            || addresses.agents.contains_key(&endpoint)
        {
            return Err(AddressBookError::Duplicate(endpoint));
        }
        Ok(())
    }

    fn publish_ddns(&self) {
        self.ddns.send_replace(self.ddns_snapshot());
    }

    fn publish_mdns(&self, bound: SocketAddr) {
        let snapshot = self.mdns_snapshot(bound);
        if let Some(sender) = self.mdns.read().unwrap().get(&bound) {
            sender.send_replace(snapshot);
        }
    }

    fn publish_all_mdns(&self) {
        let bounds = self
            .mdns
            .read()
            .unwrap()
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for bound in bounds {
            self.publish_mdns(bound);
        }
    }

    fn ddns_snapshot(&self) -> Arc<[EndpointAddr]> {
        let addresses = self.addresses.read().unwrap();
        let mut endpoints = addresses
            .outer
            .keys()
            .chain(addresses.agents.keys())
            .copied()
            .collect::<Vec<_>>();
        endpoints.sort_unstable();
        endpoints.into()
    }

    fn mdns_snapshot(&self, bound: SocketAddr) -> Arc<[EndpointAddr]> {
        let addresses = self.addresses.read().unwrap();
        let mut endpoints = addresses
            .inner
            .iter()
            .filter_map(|(endpoint, socket)| {
                (socket.udp_socket().local_addr().ok() == Some(bound)).then_some(*endpoint)
            })
            .collect::<Vec<_>>();
        endpoints.sort_unstable();
        endpoints.into()
    }
}

fn ensure_direct(endpoint: EndpointAddr) -> Result<(), AddressBookError> {
    if matches!(endpoint, EndpointAddr::Direct { .. }) {
        Ok(())
    } else {
        Err(AddressBookError::ExpectedDirect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publishes_inner_to_mdns_and_outer_agent_to_ddns() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let bound = raw.local_addr().unwrap();
        let inner = Arc::new(QuicSocket::new(raw.clone(), EndpointAddr::direct(bound)));
        let outer = Arc::new(QuicSocket::new(
            raw.clone(),
            EndpointAddr::direct("203.0.113.10:50000".parse().unwrap()),
        ));
        let agent = Arc::new(QuicSocket::new(
            raw.clone(),
            EndpointAddr::mediate(
                "198.51.100.1:3478".parse().unwrap(),
                "203.0.113.10:50000".parse().unwrap(),
            ),
        ));
        let book = AddressBook::new();

        book.insert_inner(inner.clone()).unwrap();
        book.insert_outer(outer.clone()).unwrap();
        book.insert_agent(agent.clone()).unwrap();

        assert_eq!(
            book.mdns_endpoints(bound).as_ref(),
            &[inner.endpoint_addr()]
        );
        assert_eq!(
            book.ddns_endpoints().as_ref(),
            &[outer.endpoint_addr(), agent.endpoint_addr()]
        );

        book.remove_socket(&raw);
        assert!(book.mdns_endpoints(bound).is_empty());
        assert!(book.ddns_endpoints().is_empty());
    }
}
