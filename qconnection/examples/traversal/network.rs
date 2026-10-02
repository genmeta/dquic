//! Example network owner: scan interfaces once, register sockets, discover and publish addresses.
use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use futures::future::join_all;
use qbase::net::{NatType, addr::EndpointAddr};
use qprotocol::{AddressBook, Dock, QuicProtocol, StunProtocol, UdpSocket};
use tokio::{sync::OnceCell, time::timeout};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct Network {
    pub endpoints: Vec<EndpointAddr>,
    _sockets: Vec<Socket>,
}

/// Both processes use the same relay so the mapped return address matches that relay.
/// The server selects a nat.genmeta.net address; the client reads it from the server endpoint.
pub async fn start(relay: Option<SocketAddr>) -> Result<&'static Network, Error> {
    static NETWORK: OnceCell<Network> = OnceCell::const_new();
    NETWORK.get_or_try_init(|| scan(relay)).await
}

async fn scan(relay: Option<SocketAddr>) -> Result<Network, Error> {
    let relay = match relay {
        Some(relay) => relay,
        None => *timeout(Duration::from_secs(10), StunProtocol::stun_servers())
            .await??
            .iter()
            .find(|addr| addr.is_ipv4())
            .ok_or("nat.genmeta.net has no IPv4 address")?,
    };
    let mut sockets = Vec::new();
    for interface in netdev::get_interfaces().into_iter().filter(|iface| {
        iface.is_up() && iface.is_running() && !iface.is_loopback() && iface.is_physical()
    }) {
        for ip in &interface.ipv4 {
            let result = Socket::bind((ip.addr(), 0).into(), &interface);
            match result {
                Ok(socket) => sockets.push(socket),
                Err(error) => eprintln!("{}: {error}", interface.name),
            }
        }
    }
    if sockets.is_empty() {
        return Err("no active physical IPv4 interface found".into());
    }

    // Probe bindings concurrently, but keep each socket idle during its own NAT classification.
    let results = join_all(sockets.into_iter().map(|mut socket| async move {
        let result = timeout(Duration::from_secs(45), socket.discover(relay)).await;
        match result {
            Ok(Ok(endpoint)) => Ok((socket, endpoint)),
            Ok(Err(error)) => Err(error),
            Err(error) => Err(error.into()),
        }
    }))
    .await;
    let mut network = Network {
        endpoints: Vec::new(),
        _sockets: Vec::new(),
    };
    for result in results {
        match result {
            Ok((socket, endpoint)) => {
                network.endpoints.push(endpoint);
                network._sockets.push(socket);
            }
            Err(error) => eprintln!("STUN discovery failed: {error}"),
        }
    }
    if network.endpoints.is_empty() {
        return Err("no interface completed STUN discovery".into());
    }
    Ok(network)
}

struct Socket {
    udp: Arc<UdpSocket>,
    aliases: Vec<EndpointAddr>,
}

impl Socket {
    fn bind(addr: SocketAddr, interface: &netdev::Interface) -> Result<Self, Error> {
        let device = qudp::BoundDevice::new(interface.name.clone(), interface.index)?;
        let udp = Arc::new(UdpSocket::bind_to_device(addr, device)?);
        Dock::global().add(udp.clone())?;
        let direct = udp.local_addr()?.into();
        Ok(Self {
            udp,
            aliases: vec![direct],
        })
    }

    fn register(&mut self, endpoint: EndpointAddr) -> Result<(), Error> {
        if !self.aliases.contains(&endpoint) {
            QuicProtocol::global().register(endpoint, &self.udp)?;
            self.aliases.push(endpoint);
        }
        Ok(())
    }

    async fn discover(&mut self, relay: SocketAddr) -> Result<EndpointAddr, Error> {
        let bound = self.udp.local_addr()?;
        let stun = StunProtocol::global();
        let nat = stun.detect_nat(bound, relay).await?;
        if nat == NatType::Blocked {
            return Err(io::Error::other(format!("{bound}: STUN blocked")).into());
        }
        let outer = stun
            .detect_outer(bound, relay)
            .await?
            .ok_or("missing STUN mapping")?;
        let endpoint = EndpointAddr::mediate(relay, outer);
        self.register(outer.into())?;
        self.register(endpoint)?;
        let addresses = AddressBook::global();
        addresses.insert_inner(&self.udp, bound.into())?;
        if outer != bound {
            addresses.insert_outer(&self.udp, outer.into())?;
        }
        addresses.set_nat(bound, nat);
        println!(
            "STUN: interface={}, NAT={nat:?}\n  Local:  {bound}\n  Public: {outer}\n  Relay:  {relay}\n",
            self.udp.bound_device().unwrap().name()
        );
        Ok(endpoint)
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        if let Ok(bound) = self.udp.local_addr() {
            AddressBook::global().remove_bound(bound);
        }
        Dock::global().remove(&self.udp);
    }
}
