//! Example network owner: scan interfaces once, register sockets, discover and publish addresses.
use std::{net::SocketAddr, sync::Arc, time::Duration};

use futures::future::join_all;
use qbase::net::{
    NatType,
    addr::EndpointAddr,
    route::{Link, Scope},
};
use qprotocol::{ArcAddrBook, Dock, QuicProtocol, StunProtocol, UdpSocket};
use tokio::{sync::OnceCell, task::JoinHandle, time::timeout};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct Network {
    pub endpoints: Vec<EndpointAddr>,
    _sockets: Vec<Arc<Socket>>,
    nat_tasks: Vec<JoinHandle<()>>,
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
    for interface in netdev::get_interfaces()
        .into_iter()
        .filter(|iface| iface.is_up() && iface.is_running() && !iface.is_loopback() && iface.is_physical())
    {
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

    // Publish each discovered outer address without waiting for NAT classification.
    let results = join_all(sockets.into_iter().map(|mut socket| async move {
        let result = timeout(Duration::from_secs(45), socket.discover(relay)).await;
        match result {
            Ok(Ok(endpoint)) => Ok((socket, endpoint)),
            Ok(Err(error)) => Err(error),
            Err(error) => Err(error.into()),
        }
    }))
    .await;
    let mut network = Network { endpoints: Vec::new(), _sockets: Vec::new(), nat_tasks: Vec::new() };
    for result in results {
        match result {
            Ok((socket, endpoint)) => {
                let socket = Arc::new(socket);
                network.nat_tasks.push(socket.classify(relay, endpoint.addr()));
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
        let udp = Arc::new(UdpSocket::bind(addr, interface.index)?);
        Dock::global().add_socket(udp.clone())?;
        let bound = udp.local_addr()?;
        let direct = EndpointAddr::direct(bound);
        let addresses = ArcAddrBook::global();
        addresses.add_sock_addr(bound);
        if matches!(direct.scope(), Some(Scope::Internal | Scope::Loopback)) {
            addresses.add_candidate(Link::new(bound, bound), NatType::FullCone);
        }
        Ok(Self { udp, aliases: vec![direct] })
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
        let outer = stun.detect_outer(bound, relay).await?.ok_or("missing STUN mapping")?;
        let endpoint = EndpointAddr::mediate(relay, outer);
        self.register(outer.into())?;
        self.register(endpoint)?;
        let addresses = ArcAddrBook::global();
        addresses.add_endpoint_addr(bound, outer.into())?;
        addresses.add_endpoint_addr(bound, endpoint)?;
        println!("STUN: interface={}\n  Local:  {bound}\n  Public: {outer}\n  Relay:  {relay}\n", self.udp.ifindex());
        Ok(endpoint)
    }

    fn classify(self: &Arc<Self>, relay: SocketAddr, outer: SocketAddr) -> JoinHandle<()> {
        let owner = Arc::downgrade(self);
        let bound = self.udp.local_addr().unwrap();
        tokio::spawn(async move {
            let result = timeout(Duration::from_secs(45), StunProtocol::global().detect_nat(bound, relay)).await;
            // Upgrade only after probing. Hold the socket owner through candidate insertion,
            // so no late result can add a candidate after del_sock_addr in Socket::drop.
            let Some(socket) = owner.upgrade() else {
                return;
            };
            match result {
                Ok(Ok(nat)) if nat != NatType::Blocked => {
                    ArcAddrBook::global().add_candidate(Link::new(bound, outer), nat);
                    println!("NAT: {bound} -> {outer}: {nat:?}");
                }
                result => eprintln!("NAT classification failed for {bound}: {result:?}"),
            }
            drop(socket);
        })
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        if let Ok(bound) = self.udp.local_addr() {
            ArcAddrBook::global().del_sock_addr(bound);
        }
        Dock::global().remove(&self.udp);
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        for task in &self.nat_tasks {
            task.abort();
        }
    }
}
