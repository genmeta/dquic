//! Discover interfaces externally; Dock owns socket probing and address publication.
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use futures::future::join_all;
use qbase::net::addr::EndpointAddr;
use qprotocol::{ArcAddrBook, Dock, UdpSocket};
use tokio::{sync::OnceCell, time::timeout};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct Network {
    pub endpoints: Vec<EndpointAddr>,
}

/// Both processes use the same relay so the mapped return address matches that relay.
pub async fn start(relay: Option<SocketAddr>) -> Result<&'static Network, Error> {
    static NETWORK: OnceCell<Network> = OnceCell::const_new();
    NETWORK.get_or_try_init(|| scan(relay)).await
}

async fn scan(relay: Option<SocketAddr>) -> Result<Network, Error> {
    // DNS and interface discovery belong to the application, before bootstrap.
    let relay = match relay {
        Some(relay) => relay,
        None => timeout(Duration::from_secs(10), tokio::net::lookup_host("nat.genmeta.net:20002"))
            .await??
            .find(SocketAddr::is_ipv4)
            .ok_or("nat.genmeta.net has no IPv4 address")?,
    };
    let interfaces = netdev::get_interfaces()
        .into_iter()
        .filter(|iface| iface.is_up() && iface.is_running() && !iface.is_loopback() && iface.is_physical())
        .collect::<Vec<_>>();
    let indices = interfaces.iter().flat_map(|iface| iface.ipv4.iter().map(move |ip| (ip.addr(), iface.index))).collect::<HashMap<_, _>>();
    Dock::global().with_socket_factory(Arc::new(move |addr| {
        let ifindex = match addr.ip() {
            std::net::IpAddr::V4(ip) => indices.get(&ip).copied().unwrap_or(0),
            _ => 0,
        };
        UdpSocket::bind(addr, ifindex)
    }));
    Dock::global().bootstrap([relay]);
    let mut sockets = Vec::new();
    for interface in interfaces {
        for ip in &interface.ipv4 {
            match Dock::global().use_socket((ip.addr(), 0).into()) {
                Ok(socket) => sockets.push(socket),
                Err(error) => eprintln!("{}: {error}", interface.name),
            }
        }
    }
    if sockets.is_empty() {
        return Err("no active physical IPv4 interface found".into());
    }

    let results = join_all(sockets.into_iter().map(|socket| async move {
        timeout(Duration::from_secs(45), async {
            loop {
                let peer = EndpointAddr::mediate(relay, relay);
                let endpoint = ArcAddrBook::global().matches(peer).into_iter().find(|endpoint| {
                    matches!(endpoint, EndpointAddr::Mediate { agent, .. } if *agent == relay)
                        && Dock::global()
                            .topology()
                            .quic()
                            .find_socket(*endpoint)
                            .is_some_and(|registered| Arc::ptr_eq(&registered, &socket))
                });
                if let Some(endpoint) = endpoint {
                    println!(
                        "STUN: interface={}\n  Local:  {}\n  Public: {}\n  Relay:  {relay}",
                        socket.ifindex(),
                        socket.local_addr()?,
                        endpoint.addr()
                    );
                    return Ok::<_, std::io::Error>(endpoint);
                }
                if Dock::global().find_socket(socket.local_addr()?).is_none() {
                    return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "UDP reception stopped"));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
    }))
    .await;
    let mut endpoints = Vec::new();
    for result in results {
        match result {
            Ok(Ok(endpoint)) => endpoints.push(endpoint),
            result => eprintln!("STUN discovery failed: {result:?}"),
        }
    }
    let network = Network { endpoints };
    if network.endpoints.is_empty() {
        return Err("no interface completed STUN discovery".into());
    }
    Ok(network)
}
