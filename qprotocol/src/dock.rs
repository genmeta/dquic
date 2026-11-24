use std::{
    io,
    net::SocketAddr,
    sync::{Arc, OnceLock, RwLock, Weak},
    time::Duration,
};

use dashmap::{DashMap, mapref::entry::Entry};
use futures::future::{AbortHandle, Abortable};
use qbase::net::{
    AddrFamily, NatType,
    addr::EndpointAddr,
    route::{Link, Scope},
};
use tokio::time::{Instant, MissedTickBehavior, interval_at, timeout};

use crate::{
    ArcAddrBook, EphemeralSocket, UdpSocket,
    protocol::stun::{Request, StunError},
    topology::Topology,
};

type CreateSocket = dyn Fn(SocketAddr) -> io::Result<UdpSocket> + Send + Sync + 'static;
type CloseSocket = dyn Fn(SocketAddr) + Send + Sync + 'static;

/// Manages socket reception independently of interface discovery.
pub struct Dock {
    sockets: Arc<DashMap<SocketAddr, Weak<UdpSocket>>>,
    factory: RwLock<Arc<CreateSocket>>,
    recycle: Arc<RwLock<Arc<CloseSocket>>>,
    topology: Arc<Topology>,
}

impl Dock {
    /// Process-wide dock and its protocol topology.
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
            sockets: Arc::new(DashMap::new()),
            factory: RwLock::new(Arc::new(|addr| UdpSocket::bind(addr, 0))),
            recycle: Arc::new(RwLock::new(Arc::new(|_| {}))),
            topology,
        })
    }

    /// Configure remote STUN nodes before creating permanent sockets.
    /// The first node matching the socket's family is its agent. NAT discovery
    /// follows that agent's changed-address chain to the auxiliary servers.
    pub fn bootstrap(&self, nodes: impl IntoIterator<Item = SocketAddr>) {
        self.topology.stun().set_servers(nodes);
    }

    /// Replace the factory for future sockets. Interface selection belongs to the caller.
    pub fn with_socket_factory(&self, factory: Arc<CreateSocket>) {
        *self.factory.write().unwrap() = factory;
    }

    /// Called after a regular socket's reception exits, with its actual bound address.
    /// Temporary sockets do not invoke this callback.
    /// No Dock locks are held while the callback runs.
    pub fn on_socket_closed(&self, callback: Arc<CloseSocket>) {
        *self.recycle.write().unwrap() = callback;
    }

    pub fn topology(&self) -> &Arc<Topology> {
        &self.topology
    }

    /// Create a permanent socket, publish its local endpoint, and start STUN discovery and keepalive.
    /// Both public and private bindings retain Direct and add Mediate after mapping discovery.
    /// The mediated route is retained independently of the measured NAT type.
    /// The default factory binds with interface index zero. Reception retains the
    /// socket until it exits; dropping the returned Arc does not stop reception.
    pub fn use_socket(self: &Arc<Self>, addr: SocketAddr) -> io::Result<Arc<UdpSocket>> {
        self.create_socket(addr, true).map(|(socket, _)| socket)
    }

    /// Create a temporary socket. Dropping its owner requests reception to stop;
    /// the receive task then unregisters and releases it without a close callback.
    pub fn ephemeral_socket(self: &Arc<Self>, addr: SocketAddr) -> io::Result<EphemeralSocket> {
        let (udp, reception) = self.create_socket(addr, false)?;
        Ok(EphemeralSocket { socket: udp, reception })
    }

    fn create_socket(self: &Arc<Self>, addr: SocketAddr, permanent: bool) -> io::Result<(Arc<UdpSocket>, AbortHandle)> {
        let factory = self.factory.read().unwrap().clone();
        let socket = Arc::new(factory(addr)?);
        let sock_addr = socket.local_addr()?;
        let entry = self.sockets.entry(sock_addr);
        if let Entry::Occupied(entry) = &entry
            && entry.get().upgrade().is_some()
        {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, "socket address is already registered in Dock"));
        }
        self.topology
            .quic()
            .register(EndpointAddr::direct(sock_addr), &socket)
            .map_err(|error| io::Error::new(io::ErrorKind::AddrInUse, error))?;
        let registered = Arc::downgrade(&socket);
        self.topology.stun().register_socket(sock_addr, &socket);
        entry.insert(registered.clone());
        let addresses = ArcAddrBook::global().clone();
        if permanent {
            addresses.add_sock_addr(sock_addr);
            if matches!(EndpointAddr::direct(sock_addr).scope(), Some(Scope::Internal | Scope::Loopback)) {
                addresses.add_candidate(Link::new(sock_addr, sock_addr), NatType::FullCone);
            }
        }

        let (close, reception) = AbortHandle::new_pair();
        let sockets = self.sockets.clone();
        let recycle = self.recycle.clone();
        let topology = self.topology.clone();
        let receiving = socket.clone();
        let nodes = topology.stun().stun_servers();
        tokio::spawn(async move {
            let directed = EndpointAddr::direct(sock_addr);
            let mut endpoint = directed;
            let result = {
                let receive = Abortable::new(topology.receive(receiving.clone()), reception);
                tokio::pin!(receive);
                let discovery = async {
                    if permanent && !sock_addr.ip().is_unspecified() {
                        discover(&topology, &addresses, &receiving, &nodes, &mut endpoint).await?;
                    }
                    Ok::<(), io::Error>(())
                };
                // Dropping discovery before withdrawal prevents late probe results
                // from publishing endpoints or candidates for a closed socket.
                tokio::select! {
                    result = &mut receive => result,
                    result = discovery => match result {
                        Ok(()) => receive.await,
                        Err(error) => Ok(Err(error)),
                    },
                }
            };
            if let Ok(Err(error)) = result {
                tracing::error!(%sock_addr, %error, "UDP socket stopped");
            }
            if permanent {
                addresses.del_sock_addr(sock_addr);
            }
            topology.quic().unregister(endpoint, &receiving);
            if endpoint != directed {
                topology.quic().unregister(directed, &receiving);
            }
            topology.stun().unregister_socket(sock_addr, &registered);
            sockets.remove(&sock_addr);
            drop(receiving);
            if permanent {
                let callback = recycle.read().unwrap().clone();
                callback(sock_addr);
            }
        });
        Ok((socket, close))
    }

    /// Find the currently registered socket for an actual local binding.
    pub fn find_socket(&self, sock_addr: SocketAddr) -> Option<Arc<UdpSocket>> {
        self.sockets.get(&sock_addr)?.upgrade()
    }

    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }
}

async fn discover(
    topology: &Topology,
    addresses: &ArcAddrBook,
    socket: &Arc<UdpSocket>,
    nodes: &[SocketAddr],
    endpoint: &mut EndpointAddr,
) -> io::Result<()> {
    let sock_addr = socket.local_addr()?;
    let directed = EndpointAddr::direct(sock_addr);
    let Some(&agent) = nodes.iter().find(|node| node.family() == sock_addr.family()) else {
        return Ok(());
    };
    // Routing failures can recover without replacing the socket.
    let fatal_socket_error = |error: &io::Error| {
        !matches!(
            error.kind(),
            io::ErrorKind::WouldBlock
                | io::ErrorKind::Interrupted
                | io::ErrorKind::TimedOut
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::HostUnreachable
                | io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::NetworkDown
        )
    };
    let outer = match topology.stun().detect_outer(sock_addr, agent).await {
        Ok(Some(outer)) => outer,
        Err(StunError::Io(error)) if error.raw_os_error().is_some() && fatal_socket_error(&error) => return Err(error),
        result => {
            tracing::debug!(%sock_addr, %agent, ?result, "STUN mapping discovery failed");
            return Ok(());
        }
    };
    let mediated = EndpointAddr::mediate(agent, outer);
    if let Err(error) = topology.quic().register(mediated, socket) {
        tracing::warn!(%sock_addr, %mediated, %error, "STUN endpoint registration failed");
    } else {
        *endpoint = mediated;
        if let Err(error) = addresses.add_endpoint_addr(sock_addr, mediated) {
            tracing::warn!(%sock_addr, %mediated, %error, "STUN endpoint registration failed");
        }
    }
    // detect_nat uses the agent's changed address and then a third server;
    // those auxiliary servers never become communication endpoints.
    let nat = match topology.stun().detect_nat(sock_addr, agent).await {
        Ok(nat) if nat != NatType::Blocked => {
            addresses.add_candidate(Link::new(sock_addr, outer), nat);
            Some(nat)
        }
        Err(StunError::Io(error)) if error.raw_os_error().is_some() && fatal_socket_error(&error) => return Err(error),
        result => {
            tracing::debug!(%sock_addr, %agent, ?result, "STUN NAT classification failed");
            None
        }
    };

    let period = Duration::from_secs(20);
    let mut heartbeat = interval_at(Instant::now() + period, period);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut outer = Some(outer);
    let mut failures = 0u8;
    loop {
        heartbeat.tick().await;
        let link = Link::new(sock_addr, agent);
        let response = {
            let mut transaction = topology.stun().new_transaction();
            timeout(Duration::from_secs(3), transaction.request(link, Request::default())).await
        };
        let mapped = match response {
            Ok(Ok((received, response))) if received == link => match response.map_addr() {
                Ok(mapped) if mapped.family() == sock_addr.family() => Some(mapped),
                result => {
                    tracing::debug!(%sock_addr, %agent, ?result, "invalid STUN heartbeat mapping");
                    None
                }
            },
            Ok(Err(StunError::Io(error))) if fatal_socket_error(&error) => return Err(error),
            result => {
                tracing::debug!(%sock_addr, %agent, ?result, "STUN heartbeat failed");
                None
            }
        };
        let next = if let Some(mapped) = mapped {
            failures = 0;
            Some(mapped)
        } else {
            failures = failures.saturating_add(1);
            if failures < 3 {
                continue;
            }
            None
        };
        if outer == next {
            continue;
        }
        if let Some(previous) = outer.take() {
            if *endpoint != directed {
                addresses.del_endpoint_addr(*endpoint);
                topology.quic().unregister(*endpoint, socket);
                *endpoint = directed;
            }
            if previous == sock_addr && matches!(EndpointAddr::direct(sock_addr).scope(), Some(Scope::Internal | Scope::Loopback)) {
                addresses.add_candidate(Link::new(sock_addr, sock_addr), NatType::FullCone);
            } else {
                addresses.del_candidate(Link::new(sock_addr, previous));
            }
        }
        if let Some(mapped) = next {
            let mediated = EndpointAddr::mediate(agent, mapped);
            if let Err(error) = topology.quic().register(mediated, socket) {
                tracing::warn!(%sock_addr, %mediated, %error, "STUN endpoint registration failed");
            } else {
                *endpoint = mediated;
                if let Err(error) = addresses.add_endpoint_addr(sock_addr, mediated) {
                    tracing::warn!(%sock_addr, %mediated, %error, "STUN endpoint registration failed");
                }
            }
            if let Some(nat) = nat {
                addresses.add_candidate(Link::new(sock_addr, mapped), nat);
            }
        }
        outer = next;
    }
}
