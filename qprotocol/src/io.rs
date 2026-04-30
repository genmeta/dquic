use std::{
    collections::HashMap,
    io::{self, IoSlice},
    net::SocketAddr,
    sync::{Arc, atomic::AtomicUsize},
    task::{Context, Poll},
};

use dashmap::DashMap;
use qbase::{
    ArcReceiving,
    net::{
        NetFeature,
        addr::EndpointAddr,
        route::{Link, Route},
    },
};
use qinterface::bind_uri::BindUri;
use qudp::ext::UdpSocket;
use tokio::sync::{SetOnce, mpsc};

use crate::stun;

/// A unique handle identifying a managed UDP socket inside the [`Dock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fd(usize);

static FD_COUNTER: AtomicUsize = AtomicUsize::new(0);

impl Fd {
    fn next() -> Self {
        Fd(FD_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

/// STUN agent handle – the concrete keepalive logic lives in `stun/agent.rs`.
/// Wraps an inner agent behind `Arc` so that the keepalive task and the Dock
/// can share ownership.
pub struct Agent {
    // TODO: fill in keepalive / probe state
    pub stun_addr: SocketAddr,
}

pub type ArcAgent = Arc<Agent>;

/// A packet that should be forwarded (relayed).
pub struct ForwardPacket {
    pub payload: bytes::Bytes,
    pub link: Link,
}

/// Aggregated external addresses learned from STUN for the resident sockets.
#[derive(Default)]
pub struct AddressBook {
    /// bind_uri -> list of discovered endpoint addresses
    entries: HashMap<BindUri, Vec<EndpointAddr>>,
}

/// The harbour where all managed UDP sockets are docked.
///
/// It owns every UDP socket, their STUN agents, NAT probing results,
/// transaction routing, and protocol-level channels.
pub struct Dock {
    // ── resident listeners ──────────────────────────────────────────────
    /// BindUri → Fd mapping for sockets that **must** stay open.
    resident: DashMap<BindUri, Fd>,

    // ── sockets ─────────────────────────────────────────────────────────
    /// All managed sockets (both long-lived residents and ephemeral ones).
    sockets: DashMap<Fd, UdpSocket>,

    // ── STUN agents ─────────────────────────────────────────────────────
    /// Per-socket STUN agents with their associated server address.
    /// `Vec` because the number of agents per socket is typically tiny.
    agents: DashMap<Fd, Vec<(SocketAddr, ArcAgent)>>,
    /// Pending STUN BindingRequest→BindingResponse transactions.
    transactions: DashMap<stun::TransactionId, ArcReceiving<stun::Response>>,
    // ── NAT feature ─────────────────────────────────────────────────────
    /// Per-socket NAT type, resolved asynchronously by the NAT probe task.
    nat_features: DashMap<Fd, SetOnce<NetFeature>>,
    /// Externally-visible addresses discovered by agents.
    endpoint_addrs: DashMap<Fd, HashMap<SocketAddr, Arc<SetOnce<SocketAddr>>>>,

    // ── global address book ─────────────────────────────────────────────
    /// Aggregated endpoint addresses **only** for resident sockets.
    address_book: AddressBook,

    // ── QUIC routing ────────────────────────────────────────────────────
    // router: HashMap<ConnectionId, ...>,  // TODO: wire up QUIC CID router

    // ── channels ────────────────────────────────────────────────────────
    /// Incoming STUN BindingRequests (for the built-in STUN server).
    stun_tx: mpsc::UnboundedSender<stun::Request>,
    stun_rx: mpsc::UnboundedReceiver<stun::Request>,

    /// Packets that need to be forwarded / relayed.
    forward_tx: mpsc::UnboundedSender<ForwardPacket>,
    forward_rx: mpsc::UnboundedReceiver<ForwardPacket>,
}

impl Dock {
    /// Create an empty `Dock`.
    pub fn new() -> Self {
        let (stun_tx, stun_rx) = mpsc::unbounded_channel();
        let (forward_tx, forward_rx) = mpsc::unbounded_channel();
        Self {
            resident: DashMap::new(),
            sockets: DashMap::new(),
            agents: DashMap::new(),
            endpoint_addrs: DashMap::new(),
            transactions: DashMap::new(),
            nat_features: DashMap::new(),
            stun_tx,
            stun_rx,
            forward_tx,
            forward_rx,
            address_book: AddressBook::default(),
        }
    }

    /// Bind a new UDP socket for the given URI and return its [`Fd`].
    pub fn bind(&self, uri: BindUri) -> io::Result<Fd> {
        let addr: SocketAddr = (&uri)
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e}")))?;
        let socket = UdpSocket::bind(addr);
        let fd = Fd::next();

        self.sockets.insert(fd, socket);
        self.resident.insert(uri, fd);
        self.nat_features.insert(fd, SetOnce::const_new());
        self.endpoint_addrs.insert(fd, HashMap::new());
        Ok(fd)
    }

    /// Close and remove the socket identified by `fd`.
    pub fn close(&self, fd: Fd) {
        if let Some((_, mut socket)) = self.sockets.remove(&fd) {
            socket.close();
        }
        self.agents.remove(&fd);
        self.nat_features.remove(&fd);
        self.endpoint_addrs.remove(&fd);
        // Remove from resident map if present.
        self.resident.retain(|_, v| *v != fd);
    }

    // ── send ────────────────────────────────────────────────────────────

    /// Send datagrams through the socket identified by `fd`.
    pub fn poll_send(
        &self,
        fd: Fd,
        cx: &mut Context<'_>,
        pkts: &[IoSlice<'_>],
        route: Route,
    ) -> Poll<io::Result<usize>> {
        let socket = self
            .sockets
            .get(&fd)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown fd"))?;
        socket.poll_send(cx, pkts, route)
    }

    // ── STUN agent management ───────────────────────────────────────────

    /// Register a STUN agent for the given socket and agent server address.
    pub fn add_agent(&self, fd: Fd, agent_addr: SocketAddr) -> io::Result<()> {
        if !self.sockets.contains_key(&fd) {
            return Err(io::Error::new(io::ErrorKind::NotFound, "unknown fd"));
        }
        let agent = Arc::new(Agent {
            stun_addr: agent_addr,
        });
        let mut agents = self.agents.entry(fd).or_default();
        if agents.iter().any(|(a, _)| *a == agent_addr) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "agent already registered",
            ));
        }
        agents.push((agent_addr, agent));
        Ok(())
    }

    /// Remove a previously registered STUN agent.
    pub fn del_agent(&self, fd: Fd, agent_addr: SocketAddr) {
        if let Some(mut agents) = self.agents.get_mut(&fd) {
            agents.retain(|(a, _)| *a != agent_addr);
        }
        if let Some(mut ep_addrs) = self.endpoint_addrs.get_mut(&fd) {
            ep_addrs.remove(&agent_addr);
        }
    }

    // ── queries ─────────────────────────────────────────────────────────

    /// Return the locally bound address of the socket.
    pub fn bind_addr(&self, fd: Fd) -> io::Result<SocketAddr> {
        self.sockets
            .get(&fd)
            .map(|s| s.local_addr())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown fd"))?
    }

    /// Asynchronously wait for the NAT type probing result of the socket.
    pub async fn nat_feature(&self, fd: Fd) -> io::Result<NetFeature> {
        let once = self
            .nat_features
            .get(&fd)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown fd"))?;
        Ok(*once.wait().await)
    }

    /// Asynchronously wait for the external (STUN-mapped) endpoint address.
    pub async fn endpoint_addr(&self, fd: Fd, agent_addr: SocketAddr) -> io::Result<SocketAddr> {
        let once = {
            let ep_addrs = self
                .endpoint_addrs
                .get(&fd)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown fd"))?;

            ep_addrs
                .get(&agent_addr)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown agent"))?
        };

        Ok(*once.wait().await)
    }
}
