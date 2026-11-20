use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, OnceLock},
};

use qbase::net::{
    NatType,
    addr::EndpointAddr,
    route::{Link, Scopes},
};
use qresolve::Publish;
use smallvec::SmallVec;
use thiserror::Error;
use tokio::sync::{mpsc, watch};

#[derive(Debug, Error)]
pub enum AddressBookError {
    #[error("{0} is already associated with another socket")]
    AddressInUse(EndpointAddr),
}

/// Explicit candidate insertion, refresh and withdrawal, in directory order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Candidate {
    /// Insert or refresh a socket -> outer mapping with its measured NAT type.
    New { link: Link, nat: NatType },
    /// Withdraw a previously advertised candidate.
    Invalid { link: Link },
}

struct AddrBook {
    socket_addr: HashSet<SocketAddr>,
    endpoint_addr: HashMap<EndpointAddr, SocketAddr>,
    candidates: HashMap<Link, NatType>,
    publishers: watch::Sender<Vec<EndpointAddr>>,
    punchers: Vec<mpsc::UnboundedSender<Candidate>>,
}

/// Shared directory of explicitly registered, non-temporary UDP socket addresses.
///
/// Socket addresses come first and are the only addresses returned by mDNS queries.
/// Endpoint addresses are registered next, including Direct loopback addresses.
/// Publisher registrations select which address scopes to expose externally.
///
/// Finally, once the NAT type is known, a candidate is registered. Its NAT type
/// describes the NAT characteristics of the link from the inner address to the
/// outer address. If the socket has a public IP address, the inner and outer
/// addresses are identical.
///
/// The network owner manages sockets, communication routes and agent probes.
/// Finish old probes before removing or reusing a socket address.
#[derive(Clone)]
pub struct ArcAddrBook(Arc<Mutex<AddrBook>>);

impl ArcAddrBook {
    /// The process-wide directory shared by network owners and address consumers.
    pub fn global() -> &'static Self {
        static GLOBAL: OnceLock<ArcAddrBook> = OnceLock::new();
        GLOBAL.get_or_init(Self::new)
    }

    /// Create an independent directory.
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(AddrBook {
            socket_addr: HashSet::new(),
            endpoint_addr: HashMap::new(),
            candidates: HashMap::new(),
            publishers: watch::Sender::new(Vec::new()),
            punchers: Vec::new(),
        })))
    }

    /// Register an actual bound address together with its Direct endpoint, including loopback.
    /// Returns true on insertion and false if already present. Inconsistent ownership is a bug.
    /// Candidate registration is independent.
    pub fn add_sock_addr(&self, sock_addr: SocketAddr) -> bool {
        self.0.lock().unwrap().add_sock_addr(sock_addr)
    }

    /// Withdraw the socket's Direct endpoint, mappings and NAT records.
    pub fn del_sock_addr(&self, sock_addr: SocketAddr) {
        self.0.lock().unwrap().del_sock_addr(sock_addr);
    }

    /// Register a Direct or Mediate endpoint already registered for communication.
    /// Only endpoint publication changes; candidate records and notifications are independent.
    /// An identical registration is a no-op; endpoints cannot belong to different sockets.
    /// Socket membership is unchecked. The caller guarantees every addition is followed by removal,
    /// even for absent sockets; no delayed addition may arrive after its corresponding removal.
    pub fn add_endpoint_addr(&self, sock_addr: SocketAddr, endpoint: EndpointAddr) -> Result<bool, AddressBookError> {
        self.0.lock().unwrap().add_endpoint_addr(sock_addr, endpoint)
    }

    /// Withdraw one endpoint without changing candidates or notifying punchers.
    /// Direct socket endpoints require del_sock_addr and cannot be removed independently.
    pub fn del_endpoint_addr(&self, endpoint: EndpointAddr) -> Option<SocketAddr> {
        self.0.lock().unwrap().del_endpoint_addr(endpoint)
    }

    /// Find local endpoints that can connect to this peer, independently of NAT classification.
    /// Results are sorted and owned; no directory lock is held while the caller creates paths.
    pub fn matches(&self, peer_ep_addr: EndpointAddr) -> SmallVec<[EndpointAddr; 4]> {
        self.0.lock().unwrap().matches(peer_ep_addr)
    }

    /// Record an explicit agent probe. The Link is socket -> outer, not socket -> agent.
    /// A changed NAT type notifies punchers, whether or not an endpoint is registered.
    pub fn add_candidate(&self, link: Link, nat_type: NatType) -> bool {
        self.0.lock().unwrap().add_candidate(link, nat_type)
    }

    /// Withdraw one candidate and notify punchers, retaining communication endpoints.
    pub fn del_candidate(&self, link: Link) -> bool {
        self.0.lock().unwrap().del_candidate(link)
    }

    /// Last explicitly measured NAT type for this exact socket -> outer mapping.
    pub fn try_get_nat_type(&self, link: Link) -> Option<NatType> {
        self.0.lock().unwrap().try_get_nat_type(link)
    }

    /// Find a registered socket with exactly this IP. Ties use the smallest SocketAddr.
    pub fn mdns_query(&self, ip_addr: IpAddr) -> Option<SocketAddr> {
        self.0.lock().unwrap().mdns_query(ip_addr)
    }

    /// Register an observer, replaying all explicitly registered candidates before subsequent changes.
    /// Replay and registration share one lock so concurrent writes cannot fall between them.
    /// Dropping the receiver unsubscribes; subsequent notifications or attachments prune closed senders.
    pub fn attach_puncher(&self, sender: mpsc::UnboundedSender<Candidate>) {
        self.0.lock().unwrap().attach_puncher(sender);
    }

    /// Publish the current endpoint list, then the latest list after each change.
    /// Filtering uses the requested scopes; publication does not depend on NAT classification.
    /// Each publish finishes before the next starts. Errors are logged; later changes are still published.
    /// Dropping this future cancels observation. Dropping the last book owner closes the stream.
    pub async fn change_then_publish_with_scope(self, publisher: Arc<dyn Publish>, scopes: Scopes) {
        let mut updates = self.0.lock().unwrap().publishers.subscribe();
        drop(self);
        loop {
            let filtered: SmallVec<[EndpointAddr; 4]> = updates
                .borrow_and_update()
                .iter()
                .copied()
                .filter(|endpoint| endpoint.scope().is_some_and(|scope| scopes.contains(scope)))
                .collect();
            if let Err(error) = publisher.publish(&mut filtered.into_iter()).await {
                tracing::warn!(%publisher, %error, "endpoint publication failed");
            }
            if updates.changed().await.is_err() {
                break;
            }
        }
    }
}

impl Default for ArcAddrBook {
    fn default() -> Self {
        Self::new()
    }
}

impl AddrBook {
    fn add_sock_addr(&mut self, sock_addr: SocketAddr) -> bool {
        let added = self.socket_addr.insert(sock_addr);
        let endpoint = EndpointAddr::direct(sock_addr);
        assert_eq!(
            self.add_endpoint_addr(sock_addr, endpoint).expect("socket address and Direct endpoint must be registered together"),
            added,
        );
        added
    }

    fn del_sock_addr(&mut self, sock_addr: SocketAddr) {
        self.socket_addr.remove(&sock_addr);
        self.del_endpoint_addr(EndpointAddr::direct(sock_addr));
        let endpoints =
            self.endpoint_addr.iter().filter_map(|(&endpoint, &source)| (source == sock_addr).then_some(endpoint)).collect::<Vec<_>>();
        for endpoint in endpoints {
            self.del_endpoint_addr(endpoint);
        }
        let links = self.candidates.keys().copied().filter(|link| link.src == sock_addr).collect::<Vec<_>>();
        for link in links {
            self.del_candidate(link);
        }
    }

    fn add_endpoint_addr(&mut self, sock_addr: SocketAddr, endpoint: EndpointAddr) -> Result<bool, AddressBookError> {
        if let Some(&source) = self.endpoint_addr.get(&endpoint) {
            return if source == sock_addr {
                Ok(false)
            } else {
                Err(AddressBookError::AddressInUse(endpoint))
            };
        }
        self.endpoint_addr.insert(endpoint, sock_addr);
        self.notify_publishers();
        Ok(true)
    }

    fn del_endpoint_addr(&mut self, endpoint: EndpointAddr) -> Option<SocketAddr> {
        if let EndpointAddr::Direct { addr } = endpoint
            && self.socket_addr.contains(&addr)
        {
            return None;
        }
        let sock_addr = self.endpoint_addr.remove(&endpoint)?;
        self.notify_publishers();
        Some(sock_addr)
    }

    fn matches(&self, peer_ep_addr: EndpointAddr) -> SmallVec<[EndpointAddr; 4]> {
        let mut endpoints: SmallVec<_> = self.endpoint_addr.keys().copied().filter(|local| local.can_connect_to(peer_ep_addr)).collect();
        endpoints.sort_unstable();
        endpoints
    }

    fn add_candidate(&mut self, link: Link, nat_type: NatType) -> bool {
        if self.candidates.insert(link, nat_type) == Some(nat_type) {
            return false;
        }
        self.notify_punchers(Candidate::New { link, nat: nat_type });
        true
    }

    fn del_candidate(&mut self, link: Link) -> bool {
        if self.candidates.remove(&link).is_none() {
            return false;
        }
        self.notify_punchers(Candidate::Invalid { link });
        true
    }

    fn try_get_nat_type(&self, link: Link) -> Option<NatType> {
        self.candidates.get(&link).copied()
    }

    fn mdns_query(&self, ip_addr: IpAddr) -> Option<SocketAddr> {
        self.socket_addr.iter().filter(|addr| addr.ip() == ip_addr).min().copied()
    }

    fn notify_punchers(&mut self, event: Candidate) {
        self.punchers.retain(|sender| sender.send(event).is_ok());
    }

    fn notify_publishers(&self) {
        self.publishers.send_modify(|endpoints| {
            endpoints.clear();
            endpoints.extend(self.endpoint_addr.keys().copied());
            endpoints.sort_unstable();
        });
    }

    fn attach_puncher(&mut self, sender: mpsc::UnboundedSender<Candidate>) {
        self.punchers.retain(|sender| !sender.is_closed());
        let mut candidates = self.candidates.iter().map(|(&link, &nat)| (link, nat)).collect::<Vec<_>>();
        candidates.sort_unstable_by_key(|&(link, _)| (link.src, link.dst));
        for (link, nat) in candidates {
            if sender.send(Candidate::New { link, nat }).is_err() {
                return;
            }
        }
        if !sender.is_closed() {
            self.punchers.push(sender);
        }
    }
}
