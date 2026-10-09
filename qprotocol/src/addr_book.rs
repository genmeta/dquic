use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
};

use qbase::net::{
    AddrFamily, Family, NatType,
    addr::EndpointAddr,
    route::{Pathway, Scope, Scopes},
};
use qresolve::Source;
use thiserror::Error;
use tokio::sync::{mpsc, watch};

use crate::UdpSocket;

#[derive(Debug, Error)]
pub enum AddressBookError {
    #[error("failed to read socket binding: {0}")]
    Socket(#[from] io::Error),
    #[error("{0} is already present in the address book")]
    Duplicate(EndpointAddr),
    #[error("{0} is not present in the address book")]
    NotFound(EndpointAddr),
    #[error("{0} is already associated with another interface")]
    ConflictingInterface(SocketAddr),
}

/// Local directory changes delivered to one scoped punch subscription in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressEvent {
    /// Insert or refresh an endpoint ready for advertisement, including its wire NAT type.
    /// Internal and loopback endpoints use FullCone; external endpoints wait for classification.
    Added {
        bound: SocketAddr,
        endpoint: EndpointAddr,
        nat: NatType,
    },
    /// Withdraw an endpoint, including one whose advertisement was waiting for classification.
    Removed {
        bound: SocketAddr,
        endpoint: EndpointAddr,
    },
    /// The binding and its NAT record have been withdrawn from the directory.
    BoundRemoved { bound: SocketAddr },
}

struct Subscriber {
    scopes: Scopes,
    sender: mpsc::UnboundedSender<AddressEvent>,
    // Remember bindings until remove_bound, even after their last visible alias is removed.
    bounds: HashSet<SocketAddr>,
}

struct State {
    inner: HashMap<EndpointAddr, SocketAddr>,
    outer: HashMap<EndpointAddr, SocketAddr>,
    interfaces: HashMap<SocketAddr, Option<qudp::BoundDevice>>,
    nat: HashMap<SocketAddr, NatType>,
    ddns: watch::Sender<Arc<[EndpointAddr]>>,
    mdns: HashMap<SocketAddr, watch::Sender<Arc<[EndpointAddr]>>>,
    punch_subscribers: Vec<Subscriber>,
}

/// Shared local endpoint directory, including external relay endpoints.
/// Socket registration, reception and STUN tasks belong to the network owner. Register communication addresses before publishing them here, and
/// finish old measurement tasks before removing or reusing a binding.
///
/// Directory changes, DNS snapshots and punch replay/subscription share one lock. All sends
/// under the lock are synchronous; consumers process their notifications outside this lock.
pub struct AddressBook {
    state: Mutex<State>,
}

impl Default for AddressBook {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressBook {
    /// Process-wide local endpoint directory used by connection discovery.
    /// The network owner registers sockets and publishes their endpoints here.
    pub fn global() -> &'static Arc<Self> {
        static ADDRESSES: OnceLock<Arc<AddressBook>> = OnceLock::new();
        ADDRESSES.get_or_init(|| Arc::new(Self::new()))
    }

    pub fn new() -> Self {
        let (ddns, _) = watch::channel(Arc::from([]));
        Self {
            state: Mutex::new(State {
                inner: HashMap::new(),
                outer: HashMap::new(),
                interfaces: HashMap::new(),
                nat: HashMap::new(),
                ddns,
                mdns: HashMap::new(),
                punch_subscribers: Vec::new(),
            }),
        }
    }

    /// Publish an inner endpoint using the socket's actual binding and interface metadata.
    /// The caller supplies a Direct endpoint.
    /// Only the metadata is copied; the directory does not retain the socket.
    pub fn insert_inner(
        &self,
        socket: &UdpSocket,
        endpoint: EndpointAddr,
    ) -> Result<(), AddressBookError> {
        self.insert(
            socket.local_addr()?,
            endpoint,
            Scope::Internal,
            socket.bound_device(),
        )
    }

    /// Publish a Direct or Mediate outer alias, sharing its binding's interface metadata.
    pub fn insert_outer(
        &self,
        socket: &UdpSocket,
        endpoint: EndpointAddr,
    ) -> Result<(), AddressBookError> {
        self.insert(
            socket.local_addr()?,
            endpoint,
            Scope::External,
            socket.bound_device(),
        )
    }

    /// Replace an endpoint in its existing table, retaining its binding and NAT record.
    /// Failed replacement leaves the old endpoint intact. Punch consumers receive Removed
    /// followed by Added when the new endpoint is ready; DNS receives the final snapshot.
    pub fn replace(&self, old: EndpointAddr, new: EndpointAddr) -> Result<(), AddressBookError> {
        let mut state = self.state.lock().unwrap();
        let (scope, bound) = state.locate(old).ok_or(AddressBookError::NotFound(old))?;
        if old == new {
            return Ok(());
        }
        state.ensure_absent(new)?;
        let addresses = state.addresses_mut(scope);
        addresses.remove(&old);
        addresses.insert(new, bound);
        state.publish(scope, bound);
        state.removed(bound, old);
        state.added(bound, new);
        Ok(())
    }

    /// Withdraw one endpoint without discarding its binding's NAT classification.
    pub fn remove(&self, endpoint: EndpointAddr) -> Option<SocketAddr> {
        let mut state = self.state.lock().unwrap();
        let (scope, bound) = state.locate(endpoint)?;
        state.addresses_mut(scope).remove(&endpoint);
        state.publish(scope, bound);
        state.removed(bound, endpoint);
        Some(bound)
    }

    /// Withdraw all endpoints, interface and NAT information for a binding. Returns the withdrawn
    /// endpoints for the network owner to clean up communication registrations.
    pub fn remove_bound(&self, bound: SocketAddr) -> Vec<EndpointAddr> {
        let mut state = self.state.lock().unwrap();
        let mut removed = state
            .entries()
            .filter_map(|(endpoint, candidate)| (*candidate == bound).then_some(*endpoint))
            .collect::<Vec<_>>();
        removed.sort_unstable();
        let inner_changed = state.inner.values().any(|candidate| *candidate == bound);
        let ddns_changed = state.outer.values().any(|candidate| *candidate == bound);
        state.inner.retain(|_, candidate| *candidate != bound);
        state.outer.retain(|_, candidate| *candidate != bound);
        state.nat.remove(&bound);
        state.interfaces.remove(&bound);
        if inner_changed {
            state.publish(Scope::Internal, bound);
        }
        if ddns_changed {
            state.publish(Scope::External, bound);
        }
        for &endpoint in &removed {
            state.removed(bound, endpoint);
        }
        state.punch_subscribers.retain_mut(|subscriber| {
            if subscriber.sender.is_closed() {
                return false;
            }
            !subscriber.bounds.remove(&bound)
                || subscriber
                    .sender
                    .send(AddressEvent::BoundRemoved { bound })
                    .is_ok()
        });
        removed
    }

    /// Store one classification per binding, independently of endpoint insertion.
    /// Refresh the binding's external endpoints for punch subscribers when the value changes.
    /// Returns whether the value changed. DNS snapshots are unaffected.
    pub fn set_nat(&self, bound: SocketAddr, nat: NatType) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.nat.get(&bound) == Some(&nat) {
            return false;
        }
        state.nat.insert(bound, nat);
        let mut endpoints = state.bound_endpoints(bound);
        endpoints.sort_unstable();
        for endpoint in endpoints {
            if endpoint.scope() == Some(Scope::External) {
                state.added(bound, endpoint);
            }
        }
        true
    }

    pub fn nat(&self, bound: SocketAddr) -> Option<NatType> {
        self.state.lock().unwrap().nat.get(&bound).copied()
    }

    /// Subscribe to the latest complete outer DNS address set.
    /// Read the current value before awaiting subsequent watch changes.
    pub fn subscribe_ddns(&self) -> watch::Receiver<Arc<[EndpointAddr]>> {
        self.state.lock().unwrap().ddns.subscribe()
    }

    /// Subscribe to the latest complete inner DNS address set for one binding.
    /// Snapshot initialization and publisher registration are atomic with directory writes.
    pub fn subscribe_mdns(&self, bound: SocketAddr) -> watch::Receiver<Arc<[EndpointAddr]>> {
        let mut state = self.state.lock().unwrap();
        if let Some(sender) = state.mdns.get(&bound) {
            return sender.subscribe();
        }
        let snapshot = state.mdns_snapshot(bound);
        state
            .mdns
            .entry(bound)
            .or_insert_with(|| watch::channel(snapshot).0)
            .subscribe()
    }

    /// Snapshot internal bindings with their actual interface metadata.
    pub fn inner_bindings(&self) -> Vec<(SocketAddr, qudp::BoundDevice)> {
        let state = self.state.lock().unwrap();
        let mut bounds = state
            .inner
            .iter()
            .filter_map(|(endpoint, bound)| {
                (endpoint.scope() == Some(Scope::Internal)
                    && endpoint.addr().port() != 0
                    && bound.port() != 0)
                    .then_some(*bound)
            })
            .collect::<Vec<_>>();
        bounds.sort_unstable();
        bounds.dedup();
        bounds
            .into_iter()
            .filter_map(|bound| Some((bound, state.interfaces.get(&bound)?.as_ref()?.clone())))
            .collect()
    }

    pub fn ddns_endpoints(&self) -> Arc<[EndpointAddr]> {
        self.state.lock().unwrap().ddns_snapshot()
    }

    pub fn mdns_endpoints(&self, bound: SocketAddr) -> Arc<[EndpointAddr]> {
        self.state.lock().unwrap().mdns_snapshot(bound)
    }

    /// Replay in-scope endpoints ready for advertisement, then deliver changes in order.
    /// Internal and loopback endpoints use FullCone; external endpoints wait for classification.
    /// Added also refreshes an existing endpoint when its NAT classification changes.
    /// Dropping the receiver ends the subscription; later writes/subscriptions prune it.
    pub fn subscribe_punch(
        &self,
        scopes: impl Into<Scopes>,
    ) -> mpsc::UnboundedReceiver<AddressEvent> {
        let mut state = self.state.lock().unwrap();
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut subscriber = Subscriber {
            scopes: scopes.into(),
            sender,
            bounds: HashSet::new(),
        };
        let mut endpoints = state
            .entries()
            .filter_map(|(&endpoint, &bound)| {
                in_scope(endpoint, subscriber.scopes).then_some((bound, endpoint))
            })
            .collect::<Vec<_>>();
        endpoints.sort_unstable();
        for (bound, endpoint) in endpoints {
            subscriber.bounds.insert(bound);
            let Some(nat) = state.advertisement_nat(bound, endpoint) else {
                continue;
            };
            // The receiver is still owned by this function, so it cannot be closed.
            let _ = subscriber.sender.send(AddressEvent::Added {
                bound,
                endpoint,
                nat,
            });
        }
        state
            .punch_subscribers
            .retain(|subscriber| !subscriber.sender.is_closed());
        state.punch_subscribers.push(subscriber);
        receiver
    }

    /// Select sorted bootstrap candidates from existing unique local endpoints.
    /// Direct peers match Direct endpoints; mediated peers match Mediate endpoints and
    /// retain each local endpoint's own agent and outer mapping. No endpoint is synthesized.
    /// mDNS sources restrict the address family and interface using registered binding metadata;
    /// missing metadata cannot match. The caller checks socket liveness and reachability.
    pub fn pathways_to(&self, peer: EndpointAddr, source: &Source) -> Vec<Pathway> {
        let state = self.state.lock().unwrap();
        let mut pathways = state
            .entries()
            .filter(|&(&endpoint, _)| endpoint.matches_peer(peer))
            .filter(|&(_, &bound)| match source {
                Source::Mdns { nic, family } => {
                    peer.addr().family() == *family && state.matches_mdns(bound, nic, *family)
                }
                _ => true,
            })
            .map(|(&endpoint, _)| Pathway::new(endpoint, peer))
            .collect::<Vec<_>>();
        pathways.sort_unstable();
        pathways
    }

    fn insert(
        &self,
        bound: SocketAddr,
        endpoint: EndpointAddr,
        scope: Scope,
        interface: Option<&qudp::BoundDevice>,
    ) -> Result<(), AddressBookError> {
        let mut state = self.state.lock().unwrap();
        state.ensure_absent(endpoint)?;
        state.set_interface(bound, interface)?;
        state.addresses_mut(scope).insert(endpoint, bound);
        state.publish(scope, bound);
        state.added(bound, endpoint);
        Ok(())
    }
}

impl State {
    fn matches_mdns(&self, bound: SocketAddr, nic: &str, family: Family) -> bool {
        let Some(device) = self.interfaces.get(&bound).and_then(Option::as_ref) else {
            return false;
        };
        bound.family() == family
            && device.name() == nic
            && match bound {
                SocketAddr::V4(_) => true,
                SocketAddr::V6(addr) => {
                    addr.scope_id() == 0 || addr.scope_id() == device.index().get()
                }
            }
    }

    // Metadata is recorded atomically with endpoint publication. All aliases must
    // agree, including an explicitly unscoped socket. remove_bound ends its lifetime.
    fn set_interface(
        &mut self,
        bound: SocketAddr,
        interface: Option<&qudp::BoundDevice>,
    ) -> Result<(), AddressBookError> {
        if let Some(known) = self.interfaces.get(&bound) {
            if known.as_ref() != interface {
                return Err(AddressBookError::ConflictingInterface(bound));
            }
        } else {
            self.interfaces.insert(bound, interface.cloned());
        }
        Ok(())
    }

    fn addresses_mut(&mut self, scope: Scope) -> &mut HashMap<EndpointAddr, SocketAddr> {
        match scope {
            Scope::Loopback | Scope::Internal => &mut self.inner,
            Scope::External => &mut self.outer,
        }
    }

    fn locate(&self, endpoint: EndpointAddr) -> Option<(Scope, SocketAddr)> {
        // Both loopback and internal endpoints are published through the inner DNS table.
        self.inner
            .get(&endpoint)
            .map(|&bound| (Scope::Internal, bound))
            .or_else(|| {
                self.outer
                    .get(&endpoint)
                    .map(|&bound| (Scope::External, bound))
            })
    }

    fn ensure_absent(&self, endpoint: EndpointAddr) -> Result<(), AddressBookError> {
        if self.locate(endpoint).is_some() {
            return Err(AddressBookError::Duplicate(endpoint));
        }
        Ok(())
    }

    fn entries(&self) -> impl Iterator<Item = (&EndpointAddr, &SocketAddr)> {
        self.inner.iter().chain(self.outer.iter())
    }

    fn bound_endpoints(&self, bound: SocketAddr) -> Vec<EndpointAddr> {
        self.entries()
            .filter_map(|(&endpoint, &candidate)| (candidate == bound).then_some(endpoint))
            .collect()
    }

    fn ddns_snapshot(&self) -> Arc<[EndpointAddr]> {
        let mut endpoints = self.outer.keys().copied().collect::<Vec<_>>();
        endpoints.sort_unstable();
        endpoints.into()
    }

    fn mdns_snapshot(&self, bound: SocketAddr) -> Arc<[EndpointAddr]> {
        let mut endpoints = self
            .inner
            .iter()
            .filter_map(|(&endpoint, &candidate)| (candidate == bound).then_some(endpoint))
            .collect::<Vec<_>>();
        endpoints.sort_unstable();
        endpoints.into()
    }

    fn publish(&self, scope: Scope, bound: SocketAddr) {
        match scope {
            Scope::Loopback | Scope::Internal => {
                if let Some(sender) = self.mdns.get(&bound) {
                    sender.send_replace(self.mdns_snapshot(bound));
                }
            }
            Scope::External => {
                self.ddns.send_replace(self.ddns_snapshot());
            }
        }
    }

    fn advertisement_nat(&self, bound: SocketAddr, endpoint: EndpointAddr) -> Option<NatType> {
        match endpoint.scope()? {
            Scope::Internal | Scope::Loopback => Some(NatType::FullCone),
            Scope::External => self.nat.get(&bound).copied(),
        }
    }

    fn added(&mut self, bound: SocketAddr, endpoint: EndpointAddr) {
        let nat = self.advertisement_nat(bound, endpoint);
        self.punch_subscribers.retain_mut(|subscriber| {
            if subscriber.sender.is_closed() {
                return false;
            }
            if !in_scope(endpoint, subscriber.scopes) {
                return true;
            }
            subscriber.bounds.insert(bound);
            let Some(nat) = nat else {
                return true;
            };
            subscriber
                .sender
                .send(AddressEvent::Added {
                    bound,
                    endpoint,
                    nat,
                })
                .is_ok()
        });
    }

    fn removed(&mut self, bound: SocketAddr, endpoint: EndpointAddr) {
        self.punch_subscribers.retain(|subscriber| {
            if subscriber.sender.is_closed() {
                return false;
            }
            !in_scope(endpoint, subscriber.scopes)
                || subscriber
                    .sender
                    .send(AddressEvent::Removed { bound, endpoint })
                    .is_ok()
        });
    }
}

fn in_scope(endpoint: EndpointAddr, scopes: Scopes) -> bool {
    endpoint.scope().is_some_and(|scope| scopes.contains(scope))
}

#[cfg(test)]
mod tests;
