use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use qbase::net::{
    NatType,
    addr::{EndpointAddr, Kind},
    route::{Pathway, Scope, Scopes},
};
use thiserror::Error;
use tokio::sync::{mpsc, watch};

#[derive(Debug, Error)]
pub enum AddressBookError {
    #[error("{0} is already present in the address book")]
    Duplicate(EndpointAddr),
    #[error("{0} is not present in the address book")]
    NotFound(EndpointAddr),
    #[error("expected a Direct endpoint")]
    ExpectedDirect,
    #[error("expected an Agent endpoint")]
    ExpectedMediate,
    #[error("a bound address can publish at most three Agent endpoints")]
    TooManyAgents,
}

/// Local directory changes delivered to one scoped punch subscription in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressEvent {
    Added {
        bound: SocketAddr,
        endpoint: EndpointAddr,
    },
    Removed {
        bound: SocketAddr,
        endpoint: EndpointAddr,
    },
    /// A classification result, also replayed when a binding enters a subscription's scope.
    NatDetected { bound: SocketAddr, nat: NatType },
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
    agents: HashMap<EndpointAddr, SocketAddr>,
    nat: HashMap<SocketAddr, NatType>,
    ddns: watch::Sender<Arc<[EndpointAddr]>>,
    mdns: HashMap<SocketAddr, watch::Sender<Arc<[EndpointAddr]>>>,
    punch_subscribers: Vec<Subscriber>,
}

/// Shared local endpoint directory. Socket registration, reception and STUN tasks belong to
/// the network owner. Register communication addresses before publishing them here, and
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
    pub fn new() -> Self {
        let (ddns, _) = watch::channel(Arc::from([]));
        Self {
            state: Mutex::new(State {
                inner: HashMap::new(),
                outer: HashMap::new(),
                agents: HashMap::new(),
                nat: HashMap::new(),
                ddns,
                mdns: HashMap::new(),
                punch_subscribers: Vec::new(),
            }),
        }
    }

    pub fn insert_inner(
        &self,
        bound: SocketAddr,
        endpoint: EndpointAddr,
    ) -> Result<(), AddressBookError> {
        ensure_kind(endpoint, Kind::Direct)?;
        self.insert(bound, endpoint, Scope::Internal)
    }

    pub fn insert_outer(
        &self,
        bound: SocketAddr,
        endpoint: EndpointAddr,
    ) -> Result<(), AddressBookError> {
        ensure_kind(endpoint, Kind::Direct)?;
        self.insert(bound, endpoint, Scope::External)
    }

    pub fn insert_agent(
        &self,
        bound: SocketAddr,
        endpoint: EndpointAddr,
    ) -> Result<(), AddressBookError> {
        ensure_kind(endpoint, Kind::Mediate)?;
        self.insert(bound, endpoint, Scope::External)
    }

    /// Replace an endpoint in its existing table, retaining its binding and NAT record.
    /// Failed validation leaves the old endpoint intact. Punch consumers receive Removed
    /// followed by Added (with a NAT replay when needed); DNS receives the final snapshot.
    pub fn replace(&self, old: EndpointAddr, new: EndpointAddr) -> Result<(), AddressBookError> {
        let mut state = self.state.lock().unwrap();
        let (scope, bound) = state.locate(old).ok_or(AddressBookError::NotFound(old))?;
        if old == new {
            return Ok(());
        }
        ensure_kind(new, old.kind())?;
        state.ensure_absent(new)?;
        let addresses = state.addresses_mut(scope, old.kind());
        addresses.remove(&old);
        addresses.insert(new, bound);
        state.publish(scope, bound);
        state.removed(bound, old);
        state.added(bound, new, Some(old));
        Ok(())
    }

    /// Withdraw one endpoint without discarding its binding's NAT classification.
    pub fn remove(&self, endpoint: EndpointAddr) -> Option<SocketAddr> {
        let mut state = self.state.lock().unwrap();
        let (scope, bound) = state.locate(endpoint)?;
        state
            .addresses_mut(scope, endpoint.kind())
            .remove(&endpoint);
        state.publish(scope, bound);
        state.removed(bound, endpoint);
        Some(bound)
    }

    /// Withdraw all endpoints and NAT information for a binding. Returns the withdrawn
    /// endpoints for the network owner to clean up communication registrations.
    pub fn remove_bound(&self, bound: SocketAddr) -> Vec<EndpointAddr> {
        let mut state = self.state.lock().unwrap();
        let mut removed = state
            .entries()
            .filter_map(|(endpoint, candidate)| (*candidate == bound).then_some(*endpoint))
            .collect::<Vec<_>>();
        removed.sort_unstable();
        let inner_changed = state.inner.values().any(|candidate| *candidate == bound);
        let ddns_changed = state
            .outer
            .values()
            .chain(state.agents.values())
            .any(|candidate| *candidate == bound);
        state.inner.retain(|_, candidate| *candidate != bound);
        state.outer.retain(|_, candidate| *candidate != bound);
        state.agents.retain(|_, candidate| *candidate != bound);
        state.nat.remove(&bound);
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
    /// Returns whether the value changed. DNS snapshots are unaffected.
    pub fn set_nat(&self, bound: SocketAddr, nat: NatType) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.nat.get(&bound) == Some(&nat) {
            return false;
        }
        state.nat.insert(bound, nat);
        let endpoints = state.bound_endpoints(bound);
        state.punch_subscribers.retain(|subscriber| {
            if subscriber.sender.is_closed() {
                return false;
            }
            !endpoints
                .iter()
                .any(|&endpoint| in_scope(endpoint, subscriber.scopes))
                || subscriber
                    .sender
                    .send(AddressEvent::NatDetected { bound, nat })
                    .is_ok()
        });
        true
    }

    pub fn nat(&self, bound: SocketAddr) -> Option<NatType> {
        self.state.lock().unwrap().nat.get(&bound).copied()
    }

    /// Subscribe to the latest complete outer and mediated DNS address set.
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

    pub fn ddns_endpoints(&self) -> Arc<[EndpointAddr]> {
        self.state.lock().unwrap().ddns_snapshot()
    }

    pub fn mdns_endpoints(&self, bound: SocketAddr) -> Arc<[EndpointAddr]> {
        self.state.lock().unwrap().mdns_snapshot(bound)
    }

    /// Replay existing in-scope endpoints and their NAT classifications, then deliver
    /// subsequent changes in order. NAT is replayed before the first Added for a binding.
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
            if subscriber.bounds.insert(bound)
                && let Some(&nat) = state.nat.get(&bound)
            {
                // The receiver is still owned by this function, so it cannot be closed.
                let _ = subscriber
                    .sender
                    .send(AddressEvent::NatDetected { bound, nat });
            }
            let _ = subscriber
                .sender
                .send(AddressEvent::Added { bound, endpoint });
        }
        state
            .punch_subscribers
            .retain(|subscriber| !subscriber.sender.is_closed());
        state.punch_subscribers.push(subscriber);
        receiver
    }

    /// Generate sorted, deduplicated bootstrap candidates without opening sockets or Paths.
    /// Direct peers use the actual binding; mediated peers need a publicly reachable local
    /// return endpoint. The network owner must register each binding's Direct address as
    /// well as published aliases with QuicProtocol. Socket liveness and interface preferences
    /// are checked by the caller; scope compatibility alone does not establish reachability.
    pub fn pathways_to(&self, peer: EndpointAddr) -> Vec<Pathway> {
        if !usable_endpoint(peer) {
            return Vec::new();
        }
        let Some(destination_scope) = EndpointAddr::direct(*peer).scope() else {
            return Vec::new();
        };
        let state = self.state.lock().unwrap();
        let mut pathways = Vec::new();
        for (&endpoint, &bound) in state.entries() {
            let direct = EndpointAddr::direct(bound);
            if !usable_endpoint(direct)
                || bound.is_ipv4() != peer.addr().is_ipv4()
                || !compatible_scope(direct.scope().unwrap(), destination_scope)
                || !usable_endpoint(endpoint)
            {
                continue;
            }
            if peer.kind() == Kind::Direct || direct.is_globally_routable() {
                if direct != peer {
                    pathways.push(Pathway::new(direct, peer));
                }
            }
            if peer.kind() == Kind::Mediate
                && endpoint.is_globally_routable()
                && endpoint.addr().is_ipv4() == bound.is_ipv4()
                && endpoint != peer
            {
                pathways.push(Pathway::new(endpoint, peer));
            }
        }
        pathways.sort_unstable();
        pathways.dedup();
        pathways
    }

    fn insert(
        &self,
        bound: SocketAddr,
        endpoint: EndpointAddr,
        scope: Scope,
    ) -> Result<(), AddressBookError> {
        let mut state = self.state.lock().unwrap();
        state.ensure_absent(endpoint)?;
        if endpoint.kind() == Kind::Mediate
            && state
                .agents
                .values()
                .filter(|&&candidate| candidate == bound)
                .count()
                >= 3
        {
            return Err(AddressBookError::TooManyAgents);
        }
        state
            .addresses_mut(scope, endpoint.kind())
            .insert(endpoint, bound);
        state.publish(scope, bound);
        state.added(bound, endpoint, None);
        Ok(())
    }
}

impl State {
    fn addresses_mut(
        &mut self,
        scope: Scope,
        kind: Kind,
    ) -> &mut HashMap<EndpointAddr, SocketAddr> {
        match (scope, kind) {
            (Scope::Loopback | Scope::Internal, _) => &mut self.inner,
            (Scope::External, Kind::Direct) => &mut self.outer,
            (Scope::External, Kind::Mediate) => &mut self.agents,
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
            .or_else(|| {
                self.agents
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
        self.inner
            .iter()
            .chain(self.outer.iter())
            .chain(self.agents.iter())
    }

    fn bound_endpoints(&self, bound: SocketAddr) -> Vec<EndpointAddr> {
        self.entries()
            .filter_map(|(&endpoint, &candidate)| (candidate == bound).then_some(endpoint))
            .collect()
    }

    fn ddns_snapshot(&self) -> Arc<[EndpointAddr]> {
        let mut endpoints = self
            .outer
            .keys()
            .chain(self.agents.keys())
            .copied()
            .collect::<Vec<_>>();
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

    fn added(&mut self, bound: SocketAddr, endpoint: EndpointAddr, replaced: Option<EndpointAddr>) {
        let nat = self.nat.get(&bound).copied();
        let others = self.bound_endpoints(bound);
        self.punch_subscribers.retain_mut(|subscriber| {
            if subscriber.sender.is_closed() {
                return false;
            }
            if !in_scope(endpoint, subscriber.scopes) {
                return true;
            }
            subscriber.bounds.insert(bound);
            // A binding can leave the scope and later reenter after an unobserved NAT result.
            // Replay the current NAT when there is no other visible endpoint for this binding.
            let previously_visible = replaced.is_some_and(|old| in_scope(old, subscriber.scopes))
                || others
                    .iter()
                    .any(|&other| other != endpoint && in_scope(other, subscriber.scopes));
            if !previously_visible
                && let Some(nat) = nat
                && subscriber
                    .sender
                    .send(AddressEvent::NatDetected { bound, nat })
                    .is_err()
            {
                return false;
            }
            subscriber
                .sender
                .send(AddressEvent::Added { bound, endpoint })
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

fn ensure_kind(endpoint: EndpointAddr, expected: Kind) -> Result<(), AddressBookError> {
    if endpoint.kind() == expected {
        return Ok(());
    }
    Err(match expected {
        Kind::Direct => AddressBookError::ExpectedDirect,
        Kind::Mediate => AddressBookError::ExpectedMediate,
    })
}

fn in_scope(endpoint: EndpointAddr, scopes: Scopes) -> bool {
    endpoint.scope().is_some_and(|scope| scopes.contains(scope))
}

fn compatible_scope(local: Scope, destination: Scope) -> bool {
    match destination {
        Scope::Loopback | Scope::Internal => local == destination,
        Scope::External => matches!(local, Scope::Internal | Scope::External),
    }
}

fn usable_endpoint(endpoint: EndpointAddr) -> bool {
    match endpoint {
        EndpointAddr::Direct { addr } => addr.port() != 0 && endpoint.scope().is_some(),
        EndpointAddr::Mediate { agent, outer } => {
            usable_endpoint(EndpointAddr::direct(agent))
                && outer.port() != 0
                && !outer.ip().is_unspecified()
                && !outer.ip().is_multicast()
                && agent.is_ipv4() == outer.is_ipv4()
        }
    }
}

#[cfg(test)]
mod tests;
