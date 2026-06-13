use std::{
    collections::{HashMap, hash_map::Entry},
    net::SocketAddr,
    ops::Deref,
};

use futures::io;
use qbase::{
    frame::{AddAddressFrame, RemoveAddressFrame},
    net::{NatType, addr::EndpointAddr},
};
use qinterface::bind_uri::BindUri;
use qresolve::Source;

/// Local endpoint membership effect emitted for qtraversal/qconnection integration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalEndpointEffect {
    AddEndpoint {
        bind_uri: BindUri,
        endpoint: EndpointAddr,
    },
    RemoveEndpoint {
        bind_uri: BindUri,
        endpoint: EndpointAddr,
    },
    AddPunchAddress {
        bind_uri: BindUri,
        endpoint: EndpointAddr,
    },
    RemovePunchAddress {
        addr: SocketAddr,
    },
}

/// Ordered local endpoint membership effects consumed by qtraversal/qconnection integration.
pub type LocalEndpointEffects = Vec<LocalEndpointEffect>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalEndpointSource {
    Explicit,
    #[allow(dead_code)]
    LocationDirect,
    #[allow(dead_code)]
    LocationStun,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct LocalEndpointSources {
    explicit: bool,
    location_direct: bool,
    location_stun: bool,
}

impl LocalEndpointSources {
    fn contains(self, source: LocalEndpointSource) -> bool {
        match source {
            LocalEndpointSource::Explicit => self.explicit,
            LocalEndpointSource::LocationDirect => self.location_direct,
            LocalEndpointSource::LocationStun => self.location_stun,
        }
    }

    fn insert(&mut self, source: LocalEndpointSource) -> bool {
        let existed = self.contains(source);
        match source {
            LocalEndpointSource::Explicit => self.explicit = true,
            LocalEndpointSource::LocationDirect => self.location_direct = true,
            LocalEndpointSource::LocationStun => self.location_stun = true,
        }
        !existed
    }

    fn remove(&mut self, source: LocalEndpointSource) -> bool {
        let existed = self.contains(source);
        match source {
            LocalEndpointSource::Explicit => self.explicit = false,
            LocalEndpointSource::LocationDirect => self.location_direct = false,
            LocalEndpointSource::LocationStun => self.location_stun = false,
        }
        existed
    }

    fn is_empty(self) -> bool {
        !self.explicit && !self.location_direct && !self.location_stun
    }
}

#[derive(Default)]
pub struct AddressBook {
    local: HashMap<u32, (BindUri, AddAddressFrame)>,
    remote: HashMap<u32, AddAddressFrame>,
    local_endpoint: HashMap<BindUri, HashMap<EndpointAddr, LocalEndpointSources>>,
    /// Remote endpoints with their DNS [`Source`] so the puncher can enforce
    /// source-specific constraints (e.g. mDNS endpoints are tied to a NIC).
    remote_endpoint: HashMap<EndpointAddr, Source>,
    largest_seq_num: u32,
}

impl AddressBook {
    pub(crate) fn add_local_address(
        &mut self,
        bind: BindUri,
        addr: SocketAddr,
        tire: u32,
        nat_type: NatType,
    ) -> io::Result<AddAddressFrame> {
        if self
            .local
            .values()
            .any(|(_local, frame)| *frame.deref() == addr)
        {
            tracing::debug!(target: "quic", %addr, "Duplicate local address");
            return Err(io::Error::other("Duplicate local address"));
        }
        let frame = AddAddressFrame::new(self.largest_seq_num, addr, tire, nat_type);
        self.local.insert(self.largest_seq_num, (bind, frame));
        self.largest_seq_num += 1;
        Ok(frame)
    }

    pub(crate) fn add_local_endpoint(
        &mut self,
        bind: BindUri,
        addr: EndpointAddr,
    ) -> io::Result<LocalEndpointEffects> {
        if self
            .local_endpoint
            .get(&bind)
            .and_then(|endpoints| endpoints.get(&addr))
            .is_some_and(|sources| sources.contains(LocalEndpointSource::Explicit))
        {
            return Err(io::Error::other("Duplicate local endpoint"));
        }
        Ok(self.insert_local_endpoint_source(bind, addr, LocalEndpointSource::Explicit))
    }

    pub(crate) fn remove_local_endpoint(
        &mut self,
        bind: &BindUri,
        addr: EndpointAddr,
    ) -> LocalEndpointEffects {
        self.remove_local_endpoint_source(bind, addr, LocalEndpointSource::Explicit)
    }

    #[allow(dead_code)]
    pub(crate) fn upsert_direct_endpoint(
        &mut self,
        bind: BindUri,
        addr: SocketAddr,
    ) -> LocalEndpointEffects {
        let endpoint = EndpointAddr::direct(addr);
        if self
            .local_endpoint
            .get(&bind)
            .and_then(|endpoints| endpoints.get(&endpoint))
            .is_some_and(|sources| sources.contains(LocalEndpointSource::LocationDirect))
        {
            return Vec::new();
        }

        let mut effects =
            self.remove_current_local_endpoint_source(&bind, LocalEndpointSource::LocationDirect);
        effects.extend(self.insert_local_endpoint_source(
            bind,
            endpoint,
            LocalEndpointSource::LocationDirect,
        ));
        effects
    }

    #[allow(dead_code)]
    pub(crate) fn remove_direct_endpoint(&mut self, bind: &BindUri) -> LocalEndpointEffects {
        self.remove_current_local_endpoint_source(bind, LocalEndpointSource::LocationDirect)
    }

    #[allow(dead_code)]
    pub(crate) fn upsert_stun_endpoint(
        &mut self,
        bind: BindUri,
        endpoint: EndpointAddr,
    ) -> LocalEndpointEffects {
        if self
            .local_endpoint
            .get(&bind)
            .and_then(|endpoints| endpoints.get(&endpoint))
            .is_some_and(|sources| sources.contains(LocalEndpointSource::LocationStun))
        {
            return Vec::new();
        }

        let mut effects =
            self.remove_current_local_endpoint_source(&bind, LocalEndpointSource::LocationStun);
        effects.extend(self.insert_local_endpoint_source(
            bind,
            endpoint,
            LocalEndpointSource::LocationStun,
        ));
        effects
    }

    #[allow(dead_code)]
    pub(crate) fn remove_stun_endpoint(&mut self, bind: &BindUri) -> LocalEndpointEffects {
        self.remove_current_local_endpoint_source(bind, LocalEndpointSource::LocationStun)
    }

    #[allow(dead_code)]
    pub(crate) fn close_tracked_bind_uri(&mut self, bind: &BindUri) -> LocalEndpointEffects {
        let mut effects = self.remove_direct_endpoint(bind);
        effects.extend(self.remove_stun_endpoint(bind));
        effects
    }

    pub(crate) fn has_local_endpoint(&self, bind: &BindUri, addr: EndpointAddr) -> bool {
        self.local_endpoint
            .get(bind)
            .and_then(|endpoints| endpoints.get(&addr))
            .is_some_and(|sources| !sources.is_empty())
    }

    pub(crate) fn add_peer_endpoint(
        &mut self,
        endpoint: EndpointAddr,
        source: Source,
    ) -> io::Result<()> {
        match self.remote_endpoint.entry(endpoint) {
            Entry::Occupied(_) => return Err(io::Error::other("Duplicate remote endpoint")),
            Entry::Vacant(e) => {
                e.insert(source);
            }
        }
        Ok(())
    }

    pub(crate) fn remote_endpoint(&self) -> &HashMap<EndpointAddr, Source> {
        &self.remote_endpoint
    }

    pub(crate) fn local_endpoint(&self) -> Vec<(BindUri, EndpointAddr)> {
        self.local_endpoint
            .iter()
            .flat_map(|(bind, endpoints)| {
                endpoints.iter().filter_map(|(endpoint, sources)| {
                    (!sources.is_empty()).then_some((bind.clone(), *endpoint))
                })
            })
            .collect()
    }

    fn insert_local_endpoint_source(
        &mut self,
        bind: BindUri,
        endpoint: EndpointAddr,
        source: LocalEndpointSource,
    ) -> LocalEndpointEffects {
        let endpoints = self.local_endpoint.entry(bind.clone()).or_default();
        let sources = endpoints.entry(endpoint).or_default();
        let was_present = !sources.is_empty();
        if !sources.insert(source) {
            return Vec::new();
        }

        let mut effects = Vec::new();
        if !was_present {
            effects.push(LocalEndpointEffect::AddEndpoint {
                bind_uri: bind.clone(),
                endpoint,
            });
        }
        if matches!(source, LocalEndpointSource::LocationStun)
            && matches!(endpoint, EndpointAddr::Agent { .. })
        {
            effects.push(LocalEndpointEffect::AddPunchAddress {
                bind_uri: bind,
                endpoint,
            });
        }
        effects
    }

    #[allow(dead_code)]
    fn remove_current_local_endpoint_source(
        &mut self,
        bind: &BindUri,
        source: LocalEndpointSource,
    ) -> LocalEndpointEffects {
        let Some(endpoint) = self.local_endpoint.get(bind).and_then(|endpoints| {
            endpoints
                .iter()
                .find_map(|(endpoint, sources)| sources.contains(source).then_some(*endpoint))
        }) else {
            return Vec::new();
        };
        self.remove_local_endpoint_source(bind, endpoint, source)
    }

    fn remove_local_endpoint_source(
        &mut self,
        bind: &BindUri,
        endpoint: EndpointAddr,
        source: LocalEndpointSource,
    ) -> LocalEndpointEffects {
        let mut effects = Vec::new();
        let mut remove_bind = false;
        let mut removed_source = false;
        let mut remove_endpoint = false;

        if let Some(endpoints) = self.local_endpoint.get_mut(bind) {
            if let Some(sources) = endpoints.get_mut(&endpoint) {
                removed_source = sources.remove(source);
                remove_endpoint = removed_source && sources.is_empty();
            }
            if remove_endpoint {
                endpoints.remove(&endpoint);
            }
            remove_bind = endpoints.is_empty();
        }
        if remove_bind {
            self.local_endpoint.remove(bind);
        }
        if !removed_source {
            return effects;
        }

        if matches!(source, LocalEndpointSource::LocationStun)
            && matches!(endpoint, EndpointAddr::Agent { .. })
        {
            effects.push(LocalEndpointEffect::RemovePunchAddress {
                addr: endpoint.addr(),
            });
        }
        if remove_endpoint {
            effects.push(LocalEndpointEffect::RemoveEndpoint {
                bind_uri: bind.clone(),
                endpoint,
            });
        }
        effects
    }

    pub(crate) fn remove_local_address(
        &mut self,
        addr: SocketAddr,
    ) -> io::Result<RemoveAddressFrame> {
        let Some(seq_num) = self
            .local
            .iter()
            .find(|(_, (_local, frame))| *frame.deref() == addr)
            .map(|(key, _)| *key)
        else {
            tracing::debug!(target: "quic", %addr, "No matching local address to remove");
            return Err(io::Error::other("No matching local address"));
        };
        self.local.remove(&seq_num).map(|(_local, _frame)| seq_num);
        Ok(RemoveAddressFrame {
            seq_num: seq_num.into(),
        })
    }

    pub(crate) fn get_local_address(&self, seq_num: &u32) -> Option<(BindUri, AddAddressFrame)> {
        self.local.get(seq_num).cloned()
    }

    pub(crate) fn add_remote_address(&mut self, remote: AddAddressFrame) -> io::Result<()> {
        match self.remote.entry(remote.seq_num()) {
            Entry::Occupied(_) => {
                tracing::debug!(target: "quic", remote_seq_num = remote.seq_num(), "Duplicate remote address");
                return Err(io::Error::other("Duplicate remote address"));
            }
            Entry::Vacant(entry) => {
                entry.insert(remote);
            }
        }
        Ok(())
    }

    pub(crate) fn remove_remote_address(&mut self, seq_num: u32) -> Option<AddAddressFrame> {
        self.remote.remove(&seq_num)
    }

    pub(crate) fn pick_local_address(
        &self,
        remote: &AddAddressFrame,
    ) -> io::Result<(BindUri, AddAddressFrame)> {
        let mut addrs: Vec<_> = self
            .local
            .iter()
            .filter(|(_seq, (_local, frame))| {
                frame.tire() == remote.tire() && frame.is_ipv4() == remote.is_ipv4()
            })
            .map(|(_, addr)| addr.clone())
            .collect();

        if addrs.is_empty() {
            tracing::debug!(target: "quic", ?remote, "No matching local address for remote address");
            return Err(io::Error::other("No matching local address"));
        }

        const NAT_PRIORITY: [NatType; 5] = [
            NatType::FullCone,
            NatType::RestrictedCone,
            NatType::RestrictedPort,
            NatType::Dynamic,
            NatType::Symmetric,
        ];

        addrs.sort_by_key(|(_addr, frame)| {
            NAT_PRIORITY
                .iter()
                .position(|&x| x == frame.nat_type())
                .unwrap_or(usize::MAX)
        });

        let (bind, frame) = addrs
            .iter()
            .find(|(_, frame)| *frame != *remote)
            .ok_or_else(|| io::Error::other("No matching local address"))?;

        Ok((bind.clone(), *frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bind_uri() -> BindUri {
        "inet://127.0.0.1:0".parse().expect("valid bind uri")
    }

    fn direct_endpoint(port: u16) -> EndpointAddr {
        EndpointAddr::direct(format!("127.0.0.1:{port}").parse().expect("socket addr"))
    }

    #[test]
    fn remove_local_endpoint_deletes_only_explicit_source() {
        let mut book = AddressBook::default();
        let bind_uri = bind_uri();
        let endpoint = direct_endpoint(34567);

        let effects = book
            .add_local_endpoint(bind_uri.clone(), endpoint)
            .expect("explicit endpoint insert");
        assert_eq!(
            effects,
            vec![LocalEndpointEffect::AddEndpoint {
                bind_uri: bind_uri.clone(),
                endpoint,
            }]
        );
        assert!(book.has_local_endpoint(&bind_uri, endpoint));
        let duplicate = book
            .add_local_endpoint(bind_uri.clone(), endpoint)
            .expect_err("duplicate explicit endpoint should fail");
        assert_eq!(duplicate.to_string(), "Duplicate local endpoint");

        let effects = book.remove_local_endpoint(&bind_uri, endpoint);
        assert_eq!(
            effects,
            vec![LocalEndpointEffect::RemoveEndpoint {
                bind_uri: bind_uri.clone(),
                endpoint,
            }]
        );
        assert!(!book.has_local_endpoint(&bind_uri, endpoint));
        assert!(book.remove_local_endpoint(&bind_uri, endpoint).is_empty());
    }

    #[test]
    fn explicit_source_survives_location_direct_remove() {
        let mut book = AddressBook::default();
        let bind_uri = bind_uri();
        let addr: SocketAddr = "127.0.0.1:34567".parse().expect("socket addr");
        let endpoint = EndpointAddr::direct(addr);

        assert_eq!(
            book.add_local_endpoint(bind_uri.clone(), endpoint)
                .expect("explicit endpoint insert"),
            vec![LocalEndpointEffect::AddEndpoint {
                bind_uri: bind_uri.clone(),
                endpoint,
            }]
        );
        assert_eq!(
            book.upsert_direct_endpoint(bind_uri.clone(), addr),
            Vec::new()
        );
        assert!(book.remove_direct_endpoint(&bind_uri).is_empty());
        assert!(book.has_local_endpoint(&bind_uri, endpoint));
    }

    #[test]
    fn location_direct_replace_emits_remove_then_add() {
        let mut book = AddressBook::default();
        let bind_uri = bind_uri();
        let first: SocketAddr = "127.0.0.1:34567".parse().expect("socket addr");
        let second: SocketAddr = "127.0.0.1:45678".parse().expect("socket addr");
        let first_endpoint = EndpointAddr::direct(first);
        let second_endpoint = EndpointAddr::direct(second);

        assert_eq!(
            book.upsert_direct_endpoint(bind_uri.clone(), first),
            vec![LocalEndpointEffect::AddEndpoint {
                bind_uri: bind_uri.clone(),
                endpoint: first_endpoint,
            }]
        );
        assert_eq!(
            book.upsert_direct_endpoint(bind_uri.clone(), first),
            Vec::new()
        );
        assert_eq!(
            book.upsert_direct_endpoint(bind_uri.clone(), second),
            vec![
                LocalEndpointEffect::RemoveEndpoint {
                    bind_uri: bind_uri.clone(),
                    endpoint: first_endpoint,
                },
                LocalEndpointEffect::AddEndpoint {
                    bind_uri: bind_uri.clone(),
                    endpoint: second_endpoint,
                },
            ]
        );
        assert!(!book.has_local_endpoint(&bind_uri, first_endpoint));
        assert!(book.has_local_endpoint(&bind_uri, second_endpoint));
    }

    #[test]
    fn location_stun_agent_remove_emits_endpoint_and_punch_cleanup() {
        let mut book = AddressBook::default();
        let bind_uri = bind_uri();
        let agent: SocketAddr = "192.0.2.10:3478".parse().expect("socket addr");
        let outer: SocketAddr = "198.51.100.20:45678".parse().expect("socket addr");
        let endpoint = EndpointAddr::with_agent(agent, outer);

        assert_eq!(
            book.upsert_stun_endpoint(bind_uri.clone(), endpoint),
            vec![
                LocalEndpointEffect::AddEndpoint {
                    bind_uri: bind_uri.clone(),
                    endpoint,
                },
                LocalEndpointEffect::AddPunchAddress {
                    bind_uri: bind_uri.clone(),
                    endpoint,
                },
            ]
        );
        assert_eq!(
            book.upsert_stun_endpoint(bind_uri.clone(), endpoint),
            Vec::new()
        );
        assert_eq!(
            book.remove_stun_endpoint(&bind_uri),
            vec![
                LocalEndpointEffect::RemovePunchAddress { addr: outer },
                LocalEndpointEffect::RemoveEndpoint {
                    bind_uri: bind_uri.clone(),
                    endpoint,
                },
            ]
        );
        assert!(!book.has_local_endpoint(&bind_uri, endpoint));
    }

    #[test]
    fn explicit_agent_endpoint_survives_stun_remove_but_punch_address_is_removed() {
        let mut book = AddressBook::default();
        let bind_uri = bind_uri();
        let agent: SocketAddr = "192.0.2.10:3478".parse().expect("socket addr");
        let outer: SocketAddr = "198.51.100.20:45678".parse().expect("socket addr");
        let endpoint = EndpointAddr::with_agent(agent, outer);

        book.add_local_endpoint(bind_uri.clone(), endpoint)
            .expect("explicit endpoint insert");
        assert_eq!(
            book.upsert_stun_endpoint(bind_uri.clone(), endpoint),
            vec![LocalEndpointEffect::AddPunchAddress {
                bind_uri: bind_uri.clone(),
                endpoint,
            }]
        );

        assert_eq!(
            book.remove_stun_endpoint(&bind_uri),
            vec![LocalEndpointEffect::RemovePunchAddress { addr: outer }]
        );
        assert!(book.has_local_endpoint(&bind_uri, endpoint));
    }

    #[test]
    fn close_tracked_bind_uri_keeps_explicit_endpoint() {
        let mut book = AddressBook::default();
        let bind_uri = bind_uri();
        let explicit = direct_endpoint(34567);
        let direct: SocketAddr = "127.0.0.1:45678".parse().expect("socket addr");
        let direct_endpoint = EndpointAddr::direct(direct);

        book.add_local_endpoint(bind_uri.clone(), explicit)
            .expect("explicit endpoint insert");
        book.upsert_direct_endpoint(bind_uri.clone(), direct);

        assert_eq!(
            book.close_tracked_bind_uri(&bind_uri),
            vec![LocalEndpointEffect::RemoveEndpoint {
                bind_uri: bind_uri.clone(),
                endpoint: direct_endpoint,
            }]
        );
        assert!(book.has_local_endpoint(&bind_uri, explicit));
        assert!(!book.has_local_endpoint(&bind_uri, direct_endpoint));
    }

    #[test]
    fn remove_local_address_returns_remove_address_frame() {
        let mut book = AddressBook::default();
        let bind_uri = bind_uri();
        let addr: SocketAddr = "127.0.0.1:34567".parse().expect("socket addr");

        book.add_local_address(bind_uri, addr, 0, NatType::FullCone)
            .expect("local address insert");
        let frame = book
            .remove_local_address(addr)
            .expect("remove address frame");
        assert_eq!(frame.seq_num.into_u64(), 0);
        assert!(book.remove_local_address(addr).is_err());
    }
}
