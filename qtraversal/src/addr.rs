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
use qinterface::{bind_uri::BindUri, component::local_endpoint::InterfaceEndpointKey};
use qresolve::Source;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEndpointDelta {
    added: Option<(BindUri, EndpointAddr)>,
    removed: Option<(BindUri, EndpointAddr)>,
}

impl LocalEndpointDelta {
    pub fn none() -> Self {
        Self {
            added: None,
            removed: None,
        }
    }

    pub fn added_endpoint(&self) -> Option<(BindUri, EndpointAddr)> {
        self.added.clone()
    }

    pub fn removed_endpoint(&self) -> Option<(BindUri, EndpointAddr)> {
        self.removed.clone()
    }

    fn replace(
        bind_uri: BindUri,
        old_endpoint: Option<EndpointAddr>,
        new_endpoint: Option<EndpointAddr>,
    ) -> Self {
        Self {
            added: new_endpoint.map(|endpoint| (bind_uri.clone(), endpoint)),
            removed: old_endpoint.map(|endpoint| (bind_uri, endpoint)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseLocalEndpointsDelta {
    removed: Vec<(InterfaceEndpointKey, EndpointAddr)>,
}

impl IntoIterator for CloseLocalEndpointsDelta {
    type Item = (InterfaceEndpointKey, EndpointAddr);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.removed.into_iter()
    }
}

#[derive(Default)]
pub struct AddressBook {
    local: HashMap<u32, (BindUri, AddAddressFrame)>,
    remote: HashMap<u32, AddAddressFrame>,
    local_endpoint: HashMap<BindUri, HashMap<InterfaceEndpointKey, EndpointAddr>>,
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

    pub(crate) fn upsert_local_endpoint(
        &mut self,
        bind: BindUri,
        key: InterfaceEndpointKey,
        endpoint: EndpointAddr,
    ) -> LocalEndpointDelta {
        let endpoints = self.local_endpoint.entry(bind.clone()).or_default();
        match endpoints.insert(key, endpoint) {
            Some(old) if old == endpoint => LocalEndpointDelta::none(),
            Some(old) => LocalEndpointDelta::replace(bind, Some(old), Some(endpoint)),
            None => LocalEndpointDelta::replace(bind, None, Some(endpoint)),
        }
    }

    pub(crate) fn remove_local_endpoint(
        &mut self,
        bind: &BindUri,
        key: &InterfaceEndpointKey,
    ) -> LocalEndpointDelta {
        let mut remove_bind = false;
        let removed = self.local_endpoint.get_mut(bind).and_then(|endpoints| {
            let removed = endpoints.remove(key);
            remove_bind = endpoints.is_empty();
            removed
        });
        if remove_bind {
            self.local_endpoint.remove(bind);
        }
        LocalEndpointDelta::replace(bind.clone(), removed, None)
    }

    pub(crate) fn close_local_endpoints(&mut self, bind: &BindUri) -> CloseLocalEndpointsDelta {
        let removed = self
            .local_endpoint
            .remove(bind)
            .map(|endpoints| endpoints.into_iter().collect())
            .unwrap_or_default();
        CloseLocalEndpointsDelta { removed }
    }

    pub(crate) fn has_local_endpoint(
        &self,
        bind: &BindUri,
        key: InterfaceEndpointKey,
        endpoint: EndpointAddr,
    ) -> bool {
        self.local_endpoint
            .get(bind)
            .and_then(|endpoints| endpoints.get(&key))
            .is_some_and(|current| *current == endpoint)
    }

    pub(crate) fn local_endpoint(&self) -> impl Iterator<Item = (BindUri, EndpointAddr)> + '_ {
        self.local_endpoint.iter().flat_map(|(bind, endpoints)| {
            endpoints
                .values()
                .copied()
                .map(|endpoint| (bind.clone(), endpoint))
        })
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
    use qinterface::component::local_endpoint::InterfaceEndpointKey;

    use super::*;

    fn bind_uri() -> BindUri {
        "inet://127.0.0.1:0".parse().expect("valid bind uri")
    }

    fn socket(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().expect("socket addr")
    }

    fn direct_endpoint(port: u16) -> EndpointAddr {
        EndpointAddr::direct(socket(port))
    }

    #[test]
    fn keyed_upsert_replaces_old_endpoint_without_remove_effect() {
        let mut book = AddressBook::default();
        let bind = bind_uri();
        let first = direct_endpoint(10001);
        let second = direct_endpoint(10002);

        let first_delta =
            book.upsert_local_endpoint(bind.clone(), InterfaceEndpointKey::Direct, first);
        assert_eq!(first_delta.added_endpoint(), Some((bind.clone(), first)));
        assert_eq!(first_delta.removed_endpoint(), None);
        assert!(book.has_local_endpoint(&bind, InterfaceEndpointKey::Direct, first));

        let same_delta =
            book.upsert_local_endpoint(bind.clone(), InterfaceEndpointKey::Direct, first);
        assert_eq!(same_delta, LocalEndpointDelta::none());

        let replace_delta =
            book.upsert_local_endpoint(bind.clone(), InterfaceEndpointKey::Direct, second);
        assert_eq!(replace_delta.added_endpoint(), Some((bind.clone(), second)));
        assert_eq!(
            replace_delta.removed_endpoint(),
            Some((bind.clone(), first))
        );
        assert!(!book.has_local_endpoint(&bind, InterfaceEndpointKey::Direct, first));
        assert!(book.has_local_endpoint(&bind, InterfaceEndpointKey::Direct, second));
    }

    #[test]
    fn keyed_remove_and_close_return_removed_endpoint_only_for_internal_cleanup() {
        let mut book = AddressBook::default();
        let bind = bind_uri();
        let direct = direct_endpoint(10003);
        let agent_addr = socket(20004);
        let agent = EndpointAddr::with_agent(agent_addr, socket(30004));

        book.upsert_local_endpoint(bind.clone(), InterfaceEndpointKey::Direct, direct);
        book.upsert_local_endpoint(bind.clone(), InterfaceEndpointKey::Agent(agent_addr), agent);

        let remove_delta = book.remove_local_endpoint(&bind, &InterfaceEndpointKey::Direct);
        assert_eq!(remove_delta.added_endpoint(), None);
        assert_eq!(
            remove_delta.removed_endpoint(),
            Some((bind.clone(), direct))
        );
        assert!(!book.has_local_endpoint(&bind, InterfaceEndpointKey::Direct, direct));

        let closed = book
            .close_local_endpoints(&bind)
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(
            closed,
            vec![(InterfaceEndpointKey::Agent(agent_addr), agent)]
        );
        assert!(!book.has_local_endpoint(&bind, InterfaceEndpointKey::Agent(agent_addr), agent));
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
