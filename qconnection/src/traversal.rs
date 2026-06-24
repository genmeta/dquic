use qbase::{
    frame::{PunchHelloFrame, ReliableFrame, io::ReceiveFrame},
    net::{
        addr::EndpointAddr,
        route::{Link, Pathway},
        tx::Signals,
    },
    packet::{ProductHeader, header::short::OneRttHeader},
};
use qinterface::{
    bind_uri::BindUri,
    component::{local_endpoint::InterfaceEndpointKey, route::Way},
};
use qtraversal::punch::puncher::{LocalEndpointPathChange, LocalEndpointPathChanges};

use super::Components;
use crate::CidRegistry;

impl ReceiveFrame<(BindUri, Pathway, Link, ReliableFrame)> for Components {
    type Output = ();
    fn recv_frame(
        &self,
        frame: (BindUri, Pathway, Link, ReliableFrame),
    ) -> Result<Self::Output, qbase::error::Error> {
        self.puncher.recv_frame(frame)
    }
}

impl ReceiveFrame<(BindUri, Pathway, Link, PunchHelloFrame)> for Components {
    type Output = ();

    fn recv_frame(
        &self,
        frame: (BindUri, Pathway, Link, PunchHelloFrame),
    ) -> Result<Self::Output, qbase::error::Error> {
        self.puncher.recv_frame(frame)
    }
}

impl Components {
    fn apply_local_endpoint_path_changes(&self, changes: LocalEndpointPathChanges) {
        for change in changes {
            match change {
                LocalEndpointPathChange::AddPath(way) => {
                    let _ = self.add_path(way);
                }
                _ => {}
            }
        }
    }

    pub(crate) fn upsert_local_endpoint(
        &self,
        bind_uri: BindUri,
        key: InterfaceEndpointKey,
        endpoint: EndpointAddr,
    ) {
        let changes = self.puncher.upsert_local_endpoint(bind_uri, key, endpoint);
        self.apply_local_endpoint_path_changes(changes);
    }

    pub(crate) fn remove_local_endpoint(&self, bind_uri: &BindUri, key: &InterfaceEndpointKey) {
        let changes = self.puncher.remove_local_endpoint(bind_uri, key);
        self.apply_local_endpoint_path_changes(changes);
    }

    pub(crate) fn close_local_endpoints(&self, bind_uri: &BindUri) {
        let changes = self.puncher.close_local_endpoints(bind_uri);
        self.apply_local_endpoint_path_changes(changes);
    }

    // 添加对端直通地址，可以直接新建 path
    pub fn add_peer_endpoint(&self, addr: EndpointAddr, source: qresolve::Source) {
        tracing::trace!(target: "quic", %addr, ?source, "add peer endpoint");
        let source_for_log = source.clone();
        match self.puncher.add_peer_endpoint(addr, source) {
            Ok(ways) => {
                tracing::trace!(
                    target: "quic",
                    %addr,
                    source = ?source_for_log,
                    path_count = ways.len(),
                    paths = ?ways,
                    "resolved peer endpoint paths"
                );
                ways.into_iter().for_each(|(bind_uri, link, pathway)| {
                    let way: Way = (bind_uri, pathway, link);
                    let _ = self.add_path(way);
                });
            }
            Err(error) => {
                tracing::warn!(target: "quic", ?error, "add peer endpoint failed");
            }
        }
    }
}

#[derive(Clone)]
pub struct PunchTransaction {
    cid_registry: CidRegistry,
}

impl PunchTransaction {
    pub(crate) fn new(cid_registry: CidRegistry) -> Self {
        Self { cid_registry }
    }
}

impl ProductHeader<OneRttHeader> for PunchTransaction {
    fn new_header(&self) -> Result<OneRttHeader, Signals> {
        Ok(OneRttHeader::new(
            false.into(),
            self.cid_registry
                .remote
                .latest_dcid()
                .ok_or(Signals::CONNECTION_ID)?,
        ))
    }
}

#[cfg(test)]
mod local_endpoint_ingest_tests {
    use qinterface::component::local_endpoint::InterfaceEndpointKey;

    #[test]
    fn production_traversal_no_longer_parses_location_events() {
        let source = include_str!("traversal.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module boundary");

        assert!(!production.contains(concat!("Address", "Event")));
        assert!(!production.contains(concat!("LocalEndpoint", "Set")));
        assert!(!production.contains(concat!("subscribe_local_", "address_events")));
        assert!(!production.contains(concat!("add_local_", "punch_address")));
    }

    #[test]
    fn local_endpoint_remove_is_not_a_path_delete_effect() {
        let source = include_str!("traversal.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module boundary");

        assert!(!production.contains("remove_paths_for_local_endpoint"));
        assert!(production.contains("LocalEndpointPathChange::AddPath"));
    }

    #[test]
    fn interface_endpoint_key_is_available_to_connection_ingest() {
        let key = InterfaceEndpointKey::Direct;
        assert!(matches!(key, InterfaceEndpointKey::Direct));
    }
}
