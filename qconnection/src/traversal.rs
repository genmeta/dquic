use std::{io, net::SocketAddr};

use futures::{StreamExt, stream::FuturesUnordered};
use qbase::{
    frame::{PunchHelloFrame, ReliableFrame, io::ReceiveFrame},
    net::{
        addr::EndpointAddr,
        route::{Link, Pathway},
        tx::Signals,
    },
    packet::{ProductHeader, header::short::OneRttHeader},
};
use qevent::telemetry::Instrument;
use qinterface::{bind_uri::BindUri, component::location::AddressEvent};
use qtraversal::{
    addr::LocalEndpointEffect,
    nat::client::{ClientLocationData, StunClientsComponent},
    punch::puncher::LocalEndpointChanges,
};
use tracing::Instrument as _;

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
    fn apply_local_endpoint_changes(&self, changes: LocalEndpointChanges) {
        for way in changes.ways {
            let _ = self.add_path(way.0, way.1, way.2);
        }

        for effect in changes.effects {
            match effect {
                LocalEndpointEffect::AddEndpoint { .. } => {}
                LocalEndpointEffect::RemoveEndpoint { endpoint, .. } => {
                    self.remove_paths_for_local_endpoint(endpoint);
                }
                LocalEndpointEffect::AddPunchAddress { bind_uri, endpoint } => {
                    if let Err(error) = self.add_local_punch_address(bind_uri, endpoint) {
                        tracing::debug!(target: "quic", ?error, "failed to add local punch address");
                    }
                }
                LocalEndpointEffect::RemovePunchAddress { addr } => self.remove_address(addr),
            }
        }
    }

    fn remove_paths_for_local_endpoint(&self, endpoint: EndpointAddr) {
        let pathways = self
            .paths
            .paths::<Vec<_>>()
            .into_iter()
            .filter_map(|(pathway, _path)| (pathway.local() == endpoint).then_some(pathway))
            .collect::<Vec<_>>();
        for pathway in pathways {
            self.del_path(&pathway);
        }
    }

    fn upsert_tracked_direct_endpoint(&self, bind_uri: BindUri, addr: SocketAddr) {
        let changes = self.puncher.upsert_direct_endpoint(bind_uri, addr);
        self.apply_local_endpoint_changes(changes);
    }

    fn remove_tracked_direct_endpoint(&self, bind_uri: &BindUri) {
        let changes = self.puncher.remove_direct_endpoint(bind_uri);
        self.apply_local_endpoint_changes(changes);
    }

    fn upsert_tracked_stun_endpoint(&self, bind_uri: BindUri, endpoint: EndpointAddr) {
        let changes = self.puncher.upsert_stun_endpoint(bind_uri, endpoint);
        self.apply_local_endpoint_changes(changes);
    }

    fn remove_tracked_stun_endpoint(&self, bind_uri: &BindUri) {
        let changes = self.puncher.remove_stun_endpoint(bind_uri);
        self.apply_local_endpoint_changes(changes);
    }

    fn close_tracked_bind_uri(&self, bind_uri: &BindUri) {
        let changes = self.puncher.close_tracked_bind_uri(bind_uri);
        self.apply_local_endpoint_changes(changes);
    }

    pub fn subscribe_local_address(&self) {
        let mut observer = self.locations.subscribe();
        let conn = self.clone();

        let future = async move {
            loop {
                tokio::select! {
                    _ =  conn.conn_state.terminated() => break,
                    address_event = observer.recv() => {
                        match address_event {
                            Some((bind_uri, event)) => conn.handle_local_address_event(bind_uri, event),
                            None => break,
                        }
                    }
                }
            }
        };
        // Terminates when the connection is closed or the observer channel drops.
        tokio::spawn(future.instrument_in_current().in_current_span());
    }

    fn handle_local_address_event(&self, bind_uri: BindUri, event: AddressEvent) {
        let event = match event.downcast::<io::Result<SocketAddr>>() {
            Ok(event) => {
                self.handle_direct_address_event(bind_uri, event);
                return;
            }
            Err(event) => event,
        };

        match event.downcast::<ClientLocationData>() {
            Ok(event) => self.handle_stun_address_event(bind_uri, event),
            Err(AddressEvent::Upsert(data)) => {
                let type_id = data.as_ref().type_id();
                tracing::trace!(target: "quic", ?type_id, "ignored unknown local address upsert event");
            }
            Err(AddressEvent::Remove(type_id)) => {
                tracing::trace!(target: "quic", ?type_id, "ignored unknown local address remove event");
            }
            Err(AddressEvent::Closed) => self.close_tracked_bind_uri(&bind_uri),
        }
    }

    fn handle_direct_address_event(
        &self,
        bind_uri: BindUri,
        event: AddressEvent<io::Result<SocketAddr>>,
    ) {
        match event {
            AddressEvent::Upsert(data) => match data.as_ref() {
                Ok(addr) => self.upsert_tracked_direct_endpoint(bind_uri, *addr),
                Err(error) => {
                    tracing::debug!(target: "quic", bind_uri = %bind_uri, ?error, "direct local address update failed");
                    self.remove_tracked_direct_endpoint(&bind_uri);
                }
            },
            AddressEvent::Remove(_type_id) => self.remove_tracked_direct_endpoint(&bind_uri),
            AddressEvent::Closed => self.close_tracked_bind_uri(&bind_uri),
        }
    }

    fn handle_stun_address_event(
        &self,
        bind_uri: BindUri,
        event: AddressEvent<ClientLocationData>,
    ) {
        match event {
            AddressEvent::Upsert(data) => match data.as_ref() {
                Ok(endpoint) => self.upsert_tracked_stun_endpoint(bind_uri, *endpoint),
                Err(error) => {
                    tracing::debug!(target: "quic", bind_uri = %bind_uri, ?error, "stun local address update failed");
                    self.remove_tracked_stun_endpoint(&bind_uri);
                }
            },
            AddressEvent::Remove(_type_id) => self.remove_tracked_stun_endpoint(&bind_uri),
            AddressEvent::Closed => self.close_tracked_bind_uri(&bind_uri),
        }
    }

    // 添加本地直通地址 可以直接新建 path
    pub fn add_local_endpoint(&self, bind: BindUri, addr: EndpointAddr) {
        tracing::trace!(target: "quic", bind_uri = %bind, %addr, "add local endpoint");
        let bind_uri = bind.clone();
        match self.puncher.add_local_endpoint_changes(bind, addr) {
            Ok(changes) => {
                tracing::trace!(
                    target: "quic",
                    bind_uri = %bind_uri,
                    %addr,
                    path_count = changes.ways.len(),
                    paths = ?changes.ways,
                    "resolved local endpoint paths"
                );
                self.apply_local_endpoint_changes(changes);
            }
            Err(error) => {
                tracing::debug!(target: "quic", ?error, "add local endpoint failed");
            }
        }
    }

    pub fn remove_local_endpoint(&self, bind: &BindUri, endpoint: EndpointAddr) {
        let changes = self.puncher.remove_local_endpoint_changes(bind, endpoint);
        self.apply_local_endpoint_changes(changes);
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
                ways.into_iter().for_each(|way| {
                    let _ = self.add_path(way.0, way.1, way.2);
                });
            }
            Err(error) => {
                tracing::warn!(target: "quic", ?error, "Add peer endpoint failed");
            }
        }
    }

    // 添加本地直连地址，用于打洞，不能直接新建路径
    pub fn add_local_punch_address(
        &self,
        bind_uri: BindUri,
        endpoint_addr: EndpointAddr,
    ) -> io::Result<()> {
        let iface = self
            .interfaces
            .borrow(&bind_uri)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface not found"))?;

        let local_addr = endpoint_addr.addr();
        let conn = self.clone();

        let tasks = iface.with_component(|clinets: &StunClientsComponent| {
            clinets.with_clients(|map| {
                // workaround. clippy issue: https://github.com/rust-lang/rust-clippy/issues/16428
                #[allow(clippy::redundant_iter_cloned)]
                map.values()
                    .cloned()
                    .map(|client| async move { client.nat_type().await })
                    .collect::<FuturesUnordered<_>>()
            })
        })?;

        let Some(mut tasks) = tasks else {
            return Ok(());
        };

        tokio::spawn(
            async move {
                while let Some(result) = tasks.next().await {
                    let Ok(nat_type) = result else {
                        continue;
                    };
                    if let Err(error) = conn.puncher.add_local_address_if_endpoint_present(
                        bind_uri.clone(),
                        endpoint_addr,
                        local_addr,
                        nat_type,
                        0,
                    ) {
                        tracing::debug!(target: "quic", ?error, "failed to add local punch address");
                    }
                }
            }
            .instrument_in_current()
            .in_current_span(),
        );
        Ok(())
    }

    pub fn remove_address(&self, addr: SocketAddr) {
        let _ = self.puncher.remove_local_address(addr);
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
