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
use qtraversal::nat::client::{ClientLocationData, StunClientsComponent};
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
    pub fn subscribe_local_address(&self) {
        let mut observer = self.locations.subscribe();
        let conn = self.clone();

        let future = async move {
            let handle_address_event = |(bind_uri, event): (BindUri, AddressEvent)| {
                let event = match event.downcast::<io::Result<SocketAddr>>() {
                    Ok(AddressEvent::Upsert(data)) => {
                        // on error: delect from address book
                        // THINK: Err和remove的异同？
                        let Ok(bound_addr) = data.as_ref() else {
                            return;
                        };
                        let endpoint_addr = EndpointAddr::direct(*bound_addr);
                        conn.add_local_endpoint(bind_uri, endpoint_addr);
                        return;
                    }
                    Ok(AddressEvent::Remove(_type_id)) => return,
                    Ok(AddressEvent::Closed) => return,
                    Err(event) => event,
                };
                let _event = match event.downcast::<ClientLocationData>() {
                    Ok(AddressEvent::Upsert(data)) => {
                        let Ok(endpoint_addr) = data.as_ref() else {
                            return;
                        };
                        conn.add_local_endpoint(bind_uri.clone(), *endpoint_addr);
                        if matches!(*endpoint_addr, EndpointAddr::Agent { .. }) {
                            _ = conn.add_local_punch_address(bind_uri.clone(), *endpoint_addr);
                        }
                        return;
                    }
                    Ok(AddressEvent::Remove(_type_id)) => return,
                    Ok(AddressEvent::Closed) => return,
                    Err(_event) => return,
                };
            };

            loop {
                tokio::select! {
                    _ =  conn.conn_state.terminated() => break,
                    address_event = observer.recv() => {
                        match address_event {
                            Some(event) => handle_address_event(event),
                            None => break,
                        }
                    }
                }
            }
        };
        // Terminates when the connection is closed or the observer channel drops.
        tokio::spawn(future.instrument_in_current().in_current_span());
    }

    // 添加本地直通地址 可以直接新建 path
    pub fn add_local_endpoint(&self, bind: BindUri, addr: EndpointAddr) {
        tracing::trace!(target: "quic", bind_uri = %bind, %addr,"add local endpoint");
        let bind_uri = bind.clone();
        match self.puncher.add_local_endpoint(bind, addr) {
            Ok(ways) => {
                let ways: Vec<(BindUri, Link, qtraversal::PathWay)> = ways;
                tracing::trace!(
                    target: "quic",
                    bind_uri = %bind_uri,
                    %addr,
                    path_count = ways.len(),
                    paths = ?ways,
                    "resolved local endpoint paths"
                );
                ways.into_iter().for_each(|way| {
                    let _ = self.add_path(way.0, way.1, way.2);
                });
            }
            Err(error) => {
                tracing::debug!(target: "quic", ?error, "Add local endpoint failed");
            }
        }
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
                    if let Ok(nat_type) = result {
                        _ = conn.puncher.add_local_address(
                            bind_uri.clone(),
                            local_addr,
                            nat_type,
                            0,
                        );
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
