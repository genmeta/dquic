use std::{
    collections::HashSet,
    io,
    net::SocketAddr,
    ops::Deref,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use dashmap::{DashMap, Entry};
use qbase::{
    frame::{
        AddAddressFrame, PunchDoneFrame, PunchHelloFrame, PunchMeNowFrame, ReliableFrame,
        RemoveAddressFrame,
        io::{ReceiveFrame, SendFrame},
    },
    net::{
        NatType,
        addr::EndpointAddr,
        route::{Line, Link, Pathway, Route},
        tx::Signals,
    },
    packet::{
        Package, PacketSpace, ProductHeader,
        header::short::OneRttHeader,
        io::{AssemblePacket, Packages, PadTo20},
    },
};
use qevent::telemetry::Instrument;
use qinterface::{
    Interface, WeakInterface,
    bind_uri::BindUri,
    component::{
        local_endpoint::InterfaceEndpointKey,
        route::{InvalidWay, QuicRouter, QuicRouterComponent, Way, validate_outbound_candidate},
    },
    io::{IO, IoExt, ProductIO},
    manager::InterfaceManager,
};
use tokio::{task::AbortHandle, time::timeout};
use tracing::Instrument as _;

use crate::{
    addr::AddressBook,
    nat::{
        client::{StunClientComponent, StunClientsComponent},
        router::StunRouterComponent,
    },
    punch::{
        predictor::{PacketSendFn, PortPredictor},
        tx::{AsPunchId, PunchId, Transaction},
    },
    route::ReceiveAndDeliverPacket,
};

type StunClient<I = WeakInterface> = crate::nat::client::StunClient<I>;

fn interface_endpoint_key(endpoint: EndpointAddr) -> InterfaceEndpointKey {
    match endpoint {
        EndpointAddr::Direct { .. } => InterfaceEndpointKey::Direct,
        EndpointAddr::Agent { agent, .. } => InterfaceEndpointKey::Agent(agent),
    }
}

#[derive(Debug, thiserror::Error)]
enum ResolvePathError {
    #[error(transparent)]
    InvalidWay(#[from] InvalidWay),
    #[error("bind URI does not match resolver source constraint")]
    SourceConstraint,
    #[error("unsupported endpoint type combination for punching")]
    UnsupportedEndpointPair,
    #[error(transparent)]
    Io(#[from] io::Error),
}

fn validate_endpoint_pair(
    local: EndpointAddr,
    remote: EndpointAddr,
) -> Result<(), ResolvePathError> {
    match (local, remote) {
        (EndpointAddr::Direct { .. }, EndpointAddr::Direct { .. })
        | (EndpointAddr::Agent { .. }, EndpointAddr::Agent { .. }) => Ok(()),
        _ => Err(ResolvePathError::UnsupportedEndpointPair),
    }
}

fn build_validated_way(
    bind: &BindUri,
    local: EndpointAddr,
    remote: EndpointAddr,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> Result<(BindUri, Link, Pathway), InvalidWay> {
    let link = Link::new(local_addr, remote_addr);
    let pathway = Pathway::new(local, remote);
    let way = (bind.clone(), pathway, link);
    validate_outbound_candidate(&way)?;
    Ok((way.0, way.2, way.1))
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct LocalEndpointAdvertisementResource {
    bind_uri: BindUri,
    key: InterfaceEndpointKey,
    endpoint: EndpointAddr,
    seq_num: u32,
    advertised_bind: BindUri,
    advertised_addr: SocketAddr,
    temporary_iface: Option<Interface>,
}

impl LocalEndpointAdvertisementResource {
    fn new(
        bind_uri: BindUri,
        key: InterfaceEndpointKey,
        endpoint: EndpointAddr,
        frame: &AddAddressFrame,
        advertised_bind: BindUri,
        temporary_iface: Option<Interface>,
    ) -> Self {
        Self {
            bind_uri,
            key,
            endpoint,
            seq_num: frame.seq_num(),
            advertised_bind,
            advertised_addr: *frame.deref(),
            temporary_iface,
        }
    }

    #[cfg(test)]
    fn new_for_test(
        bind_uri: BindUri,
        key: InterfaceEndpointKey,
        endpoint: EndpointAddr,
        seq_num: u32,
        advertised_bind: BindUri,
        advertised_addr: SocketAddr,
    ) -> Self {
        Self {
            bind_uri,
            key,
            endpoint,
            seq_num,
            advertised_bind,
            advertised_addr,
            temporary_iface: None,
        }
    }

    #[cfg(test)]
    fn bind_uri(&self) -> &BindUri {
        &self.bind_uri
    }

    #[cfg(test)]
    fn key(&self) -> InterfaceEndpointKey {
        self.key
    }

    #[cfg(test)]
    fn endpoint(&self) -> EndpointAddr {
        self.endpoint
    }

    #[cfg(test)]
    fn seq_num(&self) -> u32 {
        self.seq_num
    }

    fn advertised_addr(&self) -> SocketAddr {
        self.advertised_addr
    }
}
// type StunProtocol<IO = WeakQuicInterface> = crate::nat::protocol::StunProtocol<I>;

// TTL
const HELLO_TTL: u8 = 64;
const DEFAULT_PROBE_ID: u32 = 0;
#[cfg(any(test, feature = "test-ttl"))]
pub const KNOCK_TTL: u8 = 1;
#[cfg(not(any(test, feature = "test-ttl")))]
pub const KNOCK_TTL: u8 = 5;

// Timeout
const KNOCK_TIMEOUT: Duration = Duration::from_millis(100);
const PUNCH_TIMEOUT: Duration = Duration::from_secs(3);
const PUNCH_ME_NOW_TIMEOUT: Duration = Duration::from_secs(1);
const COLLISION_TIMEOUT: Duration = Duration::from_secs(3);
const PUNCH_DONE_CONFIRM_INTERVAL: Duration = Duration::from_millis(30);
// Birthday attack timeout: must exceed PortPredictor's full run time (~6s for 300 probes × 20ms)
const BIRTHDAY_TIMEOUT: Duration = Duration::from_secs(8);

// Quantity
const MAX_RETRIES: usize = 5;
const PUNCH_DONE_CONFIRM_RETRIES: usize = 3;
const COLLISION_PORTS: u32 = 800;
const PUNCHER_LOCAL_SHARDS: usize = 2;

fn direct_punch_done_response(link: Link, hello: &PunchHelloFrame) -> (Link, PunchDoneFrame) {
    (link, PunchDoneFrame::respond_to(hello))
}

pub struct ArcPuncher<TX, PH, S>(Arc<Puncher<TX, PH, S>>);

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocalEndpointPathChange {
    AddPath(Way),
}

#[derive(Debug, Default)]
pub struct LocalEndpointPathChanges {
    changes: Vec<LocalEndpointPathChange>,
}

impl LocalEndpointPathChanges {
    pub fn new(changes: Vec<LocalEndpointPathChange>) -> Self {
        Self { changes }
    }
}

impl IntoIterator for LocalEndpointPathChanges {
    type Item = LocalEndpointPathChange;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.changes.into_iter()
    }
}

impl<TX, PH, S> Clone for ArcPuncher<TX, PH, S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<TX, PH, S> ArcPuncher<TX, PH, S>
where
    TX: SendFrame<ReliableFrame> + Send + Sync + Clone + 'static,
    PH: ProductHeader<OneRttHeader> + Send + Sync + 'static,
    S: PacketSpace<OneRttHeader> + Send + Sync + 'static,
{
    pub fn new(
        broker: TX,
        product_header: PH,
        packet_space: Arc<S>,
        ifaces: Arc<InterfaceManager>,
        iface_factory: Arc<dyn ProductIO>,
        quic_router: Arc<QuicRouter>,
        stun_servers: Arc<[SocketAddr]>,
    ) -> Self {
        Self(Arc::new(Puncher::new(
            broker,
            product_header,
            packet_space,
            ifaces,
            iface_factory,
            quic_router,
            stun_servers,
        )))
    }
}

pub struct Puncher<TX, PH, S> {
    transaction: DashMap<PunchId, (AbortHandle, Arc<Transaction>)>,
    punch_history: DashMap<PunchId, ()>,
    product_header: PH,
    packet_space: Arc<S>,
    ifaces: Arc<InterfaceManager>,
    iface_factory: Arc<dyn ProductIO>,
    quic_router: Arc<QuicRouter>,
    stun_servers: Arc<[SocketAddr]>,
    address_book: Mutex<AddressBook>,
    local_endpoint_advertisements:
        DashMap<(BindUri, InterfaceEndpointKey), LocalEndpointAdvertisementResource>,
    punch_ifaces: DashMap<BindUri, Interface>,
    broker: TX,
}

impl<TX, PH, S> Puncher<TX, PH, S>
where
    TX: SendFrame<ReliableFrame> + Send + Sync + Clone + 'static,
    PH: ProductHeader<OneRttHeader> + Send + Sync + 'static,
    S: PacketSpace<OneRttHeader> + Send + Sync + 'static,
{
    pub fn new(
        broker: TX,
        product_header: PH,
        packet_space: Arc<S>,
        ifaces: Arc<InterfaceManager>,
        iface_factory: Arc<dyn ProductIO>,
        quic_router: Arc<QuicRouter>,
        stun_servers: Arc<[SocketAddr]>,
    ) -> Self {
        Self {
            transaction: DashMap::with_shard_amount(PUNCHER_LOCAL_SHARDS),
            punch_history: DashMap::with_shard_amount(PUNCHER_LOCAL_SHARDS),
            product_header,
            packet_space,
            ifaces,
            iface_factory,
            quic_router,
            stun_servers,
            address_book: Mutex::new(AddressBook::default()),
            local_endpoint_advertisements: DashMap::new(),
            punch_ifaces: DashMap::with_shard_amount(PUNCHER_LOCAL_SHARDS),
            broker,
        }
    }

    pub async fn send_packet<P>(
        &self,
        iface: &(impl IO + ?Sized),
        link: Link,
        ttl: u8,
        packages: P,
    ) -> io::Result<()>
    where
        P: for<'b> Package<S::PacketAssembler<'b>>,
        PadTo20: for<'b> Package<S::PacketAssembler<'b>>,
    {
        let mut buffer = [0; 128];
        let sent_bytes = (|| {
            let mut packet = self
                .packet_space
                .new_packet(self.product_header.new_header()?, &mut buffer)?;
            packet.assemble_packet(&mut Packages((packages, PadTo20)))?;
            let (sent_bytes, _props) = packet.encrypt_and_protect_packet();
            Result::<_, Signals>::Ok(sent_bytes)
        })()
        .map_err(|s| io::Error::other(format!("Failed to assemble packet: {s:?}")))?;

        let line = Line::new(link, ttl, None, sent_bytes as u16);
        let route = Route::new(link.into(), line);
        iface
            .sendmmsg(&[io::IoSlice::new(&buffer[..sent_bytes])], route)
            .await
    }

    async fn send_direct_punch_done_with_retry(
        &self,
        iface: &(impl IO + ?Sized),
        link: Link,
        frame: PunchDoneFrame,
    ) where
        PunchDoneFrame: for<'b> Package<S::PacketAssembler<'b>>,
        PadTo20: for<'b> Package<S::PacketAssembler<'b>>,
    {
        for attempt in 0..PUNCH_DONE_CONFIRM_RETRIES {
            if let Err(error) = self.send_packet(iface, link, HELLO_TTL, frame).await {
                tracing::debug!(target: "punch", %link, ?error, "failed to send direct PunchDone confirmation");
            }
            if attempt + 1 < PUNCH_DONE_CONFIRM_RETRIES {
                tokio::time::sleep(PUNCH_DONE_CONFIRM_INTERVAL).await;
            }
        }
    }

    async fn collision(
        &self,
        iface: &Interface,
        link: Link,
        punch_id: PunchId,
        ttl: u8,
    ) -> io::Result<()>
    where
        PadTo20: for<'b> Package<S::PacketAssembler<'b>>,
        PunchHelloFrame: for<'b> Package<S::PacketAssembler<'b>>,
    {
        tracing::debug!(target: "punch", %punch_id, %link, ttl, "starting collision attack");
        let mut random_ports = HashSet::new();
        let dst = link.dst;
        let ip = dst.ip();
        while random_ports.len() < COLLISION_PORTS as usize {
            let port = rand::random::<u16>() % (u16::MAX - 1024) + 1024;
            let dst = SocketAddr::new(ip, port);
            if !random_ports.insert(port) {
                continue;
            }
            let link = Link::new(link.src, dst);
            let frame =
                PunchHelloFrame::new(punch_id.local_seq, punch_id.remote_seq, DEFAULT_PROBE_ID);
            self.send_packet(iface, link, ttl, frame).await?;
        }
        Ok(())
    }
}

impl<TX, PH, S> Drop for Puncher<TX, PH, S> {
    fn drop(&mut self) {
        for entry in self.transaction.iter() {
            entry.value().0.abort();
        }
        self.transaction.clear();
        self.punch_history.clear();
        let futures: Vec<_> = self
            .punch_ifaces
            .iter()
            .map(|entry| self.ifaces.unbind(entry.key().clone()))
            .collect();
        if !futures.is_empty() {
            // Inherent termination: this task owns a finite set of unbind futures
            // and exits once they all complete.
            tokio::spawn(
                async move {
                    futures::future::join_all(futures).await;
                }
                .instrument_in_current()
                .in_current_span(),
            );
        }
        self.punch_ifaces.clear();
    }
}

fn agent_endpoint_is_current(
    address_book: &AddressBook,
    bind_uri: &BindUri,
    key: InterfaceEndpointKey,
    endpoint: EndpointAddr,
) -> bool {
    address_book.has_local_endpoint(bind_uri, key, endpoint)
}

struct LocalEndpointGuard<'a> {
    bind_uri: &'a BindUri,
    key: InterfaceEndpointKey,
    endpoint: EndpointAddr,
}

struct LocalAddressAdvertisement {
    bind_uri: BindUri,
    addr: SocketAddr,
    nat_type: NatType,
    tire: u32,
}

fn add_local_address_when_endpoint_present_locked(
    address_book: &mut AddressBook,
    guard: LocalEndpointGuard<'_>,
    advertisement: LocalAddressAdvertisement,
) -> io::Result<AddAddressFrame> {
    if !agent_endpoint_is_current(address_book, guard.bind_uri, guard.key, guard.endpoint) {
        tracing::trace!(
            target: "punch",
            bind_uri = %guard.bind_uri,
            endpoint_addr = %guard.endpoint,
            advertise_bind_uri = %advertisement.bind_uri,
            local_addr = %advertisement.addr,
            nat_type = ?advertisement.nat_type,
            "skipping local address advertisement for removed endpoint"
        );
        return Err(io::Error::other("local endpoint removed"));
    }

    address_book.add_local_address(
        advertisement.bind_uri,
        advertisement.addr,
        advertisement.tire,
        advertisement.nat_type,
    )
}

fn add_guarded_dynamic_local_address_locked(
    address_book: &mut AddressBook,
    guard: LocalEndpointGuard<'_>,
    advertisement: LocalAddressAdvertisement,
) -> (io::Result<AddAddressFrame>, bool) {
    let result = add_local_address_when_endpoint_present_locked(address_book, guard, advertisement);
    let retain_dynamic_iface = result.is_ok();
    (result, retain_dynamic_iface)
}

impl<TX, PH, S> ArcPuncher<TX, PH, S>
where
    TX: SendFrame<ReliableFrame> + Send + Sync + Clone + 'static,
    PH: ProductHeader<OneRttHeader> + Send + Sync + 'static,
    S: PacketSpace<OneRttHeader> + Send + Sync + 'static,
    for<'b> PunchDoneFrame: Package<S::PacketAssembler<'b>>,
    for<'b> PunchHelloFrame: Package<S::PacketAssembler<'b>>,
    for<'b> PadTo20: Package<S::PacketAssembler<'b>>,
{
    pub fn add_local_address(
        &self,
        bind_uri: BindUri,
        local_addr: SocketAddr,
        nat_type: NatType,
        tire: u32,
    ) -> io::Result<()> {
        if nat_type == NatType::Dynamic {
            self.spawn_dynamic_local_address(bind_uri, nat_type, tire, None);
            return Ok(());
        }
        let mut address_book = self.0.address_book.lock().unwrap();
        let frame = address_book.add_local_address(bind_uri.clone(), local_addr, tire, nat_type)?;
        tracing::trace!(target: "punch", bind_uri = %bind_uri, %local_addr, nat_type = ?nat_type, "sending AddAddress frame");
        self.0.broker.send_frame([ReliableFrame::AddAddress(frame)]);
        Ok(())
    }

    pub fn add_local_address_if_endpoint_present(
        &self,
        bind_uri: BindUri,
        endpoint_addr: EndpointAddr,
        local_addr: SocketAddr,
        nat_type: NatType,
        tire: u32,
    ) -> io::Result<()> {
        if nat_type == NatType::Dynamic {
            {
                let address_book = self.0.address_book.lock().unwrap();
                if !address_book.has_local_endpoint(
                    &bind_uri,
                    interface_endpoint_key(endpoint_addr),
                    endpoint_addr,
                ) {
                    tracing::trace!(
                        target: "punch",
                        %bind_uri,
                        %endpoint_addr,
                        %local_addr,
                        ?nat_type,
                        "skipping dynamic local address advertisement for removed endpoint"
                    );
                    return Err(io::Error::other("local endpoint removed"));
                }
            }

            self.spawn_dynamic_local_address(bind_uri, nat_type, tire, Some(endpoint_addr));
            return Ok(());
        }

        let mut address_book = self.0.address_book.lock().unwrap();
        let frame = add_local_address_when_endpoint_present_locked(
            &mut address_book,
            LocalEndpointGuard {
                bind_uri: &bind_uri,
                key: interface_endpoint_key(endpoint_addr),
                endpoint: endpoint_addr,
            },
            LocalAddressAdvertisement {
                bind_uri: bind_uri.clone(),
                addr: local_addr,
                nat_type,
                tire,
            },
        )?;
        tracing::trace!(
            target: "punch",
            bind_uri = %bind_uri,
            %local_addr,
            nat_type = ?nat_type,
            "sending AddAddress frame"
        );
        self.0.broker.send_frame([ReliableFrame::AddAddress(frame)]);
        Ok(())
    }

    fn spawn_dynamic_local_address(
        &self,
        bind_uri: BindUri,
        nat_type: NatType,
        tire: u32,
        endpoint_guard: Option<EndpointAddr>,
    ) {
        let puncher = self.clone();
        let ifaces = self.0.ifaces.clone();
        let iface_factory = self.0.iface_factory.clone();
        let stun_servers = self.0.stun_servers.clone();
        let quic_router = self.0.quic_router.clone();

        // Inherent termination: dynamic address publication performs one probe
        // and sends at most one AddAddress frame before returning.
        tokio::spawn(
            async move {
                let (iface, stun_client) = dynamic_iface(
                    &bind_uri,
                    &ifaces,
                    &iface_factory,
                    &quic_router,
                    &stun_servers,
                )
                .await?;
                let dynamic_bind = iface.bind_uri();
                let outer = stun_client.outer_addr().await.inspect_err(|error| {
                    tracing::warn!(
                        target: "punch",
                        error = %snafu::Report::from_error(error),
                        bind_uri = %dynamic_bind,
                        "failed to detect outer address for dynamic interface, unbinding"
                    );
                    let ifaces = ifaces.clone();
                    let dynamic_bind = dynamic_bind.clone();
                    // Inherent termination: this task owns one interface bind
                    // and exits once the unbind future completes.
                    tokio::spawn(async move { ifaces.unbind(dynamic_bind).await }.in_current_span());
                })?;

                let frame = match endpoint_guard {
                    Some(endpoint_addr) => {
                        let (result, retain_dynamic_iface) = {
                            let mut address_book = puncher.0.address_book.lock().unwrap();
                            add_guarded_dynamic_local_address_locked(
                                &mut address_book,
                                LocalEndpointGuard {
                                    bind_uri: &bind_uri,
                                    key: interface_endpoint_key(endpoint_addr),
                                    endpoint: endpoint_addr,
                                },
                                LocalAddressAdvertisement {
                                    bind_uri: dynamic_bind.clone(),
                                    addr: outer,
                                    nat_type,
                                    tire,
                                },
                            )
                        };

                        match result {
                            Ok(frame) => {
                                puncher
                                    .0
                                    .punch_ifaces
                                    .insert(dynamic_bind.clone(), iface.clone());
                                frame
                            }
                            Err(error) => {
                                if !retain_dynamic_iface {
                                    ifaces.unbind(dynamic_bind.clone()).await;
                                }
                                return Err(error);
                            }
                        }
                    }
                    None => {
                        puncher
                            .0
                            .punch_ifaces
                            .insert(dynamic_bind.clone(), iface.clone());
                        let mut address_book = puncher.0.address_book.lock().unwrap();
                        address_book.add_local_address(
                            dynamic_bind.clone(),
                            outer,
                            tire,
                            nat_type,
                        )?
                    }
                };
                tracing::trace!(target: "punch", bind_uri = %dynamic_bind, %outer, nat_type = ?nat_type, "sending AddAddress frame for dynamic");
                puncher
                    .0
                    .broker
                    .send_frame([ReliableFrame::AddAddress(frame)]);
                Ok::<_, io::Error>(())
            }
            .instrument_in_current()
            .in_current_span(),
        );
    }

    fn endpoint_path_changes(
        &self,
        added: Option<(BindUri, EndpointAddr)>,
        remote_endpoints: Vec<(EndpointAddr, qresolve::Source)>,
    ) -> LocalEndpointPathChanges {
        let Some((bind_uri, local_endpoint)) = added else {
            return LocalEndpointPathChanges::default();
        };
        let changes = remote_endpoints
            .into_iter()
            .filter_map(|(remote_endpoint, source)| {
                match self.resolve_punch_connection(
                    &bind_uri,
                    &local_endpoint,
                    &remote_endpoint,
                    &source,
                ) {
                    Ok((bind_uri, link, pathway)) => {
                        Some(LocalEndpointPathChange::AddPath((bind_uri, pathway, link)))
                    }
                    Err(error) => {
                        tracing::trace!(
                            target: "dquic",
                            %bind_uri,
                            %local_endpoint,
                            %remote_endpoint,
                            ?source,
                            %error,
                            "skipping incompatible peer endpoint candidate"
                        );
                        None
                    }
                }
            })
            .collect();
        LocalEndpointPathChanges::new(changes)
    }

    fn update_agent_advertisement_after_upsert(
        &self,
        bind_uri: BindUri,
        key: InterfaceEndpointKey,
        endpoint: EndpointAddr,
    ) {
        let InterfaceEndpointKey::Agent(agent) = key else {
            return;
        };
        let EndpointAddr::Agent { .. } = endpoint else {
            return;
        };

        self.remove_agent_advertisement(&bind_uri, key);

        let Some(iface) = self.0.ifaces.borrow(&bind_uri) else {
            tracing::debug!(target: "punch", %bind_uri, ?key, "cannot advertise agent endpoint without interface");
            return;
        };

        let client = iface.with_component(|clients: &StunClientsComponent| {
            clients.with_clients(|map| map.get(&agent).cloned())
        });
        let Some(Some(Some(client))) = client.ok() else {
            tracing::debug!(target: "punch", %bind_uri, %agent, "cannot advertise agent endpoint without matching STUN client");
            return;
        };

        let puncher = self.clone();
        tokio::spawn(
            async move {
                let Ok(nat_type) = client.nat_type().await else {
                    tracing::debug!(target: "punch", %bind_uri, %agent, "cannot advertise agent endpoint without NAT type");
                    return;
                };
                if let Err(error) = puncher
                    .publish_agent_advertisement_if_current(bind_uri, key, endpoint, nat_type, 0)
                    .await
                {
                    tracing::debug!(target: "punch", ?error, %agent, "failed to advertise agent endpoint");
                }
            }
            .instrument_in_current()
            .in_current_span(),
        );
    }

    fn remove_agent_advertisement(&self, bind_uri: &BindUri, key: InterfaceEndpointKey) {
        let Some((_, resource)) = self
            .0
            .local_endpoint_advertisements
            .remove(&(bind_uri.clone(), key))
        else {
            return;
        };

        if let Err(error) = self.remove_local_address(resource.advertised_addr()) {
            tracing::debug!(
                target: "punch",
                ?error,
                advertised_addr = %resource.advertised_addr(),
                "failed to remove advertised local address"
            );
        }

        if let Some(iface) = resource.temporary_iface {
            let ifaces = self.0.ifaces.clone();
            let advertised_bind = resource.advertised_bind.clone();
            tokio::spawn(
                async move {
                    ifaces.unbind(advertised_bind).await;
                    drop(iface);
                }
                .instrument_in_current()
                .in_current_span(),
            );
        }
    }

    async fn publish_agent_advertisement_if_current(
        &self,
        bind_uri: BindUri,
        key: InterfaceEndpointKey,
        endpoint: EndpointAddr,
        nat_type: NatType,
        tire: u32,
    ) -> io::Result<()> {
        let local_addr = endpoint.addr();
        if nat_type == NatType::Dynamic {
            let (iface, stun_client) = dynamic_iface(
                &bind_uri,
                &self.0.ifaces,
                &self.0.iface_factory,
                &self.0.quic_router,
                &self.0.stun_servers,
            )
            .await?;
            let advertised_bind = iface.bind_uri();
            let advertised_addr = match stun_client.outer_addr().await {
                Ok(outer) => outer,
                Err(error) => {
                    self.0.ifaces.unbind(advertised_bind.clone()).await;
                    return Err(io::Error::other(error));
                }
            };
            let frame = {
                let mut address_book = self.0.address_book.lock().unwrap();
                add_local_address_when_endpoint_present_locked(
                    &mut address_book,
                    LocalEndpointGuard {
                        bind_uri: &bind_uri,
                        key,
                        endpoint,
                    },
                    LocalAddressAdvertisement {
                        bind_uri: advertised_bind.clone(),
                        addr: advertised_addr,
                        nat_type,
                        tire,
                    },
                )?
            };
            self.0
                .punch_ifaces
                .insert(advertised_bind.clone(), iface.clone());
            self.0.broker.send_frame([ReliableFrame::AddAddress(frame)]);
            let resource = LocalEndpointAdvertisementResource::new(
                bind_uri.clone(),
                key,
                endpoint,
                &frame,
                advertised_bind,
                Some(iface),
            );
            self.0
                .local_endpoint_advertisements
                .insert((bind_uri, key), resource);
            return Ok(());
        }

        let frame = {
            let mut address_book = self.0.address_book.lock().unwrap();
            add_local_address_when_endpoint_present_locked(
                &mut address_book,
                LocalEndpointGuard {
                    bind_uri: &bind_uri,
                    key,
                    endpoint,
                },
                LocalAddressAdvertisement {
                    bind_uri: bind_uri.clone(),
                    addr: local_addr,
                    nat_type,
                    tire,
                },
            )?
        };
        self.0.broker.send_frame([ReliableFrame::AddAddress(frame)]);
        let resource = LocalEndpointAdvertisementResource::new(
            bind_uri.clone(),
            key,
            endpoint,
            &frame,
            bind_uri.clone(),
            None,
        );
        self.0
            .local_endpoint_advertisements
            .insert((bind_uri, key), resource);
        Ok(())
    }

    pub fn upsert_local_endpoint(
        &self,
        bind: BindUri,
        key: InterfaceEndpointKey,
        endpoint: EndpointAddr,
    ) -> LocalEndpointPathChanges {
        let (delta, remote_endpoints) = {
            let mut address_book = self.0.address_book.lock().unwrap();
            let delta = address_book.upsert_local_endpoint(bind.clone(), key, endpoint);
            let remote_endpoints = address_book.remote_endpoint().collect();
            (delta, remote_endpoints)
        };

        if delta.removed_endpoint().is_some() && matches!(key, InterfaceEndpointKey::Agent(_)) {
            self.remove_agent_advertisement(&bind, key);
        }
        if delta.added_endpoint().is_some() {
            self.update_agent_advertisement_after_upsert(bind, key, endpoint);
        }
        self.endpoint_path_changes(delta.added_endpoint(), remote_endpoints)
    }

    pub fn remove_local_endpoint(
        &self,
        bind: &BindUri,
        key: &InterfaceEndpointKey,
    ) -> LocalEndpointPathChanges {
        let delta = {
            let mut address_book = self.0.address_book.lock().unwrap();
            address_book.remove_local_endpoint(bind, key)
        };
        if delta.removed_endpoint().is_some() && matches!(key, InterfaceEndpointKey::Agent(_)) {
            self.remove_agent_advertisement(bind, *key);
        }
        LocalEndpointPathChanges::default()
    }

    pub fn close_local_endpoints(&self, bind: &BindUri) -> LocalEndpointPathChanges {
        let removed = {
            let mut address_book = self.0.address_book.lock().unwrap();
            address_book.close_local_endpoints(bind)
        };
        for (key, _) in removed {
            if matches!(key, InterfaceEndpointKey::Agent(_)) {
                self.remove_agent_advertisement(bind, key);
            }
        }
        LocalEndpointPathChanges::default()
    }

    pub fn add_peer_endpoint(
        &self,
        endpoint: EndpointAddr,
        source: qresolve::Source,
    ) -> io::Result<Vec<(BindUri, Link, Pathway)>> {
        let local_endpoints = {
            let mut address_book = self.0.address_book.lock().unwrap();
            address_book.add_peer_endpoint(endpoint, source.clone())?;
            address_book.local_endpoint().collect::<Vec<_>>()
        };
        let mut ways = Vec::new();
        for (bind, local_ep) in local_endpoints {
            match self.resolve_punch_connection(&bind, &local_ep, &endpoint, &source) {
                Ok(way) => ways.push(way),
                Err(error) => {
                    tracing::trace!(
                        target: "dquic",
                        %bind,
                        %local_ep,
                        remote_endpoint = %endpoint,
                        ?source,
                        %error,
                        "skipping incompatible peer endpoint candidate"
                    );
                }
            }
        }
        Ok(ways)
    }

    pub fn remove_local_address(&self, addr: SocketAddr) -> io::Result<()> {
        let mut address_book = self.0.address_book.lock().unwrap();
        let frame = address_book.remove_local_address(addr)?;
        self.0
            .broker
            .send_frame([ReliableFrame::RemoveAddress(frame)]);
        Ok(())
    }

    fn recv_remove_address_frame(&self, remove_address_frame: RemoveAddressFrame) {
        let mut address_book = self.0.address_book.lock().unwrap();
        address_book.remove_remote_address(remove_address_frame.deref().into_u64() as u32);
    }

    fn recv_add_address_frame(&self, add_address_frame: AddAddressFrame) -> io::Result<()> {
        // The lock on address_book must be released before accessing the transaction map
        // to avoid a deadlock with recv_punch_me_now, which holds the transaction lock
        // while trying to acquire the address_book lock.
        let (bind, local) = {
            let mut address_book = self.0.address_book.lock().unwrap();
            address_book.add_remote_address(add_address_frame)?;
            let (bind, local) = address_book.pick_local_address(&add_address_frame)?;
            (bind.clone(), local)
        };

        let punch_id = (&local, &add_address_frame).punch_id();
        if self.0.punch_history.contains_key(&punch_id) {
            tracing::debug!(target: "punch", %punch_id, local_nat = ?local.nat_type(), remote_nat = ?add_address_frame.nat_type(), "punch already completed, skipping");
            return Ok(());
        }
        match self.0.transaction.entry(punch_id) {
            Entry::Occupied(_) => {
                tracing::debug!(target: "punch", %punch_id, local_nat = ?local.nat_type(), remote_nat = ?add_address_frame.nat_type(), "dup transaction for punch");
                return Ok(());
            }
            Entry::Vacant(entry) => {
                let tx = Arc::new(Transaction::new());
                let task = tokio::spawn(
                    {
                        let puncher = self.clone();
                        let tx = tx.clone();
                        async move {
                            let result = puncher
                                .punch_actively(bind, &local, &add_address_frame, tx)
                                .await;
                            puncher.0.punch_history.insert(punch_id, ());
                            puncher.0.transaction.remove(&punch_id);
                            result
                        }
                    }
                    .instrument_in_current()
                    .in_current_span(),
                )
                .abort_handle();
                entry.insert((task, tx.clone()));
            }
        };
        Ok(())
    }

    fn recv_punch_me_now(
        &self,
        pathway: Pathway,
        punch_me_now_frame: PunchMeNowFrame,
    ) -> io::Result<()> {
        let punch_id = punch_me_now_frame.punch_id().flip();
        if self.0.punch_history.contains_key(&punch_id) {
            tracing::debug!(target: "punch", %punch_id, "punch already completed, skipping");
            return Ok(());
        }

        let crate_punch_task = || {
            let tx = Arc::new(Transaction::new());
            let task = tokio::spawn({
                let puncher = self.clone();
                let tx = tx.clone();
                let address_book = self.0.address_book.lock().unwrap();
                let (bind, local_address) = address_book
                    .get_local_address(&punch_me_now_frame.remote_seq())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "local address not matched")
                    })?;
                tracing::debug!(target: "punch", %punch_id, local_nat = ?local_address.nat_type(), remote_nat = ?punch_me_now_frame.nat_type(), "received punch me now frame, start passive punch");
                async move {
                    let result = puncher
                        .punch_passively(bind, &local_address, &punch_me_now_frame, tx)
                        .await;
                    puncher.0.punch_history.insert(punch_id, ());
                    puncher.0.transaction.remove(&punch_id);
                    result
                }
                .instrument_in_current()
                .in_current_span()
            })
            .abort_handle();
            Ok::<_, io::Error>((task, tx.clone()))
        };

        match self.0.transaction.entry(punch_id) {
            Entry::Occupied(mut entry) => {
                if pathway.local() < pathway.remote() {
                    let (task, tx) = crate_punch_task()?;
                    tx.store_punch_me_now(punch_me_now_frame);
                    let old_task = entry.get().0.clone();
                    old_task.abort();
                    entry.insert((task, tx.clone()));
                    tracing::trace!(target: "punch", %punch_id, "new passive transaction for punch");
                } else {
                    let tx = entry.get().1.clone();
                    tracing::trace!(target: "punch", %punch_id, "using existing active transaction to respond to PunchMeNow");
                    tx.store_punch_me_now(punch_me_now_frame);
                }
            }
            Entry::Vacant(entry) => {
                let (task, tx) = crate_punch_task()?;
                entry.insert((task, tx.clone()));
                tracing::trace!(target: "punch", %punch_id, "new passive transaction");
            }
        };

        Ok(())
    }

    async fn punch_actively(
        &self,
        bind_uri: BindUri,
        local: &AddAddressFrame,
        remote: &AddAddressFrame,
        tx: Arc<Transaction>,
    ) -> io::Result<()> {
        let local_nat = local.nat_type();
        let remote_nat = remote.nat_type();
        let bind_addr = SocketAddr::try_from(bind_uri.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let link = Link::new(bind_addr, *remote.deref());
        let punch_id = (local, remote).punch_id();
        tracing::debug!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "starting active punch");

        let mut punch_me_now = PunchMeNowFrame::new(
            local.seq_num(),
            remote.seq_num(),
            *local.deref(),
            local.tire(),
            local_nat,
        );
        let ifaces = self.0.ifaces.clone();
        let dynamic_iface = {
            let ifaces = self.0.ifaces.clone();
            let iface_factory = self.0.iface_factory.clone();
            let quic_router = self.0.quic_router.clone();
            let stun_servers = self.0.stun_servers.clone();
            async move |bind_uri: &BindUri| {
                dynamic_iface(
                    bind_uri,
                    &ifaces,
                    &iface_factory,
                    &quic_router,
                    &stun_servers,
                )
                .await
            }
        };

        let broker = self.0.broker.clone();
        let punch_ifaces = &self.0.punch_ifaces;

        // local \ remote  ·FullCone    RestrictedCone    RestrictedPort  Symmetric    Dynamic
        // FullCone         1               6                 6              6          6
        // RestrictedCone   1               6                 6              6          6
        // RestrictedPort   1               6                 6              7          6
        // Symmetric        1               4                 3              /          8
        // Dynamic          1               5                 5              2          5

        // 1: Remote is FullCone
        // Send direct Hello to remote, expecting Hello(Done).
        // 2: Local Dynamic, Remote Symmetric -> New Interface & Birthday Attack
        // Send PunchMeNow, expect PunchMeNow. After receiving, start collision, expect Hello(Done).
        // 3: Local Symmetric, Remote RestrictedPort -> Birthday Attack
        // Send PunchMeNow, expect PunchMeNow. Use random socket collision, expect Hello(Done).
        // 4: Local Symmetric, Remote RestrictedCone -> Reverse Punching
        // Send PunchMeNow, expect remote to open hole and respond PunchMeNow. Then send direct Hello, expect Hello(Done).
        // 5: Local Dynamic
        // New Interface, detect external address. Then send PunchMeNow and Hello, expect Hello(Done).
        // 6: General Punching
        // Send Hello with TTL and PunchMeNow. Expect Hello, then respond Hello(Done).
        // 7: Local RestrictedPort, Remote Symmetric -> Birthday Attack (Hold Hole)
        // Send packets to 300 random ports, then notify with PunchMeNow. Expect Hello, then respond Hello(Done).
        // 8: Local Symmetric, Remote Dynamic
        // Hold holes on 30 random ports, send PunchMeNow. Expect Collision, then respond PunchMeNow.
        // Repeat until 300 sockets used.
        use NatType::*;
        let result: io::Result<()> = match (local_nat, remote_nat) {
            (Blocked, _) | (_, Blocked) | (Symmetric, Symmetric) => {
                return Err(io::Error::other("Unsupported nat type"));
            }
            // 1: Remote is FullCone
            // Send direct Hello to remote, expecting Hello(Done).
            (_, FullCone) => {
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "strategy: Remote FullCone, sending direct Hello");
                let iface = ifaces
                    .borrow(&bind_uri)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                let time = Duration::from_millis(100);
                for i in 0..5 {
                    tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %link, "sending Hello expecting Hello(Done) or receiving Hello");
                    self.0
                        .send_packet(
                            &iface,
                            link,
                            HELLO_TTL,
                            PunchHelloFrame::new(
                                punch_id.local_seq,
                                punch_id.remote_seq,
                                DEFAULT_PROBE_ID,
                            ),
                        )
                        .await?;
                    let timeout_duration = time * (1 << i);
                    tokio::select! {
                        _ = tokio::time::sleep(timeout_duration) => {
                            // continue loop
                        }
                        Ok((_, punch_hello)) = async { Ok::<_, io::Error>(tx.wait_punch_hello().await) } => {
                            tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "received Hello, sending broker PunchDone confirmation");
                            broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(&punch_hello))]);
                            return Ok(());
                        }
                        _ = tx.wait_punch_done() => {
                            tracing::debug!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "punch success");
                            return Ok(());
                        }
                    }
                }
                tracing::debug!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "punch failed");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 2. Local Dynamic, Remote Symmetric -> New Interface & Birthday Attack
            // Send PunchMeNow, expect PunchMeNow. After receiving, start collision, expect Hello(Done).
            (Dynamic, Symmetric) => {
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "strategy: Local Dynamic, Remote Symmetric, new interface & birthday attack");
                // TODO: Creating a new iface is not strictly necessary; could reuse an available temporary address.
                let (iface, stun_client) = dynamic_iface(&bind_uri).await?;

                let bind_uri = iface.bind_uri();
                punch_ifaces.insert(bind_uri.clone(), iface.clone());
                let outer_addr = stun_client.outer_addr().await?;
                punch_me_now.set_addr(outer_addr);
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "sending PunchMeNow expecting PunchMeNow then collision");
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);

                let link = Link::new(iface.bound_addr()?, link.dst);
                let mut collided = false;
                let result: io::Result<()> = loop {
                    tokio::select! {
                        _ = tokio::time::sleep(BIRTHDAY_TIMEOUT)=>
                            break Err(io::Error::new(io::ErrorKind::TimedOut, "Punch timeout")),
                        _ = tx.wait_punch_me_now(), if !collided => {
                            collided = true;
                            self.0.collision(&iface, link, punch_id, KNOCK_TTL).await?;
                        }
                        Ok((link, punch_hello)) = async { Ok::<_, io::Error>(tx.wait_punch_hello().await) } => {
                            tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %link, "received Hello, sending broker PunchDone confirmation");
                            broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(&punch_hello))]);
                            break Ok(());
                        }
                        _ = tx.wait_punch_done() =>
                            break Ok(()),
                    };
                };
                // If punch failed, clean up the interface
                if result.is_err() {
                    punch_ifaces.remove(&bind_uri);
                    ifaces.unbind(bind_uri).await;
                }
                result
            }
            // 3. Local Symmetric, Remote RestrictedPort -> Birthday Attack
            // Send PunchMeNow, expect PunchMeNow. Use random socket collision, expect Hello(Done).
            (Symmetric, RestrictedPort) => {
                // Send PunchMeNow first
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "sending PunchMeNow expecting PunchMeNow then rush");
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);

                if timeout(COLLISION_TIMEOUT, tx.wait_punch_me_now())
                    .await
                    .is_ok()
                {
                    // Use new consolidated PortPredictor birthday attack
                    let mut predictor = PortPredictor::new(
                        ifaces.clone(),
                        self.0.iface_factory.clone(),
                        self.0.quic_router.clone(),
                        bind_uri.clone(),
                        link.dst,
                    )?;

                    // Create packet send function
                    let puncher_ref = self.0.clone();
                    let packet_send_fn: PacketSendFn = Arc::new(move |iface, link, ttl, frame| {
                        let puncher = puncher_ref.clone();
                        Box::pin(async move { puncher.send_packet(iface, link, ttl, frame).await })
                    });

                    tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "starting consolidated birthday attack");
                    match predictor
                        .predict(punch_id, tx.clone(), packet_send_fn)
                        .await
                    {
                        Ok(Some((bind_uri, iface))) => {
                            tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %bind_uri, "birthday attack succeeded");
                            self.0.punch_ifaces.insert(bind_uri.clone(), iface);
                            return Ok(());
                        }
                        Ok(None) => {
                            tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "birthday attack completed without success");
                        }
                        Err(e) => {
                            tracing::warn!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %e, "birthday attack failed");
                        }
                    }
                }

                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 4. Local Symmetric, Remote RestrictedCone -> Reverse Punching
            // Send PunchMeNow, expect remote to open hole and respond PunchMeNow. Then send direct Hello, expect Hello(Done).
            (Symmetric, RestrictedCone) => {
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "strategy: Local Symmetric, Remote RestrictedCone, reverse punching");
                tracing::trace!(target: "punch", %punch_id, "sending PunchMeNow expecting PunchMeNow then Hello");
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);
                if timeout(PUNCH_ME_NOW_TIMEOUT, tx.wait_punch_me_now())
                    .await
                    .is_err()
                {
                    tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "wait for PunchMeNow timeout, try to connect blindly");
                }

                let iface = ifaces
                    .borrow(&bind_uri)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                for i in 0..5 {
                    tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %link, "sending Hello expecting Hello(Done)");
                    self.0
                        .send_packet(
                            &iface,
                            link,
                            HELLO_TTL,
                            PunchHelloFrame::new(
                                punch_id.local_seq,
                                punch_id.remote_seq,
                                DEFAULT_PROBE_ID,
                            ),
                        )
                        .await?;
                    if (timeout(KNOCK_TIMEOUT * (1 << i), tx.wait_punch_done()).await).is_ok() {
                        tracing::debug!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "punch success");
                        return Ok(());
                    }
                }

                tracing::debug!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "punch failed");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 5. Local Dynamic
            // New Interface, detect external address. Then send PunchMeNow and Hello, expect Hello(Done).
            (Dynamic, _) => {
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "strategy: Local Dynamic, new interface & send PunchMeNow + Hello");
                // Use new iface, update PunchMeNow address.
                // TODO: Creating a new iface is not strictly necessary; could reuse an available temporary address.
                let (iface, stun_client) = dynamic_iface(&bind_uri).await?;
                let outer_addr = stun_client.outer_addr().await?;
                let bind_uri = iface.bind_uri();
                punch_ifaces.insert(bind_uri.clone(), iface.clone());
                punch_me_now.set_addr(outer_addr);
                tracing::trace!(target: "punch", %punch_id, "sending PunchMeNow + Hello expecting Hello(Done)");
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);
                let link = Link::new(iface.bound_addr()?, link.dst);
                let time = Duration::from_millis(100);
                for i in 0..MAX_RETRIES {
                    tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %link, "sending Hello expecting Hello(Done)");
                    self.0
                        .send_packet(
                            &iface,
                            link,
                            HELLO_TTL,
                            PunchHelloFrame::new(
                                punch_id.local_seq,
                                punch_id.remote_seq,
                                DEFAULT_PROBE_ID,
                            ),
                        )
                        .await?;
                    let timeout_duration = time * (1 << i);
                    tokio::select! {
                        _ = tokio::time::sleep(timeout_duration) => {
                            // continue loop
                        }
                        Ok((_, punch_hello)) = async { Ok::<_, io::Error>(tx.wait_punch_hello().await) } => {
                            tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "received Hello, sending broker PunchDone confirmation");
                            broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(&punch_hello))]);
                            return Ok(());
                        }
                        _ = tx.wait_punch_done() => {
                            tracing::debug!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "punch success");
                            return Ok(());
                        }
                    }
                }
                // Punch failed, remove the interface
                punch_ifaces.remove(&bind_uri);
                ifaces.unbind(bind_uri).await;
                Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"))
            }
            // 6. General Punching
            // Send Hello with TTL and PunchMeNow. Expect Hello, then respond Hello(Done).
            (FullCone | RestrictedCone, Symmetric)
            | (FullCone | RestrictedCone | RestrictedPort, Dynamic)
            | (_, RestrictedCone | RestrictedPort) => {
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "strategy: General punching, send Hello with TTL & PunchMeNow");
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "sending PunchMeNow + Hello expecting Hello then Hello(Done)");
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);
                let iface = ifaces
                    .borrow(&bind_uri)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %link, "sending Hello expecting Hello");
                self.0
                    .send_packet(
                        &iface,
                        link,
                        HELLO_TTL,
                        PunchHelloFrame::new(
                            punch_id.local_seq,
                            punch_id.remote_seq,
                            DEFAULT_PROBE_ID,
                        ),
                    )
                    .await?;
                if let Ok((_, punch_hello)) = timeout(PUNCH_TIMEOUT, tx.wait_punch_hello()).await {
                    tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "sending broker PunchDone confirmation");
                    broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(
                        &punch_hello,
                    ))]);
                    tracing::debug!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "actively punch success");
                    return Ok(());
                }
                tracing::debug!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "punch failed");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 7. Local RestrictedPort, Remote Symmetric -> Birthday Attack (Hold Hole)
            // Send packets to 300 random ports, then notify with PunchMeNow. Expect Hello, then respond Hello(Done).
            (RestrictedPort, Symmetric) => {
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "strategy: Local RestrictedPort, Remote Symmetric, birthday attack hold hole");
                let iface = ifaces
                    .borrow(&bind_uri)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                self.0.collision(&iface, link, punch_id, KNOCK_TTL).await?;
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "sending PunchMeNow expecting Hello then Hello(Done)");
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);
                if let Ok((link, punch_hello)) =
                    timeout(BIRTHDAY_TIMEOUT, tx.wait_punch_hello()).await
                {
                    tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %link, "sending broker PunchDone confirmation");
                    broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(
                        &punch_hello,
                    ))]);
                    tracing::debug!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "punch success with collision");
                    return Ok(());
                }
                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 8. Local Symmetric, Remote Dynamic
            // Hold holes on 30 random ports, send PunchMeNow. Expect Collision, then respond PunchMeNow.
            // Repeat until 300 sockets used.
            (Symmetric, Dynamic) => {
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "strategy: Local Symmetric, Remote Dynamic, hold holes & send PunchMeNow");

                // Use new consolidated PortPredictor birthday attack
                let mut predictor = PortPredictor::new(
                    ifaces.clone(),
                    self.0.iface_factory.clone(),
                    self.0.quic_router.clone(),
                    bind_uri.clone(),
                    link.dst,
                )?;
                // Create packet send function
                let puncher_ref = self.0.clone();
                let packet_send_fn: PacketSendFn = Arc::new(move |iface, link, ttl, frame| {
                    let puncher = puncher_ref.clone();
                    Box::pin(async move { puncher.send_packet(iface, link, ttl, frame).await })
                });

                // Send initial PunchMeNow to notify peer
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "sending initial PunchMeNow for Dynamic strategy");
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);

                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "starting consolidated birthday attack for Dynamic strategy");
                match predictor
                    .predict(punch_id, tx.clone(), packet_send_fn)
                    .await
                {
                    Ok(Some((bind_uri, iface))) => {
                        tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %bind_uri, "birthday attack succeeded for Dynamic strategy");
                        self.0.punch_ifaces.insert(bind_uri.clone(), iface);
                        return Ok(());
                    }
                    Ok(None) => {
                        tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "birthday attack completed without success for Dynamic strategy");
                    }
                    Err(e) => {
                        tracing::warn!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %e, "birthday attack failed for Dynamic strategy");
                    }
                }
                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
        };
        result
    }

    async fn punch_passively(
        &self,
        bind: BindUri,
        local_address: &AddAddressFrame,
        remote_address: &PunchMeNowFrame,
        tx: Arc<Transaction>,
    ) -> io::Result<()> {
        use NatType::*;
        let remote_nat = remote_address.nat_type();
        let local_nat = local_address.nat_type();
        let punch_id = PunchId::new(local_address.seq_num(), remote_address.local_seq());
        tracing::debug!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "starting passive punch");
        let socket_addr = SocketAddr::try_from(bind.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        if local_nat == Blocked
            || remote_nat == Blocked
            || (local_nat == Symmetric && remote_nat == Symmetric)
        {
            return Err(io::Error::other("Unsupported nat type"));
        }
        let link = Link::new(socket_addr, remote_address.address());

        let ifaces = self.0.ifaces.clone();
        let broker = self.0.broker.clone();
        // Note: Receiving PunchMeNow implies we sent an AddAddress frame.
        // For Dynamic NAT, we don't need to create a new interface here;
        // it should have been created before sending AddAddress.
        // 1. Local Dynamic, Remote Symmetric
        // Remote has opened hole. We use new interface to collide, expecting Hello(Done).
        // 2. Local RestrictedPort, Remote Symmetric
        // We open holes on 300 random ports, send PunchMeNow. Expect Hello collision, then respond Hello(Done).
        // 3. Local Symmetric, Remote RestrictedPort | Dynamic
        // We use random socket collision to open hole, expecting Hello(Done).
        // 4. Local RestrictedCone, Remote Symmetric
        // Reflect, hello then Send PunchmeNow, wait for hello, send Hello(Done).
        // 5. General Punching
        // Received PunchMeNow implies remote has opened hole. We send direct Hello, expecting Hello(Done).

        match (local_nat, remote_nat) {
            // 1. Local Dynamic, Remote Symmetric
            // Remote has opened hole. We use new interface to collide, expecting Hello(Done).
            (Dynamic, Symmetric) => {
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "passive strategy: Local Dynamic, Remote Symmetric, use new interface to collide");
                let iface = ifaces
                    .borrow(&bind)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                let mut collided = false;
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(BIRTHDAY_TIMEOUT)=>
                            return Err(io::Error::new(io::ErrorKind::TimedOut, "Punch timeout")),
                        _ = tx.wait_punch_me_now(), if !collided => {
                            collided = true;
                            self.0.collision(&iface, link, punch_id, KNOCK_TTL).await?;
                        }
                        Ok((link, punch_hello)) = async { Ok::<_, io::Error>(tx.wait_punch_hello().await) } => {
                            tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %link, "received Hello, sending broker PunchDone confirmation");
                            broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(&punch_hello))]);
                            return Ok(());
                        }
                        _ = tx.wait_punch_done() =>
                                return Ok::<(), io::Error>(()),
                    };
                }
            }
            // 2. Local RestrictedPort, Remote Symmetric
            // We open holes on 300 random ports, send PunchMeNow. Expect Hello collision, then respond Hello(Done).
            (RestrictedPort, Symmetric) => {
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "passive strategy: Local RestrictedPort, Remote Symmetric, open holes & send PunchMeNow");
                let iface = ifaces
                    .borrow(&bind)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                self.0.collision(&iface, link, punch_id, KNOCK_TTL).await?;
                let punch_me_now = PunchMeNowFrame::new(
                    punch_id.local_seq,
                    punch_id.remote_seq,
                    *local_address.deref(),
                    local_address.tire(),
                    local_nat,
                );
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "sending PunchMeNow expecting Hello then Hello(Done)");
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);
                if let Ok((link, punch_hello)) =
                    tokio::time::timeout(BIRTHDAY_TIMEOUT, tx.wait_punch_hello()).await
                {
                    tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %link, "sending broker PunchDone confirmation");
                    broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(
                        &punch_hello,
                    ))]);
                    return Ok(());
                }
            }
            // 3. Local Symmetric, Remote RestrictedPort
            // Use new consolidated PortPredictor birthday attack. Expect Hello(Done).
            (Symmetric, RestrictedPort | Dynamic) => {
                let mut predictor = PortPredictor::new(
                    ifaces.clone(),
                    self.0.iface_factory.clone(),
                    self.0.quic_router.clone(),
                    bind.clone(),
                    link.dst,
                )?;

                // Create packet send function
                let puncher_ref = self.0.clone();
                let packet_send_fn: PacketSendFn = Arc::new(move |iface, link, ttl, frame| {
                    let puncher = puncher_ref.clone();
                    Box::pin(async move { puncher.send_packet(iface, link, ttl, frame).await })
                });

                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "starting consolidated birthday attack");
                match predictor
                    .predict(punch_id, tx.clone(), packet_send_fn)
                    .await
                {
                    Ok(Some((bind_uri, iface))) => {
                        tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %bind_uri, "birthday attack succeeded");
                        self.0.punch_ifaces.insert(bind_uri.clone(), iface);
                        return Ok(());
                    }
                    Ok(None) => {
                        tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "birthday attack completed without success");
                    }
                    Err(e) => {
                        tracing::warn!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %e, "birthday attack failed");
                    }
                }
            }
            // 4. Local RestrictedCone, Remote Symmetric
            // Reflect, Hello and  PunchmeNow, wait for hello, send Hello(Done)
            (RestrictedCone, Symmetric) => {
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "passive strategy: Local RestrictedCone, Remote Symmetric, reflect & send PunchMeNow");
                let iface = ifaces
                    .borrow(&bind)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                let punch_me_now = PunchMeNowFrame::new(
                    punch_id.local_seq,
                    punch_id.remote_seq,
                    *local_address.deref(),
                    local_address.tire(),
                    local_nat,
                );
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "sending PunchMeNow expecting Hello then Hello(Done)");
                let punch_hello_frame =
                    PunchHelloFrame::new(punch_id.local_seq, punch_id.remote_seq, DEFAULT_PROBE_ID);
                self.0
                    .send_packet(&iface, link, HELLO_TTL, punch_hello_frame)
                    .await?;
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);
                if let Ok((link, punch_hello)) =
                    tokio::time::timeout(PUNCH_TIMEOUT, tx.wait_punch_hello()).await
                {
                    tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %link, "sending broker PunchDone confirmation");
                    broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(
                        &punch_hello,
                    ))]);
                    return Ok(());
                }
            }
            // 5. General Punching
            // Received PunchMeNow implies remote has opened hole. We send direct Hello, expecting Hello(Done).
            _ => {
                tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "passive strategy: General punching, send direct Hello");
                let iface = ifaces
                    .borrow(&bind)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                let time = Duration::from_millis(100);
                for i in 0..MAX_RETRIES {
                    tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, %link, "sending Hello expecting Hello(Done)");
                    self.0
                        .send_packet(
                            &iface,
                            link,
                            HELLO_TTL,
                            PunchHelloFrame::new(
                                punch_id.local_seq,
                                punch_id.remote_seq,
                                DEFAULT_PROBE_ID,
                            ),
                        )
                        .await?;
                    let timeout_duration = time * (1 << i);
                    tokio::select! {
                        _ = tokio::time::sleep(timeout_duration) => {
                            // continue loop
                        }
                        Ok((_, punch_hello)) = async { Ok::<_, io::Error>(tx.wait_punch_hello().await) } => {
                            tracing::trace!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "received Hello, sending broker PunchDone confirmation");
                            broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(&punch_hello))]);
                            return Ok(());
                        }
                        _ = tx.wait_punch_done() => {
                            tracing::debug!(target: "punch", %punch_id, local_nat = ?local_nat, remote_nat = ?remote_nat, "passively punch success");
                            return Ok(());
                        }
                    }
                }
            }
        };
        Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"))
    }

    fn resolve_punch_connection(
        &self,
        bind: &BindUri,
        local: &EndpointAddr,
        remote: &EndpointAddr,
        source: &qresolve::Source,
    ) -> Result<(BindUri, Link, Pathway), ResolvePathError> {
        if let qresolve::Source::Mdns { nic, family } = source {
            let matches_iface = bind
                .as_iface_bind_uri()
                .is_some_and(|(lf, ln, _)| lf == *family && ln == nic.as_ref());
            if !matches_iface {
                return Err(ResolvePathError::SourceConstraint);
            }
        }
        validate_endpoint_pair(*local, *remote)?;

        let (local_addr, remote_addr) = self.extract_addresses(bind, local, remote)?;
        Ok(build_validated_way(
            bind,
            *local,
            *remote,
            local_addr,
            remote_addr,
        )?)
    }

    fn extract_addresses(
        &self,
        bind: &BindUri,
        local: &EndpointAddr,
        remote: &EndpointAddr,
    ) -> io::Result<(SocketAddr, SocketAddr)> {
        use EndpointAddr::*;
        match (local, remote) {
            (Direct { addr: local_addr }, Direct { addr: remote_addr }) => {
                Ok((*local_addr, *remote_addr))
            }
            (Agent { .. }, Agent { agent, .. }) => {
                let iface = self.0.ifaces.borrow(bind).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Interface not found for bind URI: {:?}", bind),
                    )
                })?;
                Ok((iface.bound_addr()?, *agent))
            }
            _ => unreachable!("endpoint kinds were validated before address extraction"),
        }
    }
}

impl<TX, PH, S> ReceiveFrame<(BindUri, Pathway, Link, ReliableFrame)> for ArcPuncher<TX, PH, S>
where
    TX: SendFrame<ReliableFrame> + Send + Sync + Clone + 'static,
    PH: ProductHeader<OneRttHeader> + Send + Sync + 'static,
    S: PacketSpace<OneRttHeader> + Send + Sync + 'static,
    for<'b> PunchDoneFrame: Package<S::PacketAssembler<'b>>,
    for<'b> PunchHelloFrame: Package<S::PacketAssembler<'b>>,
    for<'b> PadTo20: Package<S::PacketAssembler<'b>>,
{
    type Output = ();

    fn recv_frame(
        &self,
        (_bind, pathway, link, frame): (BindUri, Pathway, Link, ReliableFrame),
    ) -> Result<Self::Output, qbase::error::Error> {
        tracing::debug!(target: "punch", %pathway, %link, frame = ?frame, "received reliable punch frame");
        match frame {
            ReliableFrame::AddAddress(add_address_frame) => {
                _ = self.recv_add_address_frame(add_address_frame);
            }
            ReliableFrame::PunchMeNow(punch_me_now_frame) => {
                _ = self.recv_punch_me_now(pathway, punch_me_now_frame);
            }
            ReliableFrame::RemoveAddress(remove_address_frame) => {
                self.recv_remove_address_frame(remove_address_frame);
            }
            ReliableFrame::PunchDone(frame) => {
                let punch_id = frame.punch_id().flip();
                match self.0.transaction.entry(punch_id) {
                    Entry::Occupied(mut entry) => {
                        let tx = entry.get_mut().1.clone();
                        _ = tx.recv_frame((link, frame));
                    }
                    Entry::Vacant(_) => {
                        tracing::debug!(target: "punch", %punch_id, frame = ?frame, %link, "received unexpected punch done frame");
                    }
                }
            }
            frame => {
                tracing::debug!(target: "punch", frame = ?frame, "received unexpected reliable punch frame");
            }
        };

        Ok(())
    }
}

impl<TX, PH, S> ReceiveFrame<(BindUri, Pathway, Link, PunchHelloFrame)> for ArcPuncher<TX, PH, S>
where
    TX: SendFrame<ReliableFrame> + Send + Sync + Clone + 'static,
    PH: ProductHeader<OneRttHeader> + Send + Sync + 'static,
    S: PacketSpace<OneRttHeader> + Send + Sync + 'static,
    for<'b> PunchDoneFrame: Package<S::PacketAssembler<'b>>,
    for<'b> PunchHelloFrame: Package<S::PacketAssembler<'b>>,
    for<'b> PadTo20: Package<S::PacketAssembler<'b>>,
{
    type Output = ();

    fn recv_frame(
        &self,
        (bind, pathway, link, frame): (BindUri, Pathway, Link, PunchHelloFrame),
    ) -> Result<Self::Output, qbase::error::Error> {
        tracing::debug!(target: "punch", %pathway, %link, frame = ?frame, "received punch hello frame");
        let punch_id = frame.punch_id().flip();

        // A broker confirmation alone does not prove that the peer can receive on this path.
        // Reply on the observed link so simultaneous active punches establish path evidence at
        // both endpoints even if one side's first Hello arrived before the NAT hole was open.
        if let Some(iface) = self.0.ifaces.borrow(&bind) {
            let puncher = self.0.clone();
            let (response_link, response_frame) = direct_punch_done_response(link, &frame);
            tokio::spawn(
                async move {
                    puncher
                        .send_direct_punch_done_with_retry(&iface, response_link, response_frame)
                        .await;
                }
                .instrument_in_current()
                .in_current_span(),
            );
        } else {
            tracing::debug!(target: "punch", %bind, %link, %punch_id, "cannot send direct PunchDone without interface");
        }

        match self.0.transaction.entry(punch_id) {
            Entry::Occupied(mut entry) => {
                let tx = entry.get_mut().1.clone();
                _ = tx.recv_frame((link, frame));
            }
            Entry::Vacant(_) => {
                tracing::trace!(target: "punch", %punch_id, frame = ?frame, %link, "received unsolicited punch hello, replying with broker PunchDone");
                self.0
                    .broker
                    .send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(&frame))]);
            }
        }

        Ok(())
    }
}

#[inline]
async fn dynamic_iface(
    bind_uri: &BindUri,
    ifaces: &Arc<InterfaceManager>,
    iface_factory: &Arc<dyn ProductIO>,
    quic_router: &Arc<QuicRouter>,
    stun_servers: &[SocketAddr],
) -> io::Result<(Interface, StunClient)> {
    const MIN_PORT: u16 = 1024;
    const MAX_PORT: u16 = u16::MAX;
    let (ip_family, device, _port) = bind_uri.as_iface_bind_uri().ok_or_else(|| {
        let error = "Invalid bind uri, expected bind uri with iface schema";
        io::Error::new(io::ErrorKind::InvalidInput, error)
    })?;
    let port = rand::random::<u16>() % (MAX_PORT - MIN_PORT) + MIN_PORT;
    let bind_uri = format!(
        "iface://{ip_family}.{device}:{port}?{}=true",
        BindUri::TEMPORARY_PROP
    );
    let bind_uri = BindUri::from_str(bind_uri.as_str())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    ifaces
        .bind(bind_uri, iface_factory.clone())
        .await
        .with_components_mut(|components, iface| {
            // Ensure this temporary iface can receive+deliver QUIC packets to the connection.
            // Must use the connection-owned router.
            components.init_with(|| QuicRouterComponent::new(quic_router.clone()));

            let local_addr = iface.bound_addr()?;
            let stun_server = *stun_servers
                .iter()
                .find(|addr| addr.is_ipv4() == local_addr.is_ipv4())
                .ok_or_else(|| io::Error::other("No STUN server matches local address family"))?;
            let stun_router = components
                .init_with(|| {
                    let ref_iface = iface.downgrade();
                    StunRouterComponent::new(ref_iface)
                })
                .router();
            let stun_client = components
                .init_with(|| {
                    let client =
                        StunClient::new(iface.downgrade(), stun_router.clone(), stun_server, None);
                    StunClientComponent::new(client)
                })
                .client();
            components.init_with(|| {
                ReceiveAndDeliverPacket::builder(iface.downgrade())
                    .quic_router(quic_router.clone())
                    .stun_router(stun_router)
                    .init()
            });
            Ok((iface.to_owned(), stun_client))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simultaneous_active_punch_confirms_on_the_observed_link() {
        let link = Link::new(
            "192.0.2.10:50000".parse().unwrap(),
            "198.51.100.20:60000".parse().unwrap(),
        );
        let hello = PunchHelloFrame::new(7, 11, 13);

        let (response_link, response) = direct_punch_done_response(link, &hello);

        assert_eq!(response_link, link);
        assert_eq!(response.local_seq(), 11);
        assert_eq!(response.remote_seq(), 7);
        assert_eq!(response.probe_id(), 13);
    }

    #[test]
    fn direct_pairing_rejects_loopback_to_non_loopback() {
        let bind: BindUri = "inet://127.0.0.1:50000".parse().unwrap();
        let local_addr: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let remote_addr: SocketAddr = "203.0.113.10:4433".parse().unwrap();
        let local = EndpointAddr::direct(local_addr);
        let remote = EndpointAddr::direct(remote_addr);

        let error = build_validated_way(&bind, local, remote, local_addr, remote_addr)
            .expect_err("mixed loopback scope must be rejected");
        assert_eq!(
            error,
            qinterface::component::route::InvalidWay::LoopbackScopeMismatch
        );
    }

    #[test]
    fn direct_pairing_accepts_loopback_to_loopback() {
        let bind: BindUri = "inet://127.0.0.1:50000".parse().unwrap();
        let local_addr: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let local = EndpointAddr::direct(local_addr);
        let remote = EndpointAddr::direct(remote_addr);

        let (_, link, pathway) = build_validated_way(&bind, local, remote, local_addr, remote_addr)
            .expect("matching loopback scope must be retained");
        assert_eq!(link, Link::new(local_addr, remote_addr));
        assert_eq!(pathway, Pathway::new(local, remote));
    }

    #[test]
    fn direct_pairing_preserves_a_wildcard_local_link() {
        let bind: BindUri = "inet://0.0.0.0:50000".parse().unwrap();
        let local_addr: SocketAddr = "0.0.0.0:50000".parse().unwrap();
        let remote_addr: SocketAddr = "203.0.113.10:4433".parse().unwrap();
        let local = EndpointAddr::direct("192.0.2.10:50000".parse().unwrap());
        let remote = EndpointAddr::direct(remote_addr);

        let (_, link, pathway) = build_validated_way(&bind, local, remote, local_addr, remote_addr)
            .expect("wildcard source selection belongs to IO");

        assert_eq!(link, Link::new(local_addr, remote_addr));
        assert_eq!(pathway, Pathway::new(local, remote));
    }

    #[test]
    fn mixed_direct_agent_pair_is_rejected() {
        let direct = EndpointAddr::direct("127.0.0.1:50000".parse().unwrap());
        let agent = EndpointAddr::with_agent(
            "127.0.0.1:20004".parse().unwrap(),
            "198.51.100.10:40000".parse().unwrap(),
        );
        assert!(matches!(
            validate_endpoint_pair(direct, agent),
            Err(ResolvePathError::UnsupportedEndpointPair)
        ));
    }

    fn bind_uri() -> BindUri {
        "inet://127.0.0.1:0".parse().expect("valid bind uri")
    }

    fn endpoint_addr() -> EndpointAddr {
        EndpointAddr::direct("127.0.0.1:34567".parse().expect("socket addr"))
    }

    #[test]
    fn guarded_add_local_address_rejects_absent_endpoint_without_mutating() {
        let mut address_book = AddressBook::default();
        let bind_uri = bind_uri();
        let endpoint_addr = endpoint_addr();
        let local_addr: SocketAddr = "127.0.0.1:45678".parse().expect("socket addr");

        let error = add_local_address_when_endpoint_present_locked(
            &mut address_book,
            LocalEndpointGuard {
                bind_uri: &bind_uri,
                key: interface_endpoint_key(endpoint_addr),
                endpoint: endpoint_addr,
            },
            LocalAddressAdvertisement {
                bind_uri: bind_uri.clone(),
                addr: local_addr,
                nat_type: NatType::FullCone,
                tire: 7,
            },
        )
        .expect_err("absent endpoint must be rejected");

        assert_eq!(error.to_string(), "local endpoint removed");
        assert!(address_book.get_local_address(&0).is_none());
    }

    #[test]
    fn guarded_add_local_address_returns_frame_for_present_endpoint() {
        let mut address_book = AddressBook::default();
        let bind_uri = bind_uri();
        let endpoint_addr = endpoint_addr();
        let advertised_bind_uri: BindUri =
            "inet://127.0.0.1:45678".parse().expect("valid bind uri");
        let local_addr: SocketAddr = "127.0.0.1:45678".parse().expect("socket addr");

        address_book.upsert_local_endpoint(
            bind_uri.clone(),
            interface_endpoint_key(endpoint_addr),
            endpoint_addr,
        );

        let frame = add_local_address_when_endpoint_present_locked(
            &mut address_book,
            LocalEndpointGuard {
                bind_uri: &bind_uri,
                key: interface_endpoint_key(endpoint_addr),
                endpoint: endpoint_addr,
            },
            LocalAddressAdvertisement {
                bind_uri: advertised_bind_uri.clone(),
                addr: local_addr,
                nat_type: NatType::RestrictedCone,
                tire: 7,
            },
        )
        .expect("present endpoint must add local address");

        assert_eq!(*frame, local_addr);
        assert_eq!(frame.seq_num(), 0);
        assert_eq!(frame.tire(), 7);
        assert_eq!(frame.nat_type(), NatType::RestrictedCone);
        assert_eq!(
            address_book.get_local_address(&0),
            Some((advertised_bind_uri, frame))
        );
    }

    #[test]
    fn guarded_dynamic_local_address_rejects_absent_endpoint_without_retaining_iface() {
        let mut address_book = AddressBook::default();
        let bind_uri = bind_uri();
        let endpoint_addr = endpoint_addr();
        let dynamic_bind: BindUri = "inet://127.0.0.1:45678".parse().expect("valid bind uri");
        let local_addr: SocketAddr = "127.0.0.1:45678".parse().expect("socket addr");

        let (result, retain_dynamic_iface) = add_guarded_dynamic_local_address_locked(
            &mut address_book,
            LocalEndpointGuard {
                bind_uri: &bind_uri,
                key: interface_endpoint_key(endpoint_addr),
                endpoint: endpoint_addr,
            },
            LocalAddressAdvertisement {
                bind_uri: dynamic_bind,
                addr: local_addr,
                nat_type: NatType::Dynamic,
                tire: 7,
            },
        );

        let error = result.expect_err("absent endpoint must be rejected");
        assert_eq!(error.to_string(), "local endpoint removed");
        assert!(!retain_dynamic_iface);
        assert!(address_book.get_local_address(&0).is_none());
    }

    #[test]
    fn guarded_dynamic_local_address_returns_frame_and_retains_iface_for_present_endpoint() {
        let mut address_book = AddressBook::default();
        let bind_uri = bind_uri();
        let endpoint_addr = endpoint_addr();
        let dynamic_bind: BindUri = "inet://127.0.0.1:45678".parse().expect("valid bind uri");
        let local_addr: SocketAddr = "127.0.0.1:45678".parse().expect("socket addr");

        address_book.upsert_local_endpoint(
            bind_uri.clone(),
            interface_endpoint_key(endpoint_addr),
            endpoint_addr,
        );

        let (result, retain_dynamic_iface) = add_guarded_dynamic_local_address_locked(
            &mut address_book,
            LocalEndpointGuard {
                bind_uri: &bind_uri,
                key: interface_endpoint_key(endpoint_addr),
                endpoint: endpoint_addr,
            },
            LocalAddressAdvertisement {
                bind_uri: dynamic_bind.clone(),
                addr: local_addr,
                nat_type: NatType::Dynamic,
                tire: 7,
            },
        );

        let frame = result.expect("present endpoint must add local address");
        assert!(retain_dynamic_iface);
        assert_eq!(*frame, local_addr);
        assert_eq!(frame.seq_num(), 0);
        assert_eq!(frame.tire(), 7);
        assert_eq!(frame.nat_type(), NatType::Dynamic);
        assert_eq!(
            address_book.get_local_address(&0),
            Some((dynamic_bind, frame))
        );
    }

    #[test]
    fn endpoint_advertisement_key_uses_bind_and_interface_endpoint_key() {
        let bind = bind_uri();
        let agent: SocketAddr = "192.0.2.10:20004".parse().expect("agent addr");
        let outer: SocketAddr = "198.51.100.10:30000".parse().expect("outer addr");
        let key = InterfaceEndpointKey::Agent(agent);
        let endpoint = EndpointAddr::with_agent(agent, outer);
        let resource = LocalEndpointAdvertisementResource::new_for_test(
            bind.clone(),
            key,
            endpoint,
            7,
            bind.clone(),
            outer,
        );

        assert_eq!(resource.bind_uri(), &bind);
        assert_eq!(resource.key(), key);
        assert_eq!(resource.endpoint(), endpoint);
        assert_eq!(resource.seq_num(), 7);
        assert_eq!(resource.advertised_addr(), outer);
    }

    #[test]
    fn stale_agent_advertisement_guard_rejects_replaced_endpoint() {
        let mut address_book = AddressBook::default();
        let bind = bind_uri();
        let agent: SocketAddr = "192.0.2.10:20004".parse().expect("agent addr");
        let key = InterfaceEndpointKey::Agent(agent);
        let first = EndpointAddr::with_agent(agent, "198.51.100.10:30000".parse().expect("outer"));
        let second = EndpointAddr::with_agent(agent, "198.51.100.11:30001".parse().expect("outer"));

        address_book.upsert_local_endpoint(bind.clone(), key, first);
        address_book.upsert_local_endpoint(bind.clone(), key, second);

        assert!(agent_endpoint_is_current(&address_book, &bind, key, second));
        assert!(!agent_endpoint_is_current(&address_book, &bind, key, first));
    }
}
