use std::{
    collections::HashSet,
    io,
    net::SocketAddr,
    ops::Deref,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use dashmap::{DashMap, DashSet, Entry};
use qbase::{
    frame::{
        AddAddressFrame, PunchDoneFrame, PunchHelloFrame, PunchMeNowFrame, ReliableFrame,
        RemoveAddressFrame,
        io::{ReceiveFrame, SendFrame},
    },
    net::{
        AddrFamily, NatType,
        addr::EndpointAddr,
        route::{Line, Link, Route},
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
    component::route::{QuicRouter, QuicRouterComponent},
    io::{IO, IoExt, ProductIO},
    manager::InterfaceManager,
};
use tokio::{task::AbortHandle, time::timeout};
use tracing::Instrument as _;

use crate::{
    PathWay,
    addr::AddressBook,
    nat::{client::StunClientComponent, router::StunRouterComponent},
    punch::{
        predictor::{PacketSendFn, PortPredictor},
        tx::{AsPunchId, PunchId, Transaction},
    },
    route::ReceiveAndDeliverPacket,
};

type StunClient<I = WeakInterface> = crate::nat::client::StunClient<I>;
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
// Birthday attack timeout: must exceed PortPredictor's full run time (~6s for 300 probes × 20ms)
const BIRTHDAY_TIMEOUT: Duration = Duration::from_secs(8);

// Quantity
const MAX_RETRIES: usize = 5;
const COLLISION_PORTS: u32 = 800;

pub struct ArcPuncher<TX, PH, S>(Arc<Puncher<TX, PH, S>>);

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
    punch_history: DashSet<PunchId>,
    product_header: PH,
    packet_space: Arc<S>,
    ifaces: Arc<InterfaceManager>,
    iface_factory: Arc<dyn ProductIO>,
    quic_router: Arc<QuicRouter>,
    stun_servers: Arc<[SocketAddr]>,
    address_book: Mutex<AddressBook>,
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
            transaction: DashMap::new(),
            punch_history: DashSet::new(),
            product_header,
            packet_space,
            ifaces,
            iface_factory,
            quic_router,
            stun_servers,
            address_book: Mutex::new(AddressBook::default()),
            punch_ifaces: DashMap::new(),
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
            let puncher = self.clone();
            let ifaces = self.0.ifaces.clone();
            let iface_factory = self.0.iface_factory.clone();
            let stun_servers = self.0.stun_servers.clone();
            let quic_router = self.0.quic_router.clone();

            // Inherent termination: dynamic address publication performs one probe
            // and sends at most one AddAddress frame before returning.
            tokio::spawn(
                async move {
                    let (iface, stun_client) =
                        dynamic_iface(&bind_uri, &ifaces, &iface_factory, &quic_router, &stun_servers)
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
                        tokio::spawn(
                            async move { ifaces.unbind(dynamic_bind).await }.in_current_span(),
                        );
                    })?;
                    puncher
                        .0
                        .punch_ifaces
                        .insert(dynamic_bind.clone(), iface.clone());

                    let mut address_book = puncher.0.address_book.lock().unwrap();
                    let frame =
                        address_book.add_local_address(dynamic_bind.clone(), outer, tire, nat_type)?;
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
            return Ok(());
        }
        let mut address_book = self.0.address_book.lock().unwrap();
        let frame = address_book.add_local_address(bind_uri.clone(), local_addr, tire, nat_type)?;
        tracing::trace!(target: "punch", bind_uri = %bind_uri, %local_addr, nat_type = ?nat_type, "sending AddAddress frame");
        self.0.broker.send_frame([ReliableFrame::AddAddress(frame)]);
        Ok(())
    }

    pub fn add_local_endpoint(
        &self,
        bind: BindUri,
        addr: EndpointAddr,
    ) -> io::Result<Vec<(BindUri, Link, PathWay)>> {
        let mut address_book = self.0.address_book.lock().unwrap();
        address_book.add_local_endpoint(bind.clone(), addr)?;
        let mut ways = Vec::new();
        for (remote_ep, source) in address_book.remote_endpoint().iter() {
            if let Ok(way) = self.resolve_punch_connection(&bind, &addr, remote_ep, source) {
                ways.push(way);
            }
        }
        Ok(ways)
    }

    pub fn add_peer_endpoint(
        &self,
        endpoint: EndpointAddr,
        source: qresolve::Source,
    ) -> io::Result<Vec<(BindUri, Link, PathWay)>> {
        let mut address_book = self.0.address_book.lock().unwrap();
        address_book.add_peer_endpoint(endpoint, source.clone())?;
        let mut ways = Vec::new();
        for (bind, local_ep) in address_book.local_endpoint().iter() {
            if let Ok(way) = self.resolve_punch_connection(bind, local_ep, &endpoint, &source) {
                ways.push(way);
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
        if self.0.punch_history.contains(&punch_id) {
            tracing::debug!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", Some(local.nat_type()), Some(add_address_frame.nat_type())), "punch already completed, skipping");
            return Ok(());
        }
        match self.0.transaction.entry(punch_id) {
            Entry::Occupied(_) => {
                tracing::debug!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", Some(local.nat_type()), Some(add_address_frame.nat_type())), "dup transaction for punch");
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
                            puncher.0.punch_history.insert(punch_id);
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
        pathway: PathWay,
        punch_me_now_frame: PunchMeNowFrame,
    ) -> io::Result<()> {
        let punch_id = punch_me_now_frame.punch_id().flip();
        if self.0.punch_history.contains(&punch_id) {
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
                tracing::debug!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", Some(local_address.nat_type()), Some(punch_me_now_frame.nat_type())), "received punch me now frame, start passive punch");
                async move {
                    let result = puncher
                        .punch_passively(bind, &local_address, &punch_me_now_frame, tx)
                        .await;
                    puncher.0.punch_history.insert(punch_id);
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
        tracing::debug!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "starting active punch");

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
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "strategy: Remote FullCone, sending direct Hello");
                let iface = ifaces
                    .borrow(&bind_uri)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                let time = Duration::from_millis(100);
                for i in 0..5 {
                    tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "sending Hello expecting Hello(Done) or receiving Hello");
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
                            tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "received Hello, sending broker PunchDone confirmation");
                            broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(&punch_hello))]);
                            return Ok(());
                        }
                        _ = tx.wait_punch_done() => {
                            tracing::debug!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "punch success");
                            return Ok(());
                        }
                    }
                }
                tracing::debug!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "punch failed");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 2. Local Dynamic, Remote Symmetric -> New Interface & Birthday Attack
            // Send PunchMeNow, expect PunchMeNow. After receiving, start collision, expect Hello(Done).
            (Dynamic, Symmetric) => {
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "strategy: Local Dynamic, Remote Symmetric, new interface & birthday attack");
                // TODO: Creating a new iface is not strictly necessary; could reuse an available temporary address.
                let (iface, stun_client) = dynamic_iface(&bind_uri).await?;

                let bind_uri = iface.bind_uri();
                punch_ifaces.insert(bind_uri.clone(), iface.clone());
                let outer_addr = stun_client.outer_addr().await?;
                punch_me_now.set_addr(outer_addr);
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "sending PunchMeNow expecting PunchMeNow then collision");
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
                            tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "received Hello, sending broker PunchDone confirmation");
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
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "sending PunchMeNow expecting PunchMeNow then rush");
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

                    tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "starting consolidated birthday attack");
                    match predictor
                        .predict(punch_id, tx.clone(), packet_send_fn)
                        .await
                    {
                        Ok(Some((bind_uri, iface))) => {
                            tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %bind_uri, "birthday attack succeeded");
                            self.0.punch_ifaces.insert(bind_uri.clone(), iface);
                            return Ok(());
                        }
                        Ok(None) => {
                            tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "birthday attack completed without success");
                        }
                        Err(e) => {
                            tracing::warn!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %e, "birthday attack failed");
                        }
                    }
                }

                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 4. Local Symmetric, Remote RestrictedCone -> Reverse Punching
            // Send PunchMeNow, expect remote to open hole and respond PunchMeNow. Then send direct Hello, expect Hello(Done).
            (Symmetric, RestrictedCone) => {
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "strategy: Local Symmetric, Remote RestrictedCone, reverse punching");
                tracing::trace!(target: "punch", %punch_id, "sending PunchMeNow expecting PunchMeNow then Hello");
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);
                if timeout(PUNCH_ME_NOW_TIMEOUT, tx.wait_punch_me_now())
                    .await
                    .is_err()
                {
                    tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "wait for PunchMeNow timeout, try to connect blindly");
                }

                let iface = ifaces
                    .borrow(&bind_uri)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                for i in 0..5 {
                    tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "sending Hello expecting Hello(Done)");
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
                        tracing::debug!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "punch success");
                        return Ok(());
                    }
                }

                tracing::debug!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "punch failed");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 5. Local Dynamic
            // New Interface, detect external address. Then send PunchMeNow and Hello, expect Hello(Done).
            (Dynamic, _) => {
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "strategy: Local Dynamic, new interface & send PunchMeNow + Hello");
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
                    tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "sending Hello expecting Hello(Done)");
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
                            tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "received Hello, sending broker PunchDone confirmation");
                            broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(&punch_hello))]);
                            return Ok(());
                        }
                        _ = tx.wait_punch_done() => {
                            tracing::debug!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "punch success");
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
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "strategy: General punching, send Hello with TTL & PunchMeNow");
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "sending PunchMeNow + Hello expecting Hello then Hello(Done)");
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);
                let iface = ifaces
                    .borrow(&bind_uri)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "sending Hello expecting Hello");
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
                    tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "sending broker PunchDone confirmation");
                    broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(
                        &punch_hello,
                    ))]);
                    tracing::debug!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "actively punch success");
                    return Ok(());
                }
                tracing::debug!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "punch failed");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 7. Local RestrictedPort, Remote Symmetric -> Birthday Attack (Hold Hole)
            // Send packets to 300 random ports, then notify with PunchMeNow. Expect Hello, then respond Hello(Done).
            (RestrictedPort, Symmetric) => {
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "strategy: Local RestrictedPort, Remote Symmetric, birthday attack hold hole");
                let iface = ifaces
                    .borrow(&bind_uri)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                self.0.collision(&iface, link, punch_id, KNOCK_TTL).await?;
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "sending PunchMeNow expecting Hello then Hello(Done)");
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);
                if let Ok((link, punch_hello)) =
                    timeout(BIRTHDAY_TIMEOUT, tx.wait_punch_hello()).await
                {
                    tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "sending broker PunchDone confirmation");
                    broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(
                        &punch_hello,
                    ))]);
                    tracing::debug!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "punch success with collision");
                    return Ok(());
                }
                return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout"));
            }
            // 8. Local Symmetric, Remote Dynamic
            // Hold holes on 30 random ports, send PunchMeNow. Expect Collision, then respond PunchMeNow.
            // Repeat until 300 sockets used.
            (Symmetric, Dynamic) => {
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "strategy: Local Symmetric, Remote Dynamic, hold holes & send PunchMeNow");

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
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "sending initial PunchMeNow for Dynamic strategy");
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);

                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "starting consolidated birthday attack for Dynamic strategy");
                match predictor
                    .predict(punch_id, tx.clone(), packet_send_fn)
                    .await
                {
                    Ok(Some((bind_uri, iface))) => {
                        tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %bind_uri, "birthday attack succeeded for Dynamic strategy");
                        self.0.punch_ifaces.insert(bind_uri.clone(), iface);
                        return Ok(());
                    }
                    Ok(None) => {
                        tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "birthday attack completed without success for Dynamic strategy");
                    }
                    Err(e) => {
                        tracing::warn!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %e, "birthday attack failed for Dynamic strategy");
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
        tracing::debug!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "starting passive punch");
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
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "passive strategy: Local Dynamic, Remote Symmetric, use new interface to collide");
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
                            tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "received Hello, sending broker PunchDone confirmation");
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
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "passive strategy: Local RestrictedPort, Remote Symmetric, open holes & send PunchMeNow");
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
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "sending PunchMeNow expecting Hello then Hello(Done)");
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);
                if let Ok((link, punch_hello)) =
                    tokio::time::timeout(BIRTHDAY_TIMEOUT, tx.wait_punch_hello()).await
                {
                    tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "sending broker PunchDone confirmation");
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

                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "starting consolidated birthday attack");
                match predictor
                    .predict(punch_id, tx.clone(), packet_send_fn)
                    .await
                {
                    Ok(Some((bind_uri, iface))) => {
                        tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %bind_uri, "birthday attack succeeded");
                        self.0.punch_ifaces.insert(bind_uri.clone(), iface);
                        return Ok(());
                    }
                    Ok(None) => {
                        tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "birthday attack completed without success");
                    }
                    Err(e) => {
                        tracing::warn!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %e, "birthday attack failed");
                    }
                }
            }
            // 4. Local RestrictedCone, Remote Symmetric
            // Reflect, Hello and  PunchmeNow, wait for hello, send Hello(Done)
            (RestrictedCone, Symmetric) => {
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "passive strategy: Local RestrictedCone, Remote Symmetric, reflect & send PunchMeNow");
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
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "sending PunchMeNow expecting Hello then Hello(Done)");
                let punch_hello_frame =
                    PunchHelloFrame::new(punch_id.local_seq, punch_id.remote_seq, DEFAULT_PROBE_ID);
                self.0
                    .send_packet(&iface, link, HELLO_TTL, punch_hello_frame)
                    .await?;
                broker.send_frame([ReliableFrame::PunchMeNow(punch_me_now)]);
                if let Ok((link, punch_hello)) =
                    tokio::time::timeout(PUNCH_TIMEOUT, tx.wait_punch_hello()).await
                {
                    tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "sending broker PunchDone confirmation");
                    broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(
                        &punch_hello,
                    ))]);
                    return Ok(());
                }
            }
            // 5. General Punching
            // Received PunchMeNow implies remote has opened hole. We send direct Hello, expecting Hello(Done).
            _ => {
                tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "passive strategy: General punching, send direct Hello");
                let iface = ifaces
                    .borrow(&bind)
                    .ok_or_else(|| io::Error::other("No interface found"))?;
                let time = Duration::from_millis(100);
                for i in 0..MAX_RETRIES {
                    tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), %link, "sending Hello expecting Hello(Done)");
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
                            tracing::trace!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "received Hello, sending broker PunchDone confirmation");
                            broker.send_frame([ReliableFrame::PunchDone(PunchDoneFrame::respond_to(&punch_hello))]);
                            return Ok(());
                        }
                        _ = tx.wait_punch_done() => {
                            tracing::debug!(target: "punch", %punch_id, nat_pair = %format!("{:?}->{:?}", local_nat, remote_nat), "passively punch success");
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
    ) -> io::Result<(BindUri, Link, PathWay)> {
        if let qresolve::Source::Mdns { nic, family } = source {
            let matches_iface = bind
                .as_iface_bind_uri()
                .is_some_and(|(lf, ln, _)| lf == *family && ln == nic.as_ref());
            if !matches_iface {
                return Err(io::Error::other(
                    "Bind URI does not match source constraint",
                ));
            }
        }
        if local == remote {
            return Err(io::Error::other("Local and remote endpoints are identical"));
        }

        let (local_addr, remote_addr) = self.extract_addresses(bind, local, remote)?;

        if local_addr.family() != remote_addr.family() {
            return Err(io::Error::other(
                "Local and remote addresses must be in the same address family",
            ));
        }

        let link = Link::new(local_addr, remote_addr);
        let pathway = PathWay::new(*local, *remote);

        Ok((bind.clone(), link, pathway))
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
            (
                Agent { .. },
                Agent { agent, .. },
            ) => {
                let iface = self.0.ifaces.borrow(bind).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Interface not found for bind URI: {:?}", bind),
                    )
                })?;
                Ok((iface.bound_addr()?, *agent))
            }
            _ => Err(io::Error::other(
                "Unsupported endpoint type combination for punching",
            )),
        }
    }
}

impl<TX, PH, S> ReceiveFrame<(BindUri, PathWay, Link, ReliableFrame)> for ArcPuncher<TX, PH, S>
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
        (_bind, pathway, link, frame): (BindUri, PathWay, Link, ReliableFrame),
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

impl<TX, PH, S> ReceiveFrame<(BindUri, PathWay, Link, PunchHelloFrame)> for ArcPuncher<TX, PH, S>
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
        (_bind, pathway, link, frame): (BindUri, PathWay, Link, PunchHelloFrame),
    ) -> Result<Self::Output, qbase::error::Error> {
        tracing::debug!(target: "punch", %pathway, %link, frame = ?frame, "received punch hello frame");
        let punch_id = frame.punch_id().flip();
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
