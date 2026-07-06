use std::{
    collections::{HashMap, VecDeque},
    future::poll_fn,
    io,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use qbase::{frame::PunchHelloFrame, net::route::Link};
use qinterface::{
    Interface,
    bind_uri::{BindUri, Scheme},
    component::route::{QuicRouter, QuicRouterComponent},
    io::{IO, ProductIO},
    manager::InterfaceManager,
};
use tracing::Instrument as _;

use crate::{
    punch::{
        scheduler::SCHEDULER,
        tx::{PunchId, Transaction},
    },
    route::ReceiveAndDeliverPacket,
};

const MAX_CONCURRENT_SOCKETS: usize = 60;
const MIN_PORT: u16 = 1024;
const PACKET_TTL: u8 = 64;
const FIRST_PROBE_ID: u32 = 1;
const MAX_PROBES: u32 = 300;
const PACING_INTERVAL: Duration = Duration::from_millis(20);

pub struct PortPredictor {
    ifaces: Arc<InterfaceManager>,
    factory: Arc<dyn ProductIO>,
    quic_router: Arc<QuicRouter>,
    bind_uri: BindUri,
    dst: SocketAddr,
    device: String,
    probes: ProbeTable,
    quota_held: u32,
    probes_created: u32,
}

#[derive(Debug)]
struct PendingProbe {
    bind_uri: BindUri,
    iface: Interface,
    port: u16,
}

pub type PacketSendFn = Arc<
    dyn Fn(
            &Interface,
            Link,
            u8,
            PunchHelloFrame,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + '_>>
        + Send
        + Sync,
>;

struct ProbeTable {
    pending: HashMap<u32, PendingProbe>,
    active_ports: HashMap<u16, u32>,
    order: VecDeque<u32>,
    next_probe_id: u32,
}

impl ProbeTable {
    fn new() -> Self {
        Self {
            pending: HashMap::new(),
            active_ports: HashMap::new(),
            order: VecDeque::new(),
            next_probe_id: FIRST_PROBE_ID,
        }
    }

    fn len(&self) -> usize {
        self.pending.len()
    }

    fn contains_port(&self, port: u16) -> bool {
        self.active_ports.contains_key(&port)
    }

    fn allocate_probe_id(&mut self) -> u32 {
        let probe_id = self.next_probe_id;
        self.next_probe_id = self.next_probe_id.wrapping_add(1);
        if self.next_probe_id < FIRST_PROBE_ID {
            self.next_probe_id = FIRST_PROBE_ID;
        }
        probe_id
    }

    fn insert(&mut self, probe_id: u32, bind_uri: BindUri, iface: Interface, port: u16) {
        self.active_ports.insert(port, probe_id);
        self.order.push_back(probe_id);
        self.pending.insert(
            probe_id,
            PendingProbe {
                bind_uri,
                iface,
                port,
            },
        );
    }

    fn take(&mut self, probe_id: u32) -> Option<PendingProbe> {
        let probe = self.pending.remove(&probe_id)?;
        self.active_ports.remove(&probe.port);
        self.order.retain(|&id| id != probe_id);
        Some(probe)
    }

    fn oldest_probe_id(&self) -> Option<u32> {
        self.order.front().copied()
    }

    fn pending_probe_ids(&self) -> Vec<u32> {
        self.pending.keys().copied().collect()
    }

    fn drain_bind_uris(&mut self) -> Vec<BindUri> {
        self.active_ports.clear();
        self.order.clear();
        self.pending
            .drain()
            .map(|(_, probe)| probe.bind_uri)
            .collect()
    }
}

impl PortPredictor {
    pub fn new(
        ifaces: Arc<InterfaceManager>,
        factory: Arc<dyn ProductIO>,
        quic_router: Arc<QuicRouter>,
        bind_uri: BindUri,
        dst: SocketAddr,
    ) -> io::Result<Self> {
        let device = match bind_uri.scheme() {
            Scheme::Iface => bind_uri.as_iface_bind_uri().unwrap().1.to_string(),
            Scheme::Inet => bind_uri.as_inet_bind_uri().unwrap().ip().to_string(),
            _ => return Err(io::ErrorKind::Unsupported.into()),
        };
        tracing::debug!(
            target: "punch",
            bind_uri = %bind_uri,
            dst = %dst,
            device = %device,
            "created port predictor"
        );
        Ok(Self {
            ifaces,
            factory,
            quic_router,
            bind_uri,
            dst,
            device,
            probes: ProbeTable::new(),
            quota_held: 0,
            probes_created: 0,
        })
    }

    fn release_quota(&mut self, count: u32) -> io::Result<()> {
        SCHEDULER
            .lock()
            .unwrap()
            .release_port(count, self.dst, self.device.clone())?;
        self.quota_held = self.quota_held.saturating_sub(count);
        Ok(())
    }

    fn port_to_bind_uri(&self, port: u16) -> BindUri {
        match self.bind_uri.scheme() {
            Scheme::Iface => {
                let (ip_family, device, _) = self.bind_uri.as_iface_bind_uri().unwrap();
                let bind_uri = format!(
                    "iface://{ip_family}.{device}:{port}?{}=true",
                    BindUri::TEMPORARY_PROP
                );
                BindUri::from_str(bind_uri.as_str()).unwrap_or_else(|e| {
                    panic!("Constructed invalid iface bind URI {bind_uri}: {e}")
                })
            }
            Scheme::Inet => {
                let socket_addr = self.bind_uri.as_inet_bind_uri().unwrap();
                let ip = socket_addr.ip();
                let bind_uri = format!("inet://{ip}:{port}?{}=true", BindUri::TEMPORARY_PROP);
                BindUri::from_str(bind_uri.as_str())
                    .unwrap_or_else(|e| panic!("Constructed invalid inet bind URI {bind_uri}: {e}"))
            }
            _ => unreachable!("Unsupported bind URI scheme for port prediction"),
        }
    }

    async fn release_interface(&mut self, bind_uri: BindUri) {
        self.ifaces.unbind(bind_uri).await;
        if let Err(error) = self.release_quota(1) {
            tracing::warn!(target: "punch", %error, "failed to release quota for interface");
        }
    }

    async fn release_probe(&mut self, probe_id: u32) -> bool {
        let Some(probe) = self.probes.take(probe_id) else {
            return false;
        };
        self.release_interface(probe.bind_uri).await;
        true
    }

    fn check_and_claim(&mut self, tx: &Transaction) -> Option<(BindUri, Interface)> {
        let (_, frame) = tx.try_punch_done()?;
        let probe_id = frame.probe_id();
        tracing::debug!(target: "punch", probe_id, "punchDone received, attempting to claim probe");
        self.claim_probe(probe_id)
    }

    async fn evict_if_needed(
        &mut self,
        tx: &Transaction,
    ) -> io::Result<Option<(BindUri, Interface)>> {
        while self.probes.len() >= MAX_CONCURRENT_SOCKETS {
            if let Some(result) = self.check_and_claim(tx) {
                return Ok(Some(result));
            }
            let Some(oldest_id) = self.probes.oldest_probe_id() else {
                break;
            };
            self.release_probe(oldest_id).await;
            tracing::trace!(target: "punch", oldest_id, active_probes = self.probes.len(), "evicted oldest probe");
        }
        Ok(None)
    }

    fn claim_probe(&mut self, probe_id: u32) -> Option<(BindUri, Interface)> {
        let probe = self.probes.take(probe_id)?;
        Some((probe.bind_uri, probe.iface))
    }

    async fn finalize(
        &mut self,
        result: (BindUri, Interface),
    ) -> io::Result<Option<(BindUri, Interface)>> {
        if let Err(error) = self.release_all().await {
            tracing::warn!(target: "punch", %error, "failed to cleanup remaining probes after success");
        }
        Ok(Some(result))
    }

    pub(super) async fn predict(
        &mut self,
        punch_id: PunchId,
        tx: Arc<Transaction>,
        packet_send_fn: PacketSendFn,
    ) -> io::Result<Option<(BindUri, Interface)>> {
        tracing::debug!(target: "punch", %punch_id, "starting port prediction");

        while self.probes_created < MAX_PROBES {
            // Check if PunchDone has been received for an active probe
            if let Some(result) = self.check_and_claim(tx.as_ref()) {
                if let Err(error) = self.release_quota(1) {
                    tracing::warn!(target: "punch", %error, "failed to release quota for claimed probe");
                }
                return self.finalize(result).await;
            }

            // Evict oldest probe if at capacity
            if let Some(result) = self.evict_if_needed(tx.as_ref()).await? {
                if let Err(error) = self.release_quota(1) {
                    tracing::warn!(target: "punch", %error, "failed to release quota for claimed probe");
                }
                return self.finalize(result).await;
            }

            // Create and send one probe
            if let Err(error) = self.create_and_send_probe(punch_id, &packet_send_fn).await {
                tracing::trace!(target: "punch", %punch_id, %error, "probe creation failed, continuing");
            }

            // Pacing: wait interval or return early if PunchDone arrives
            if tx.try_punch_done().is_none() {
                tokio::time::timeout(PACING_INTERVAL, tx.wait_punch_done())
                    .await
                    .ok();
            }
        }

        // Final check before giving up
        if let Some(result) = self.check_and_claim(tx.as_ref()) {
            if let Err(error) = self.release_quota(1) {
                tracing::warn!(target: "punch", %error, "failed to release quota for claimed probe");
            }
            return self.finalize(result).await;
        }

        if let Err(e) = self.release_all().await {
            tracing::error!(target: "punch", %punch_id, %e, "failed to cleanup resources");
        }
        tracing::debug!(target: "punch", %punch_id, probes_created = self.probes_created, "port prediction finished without match");
        Ok(None)
    }

    async fn create_and_send_probe(
        &mut self,
        punch_id: PunchId,
        packet_send_fn: &PacketSendFn,
    ) -> io::Result<()> {
        self.acquire_quota(1).await?;

        let (bind_uri, iface) = match self.create_interface().await {
            Ok(result) => result,
            Err(e) => {
                if let Err(error) = self.release_quota(1) {
                    tracing::warn!(target: "punch", %error, "failed to release quota on interface creation failure");
                }
                return Err(e);
            }
        };

        let socket_addr = match iface.bound_addr() {
            Ok(addr) => addr,
            Err(_) => {
                self.release_interface(bind_uri).await;
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "failed to get bound addr",
                ));
            }
        };

        let port = socket_addr.port();
        let probe_id = self.probes.allocate_probe_id();
        let link = Link::new(socket_addr, self.dst);
        let frame = PunchHelloFrame::new(punch_id.local_seq, punch_id.remote_seq, probe_id);

        if packet_send_fn(&iface, link, PACKET_TTL, frame)
            .await
            .is_ok()
        {
            self.probes.insert(probe_id, bind_uri, iface, port);
            self.probes_created += 1;
            Ok(())
        } else {
            self.release_interface(bind_uri).await;
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "failed to send probe",
            ))
        }
    }

    async fn create_interface(&mut self) -> io::Result<(BindUri, Interface)> {
        for _ in 0..10 {
            let port = rand::random::<u16>() % (u16::MAX - MIN_PORT) + MIN_PORT;
            if self.probes.contains_port(port) {
                continue;
            }
            let bind_addr = self.port_to_bind_uri(port);
            let bind_iface = self
                .ifaces
                .bind(bind_addr.clone(), self.factory.clone())
                .await;

            bind_iface.with_components_mut(|components, iface| {
                components.init_with(|| QuicRouterComponent::new(self.quic_router.clone()));
                components.init_with(|| {
                    ReceiveAndDeliverPacket::builder(iface.downgrade())
                        .quic_router(self.quic_router.clone())
                        .init()
                });
            });

            let iface = bind_iface.borrow();

            match iface.bound_addr() {
                Ok(_bound_addr) => {
                    return Ok((bind_addr, iface));
                }
                Err(_) => {
                    self.ifaces.unbind(bind_addr).await;
                    continue;
                }
            }
        }
        tracing::warn!(target: "punch", bind_uri = %self.bind_uri, dst = %self.dst, "failed to create interface after 10 attempts");
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "Failed to bind port after max retries",
        ))
    }

    async fn release_all(&mut self) -> io::Result<()> {
        tracing::debug!(target: "punch", active_probes = self.probes.len(), 
                      "starting resource cleanup");
        let probe_ids = self.probes.pending_probe_ids();
        for probe_id in probe_ids {
            self.release_probe(probe_id).await;
        }
        if self.quota_held > 0 {
            let orphaned = self.quota_held;
            tracing::warn!(target: "punch", orphaned, "releasing orphaned quota without pending probes");
            self.release_quota(orphaned)?;
        }
        tracing::debug!(target: "punch", "resource cleanup completed");
        Ok(())
    }

    async fn acquire_quota(&mut self, count: u32) -> io::Result<u32> {
        let count = count.min(MAX_PROBES - self.probes_created);
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!("Would exceed maximum limit of {}", MAX_PROBES),
            ));
        }
        let granted = poll_fn(|cx| {
            SCHEDULER
                .lock()
                .unwrap()
                .poll_allocate(cx, self.dst, self.device.clone(), count)
        })
        .await?;
        self.quota_held += granted;
        Ok(granted)
    }
}

impl Drop for PortPredictor {
    fn drop(&mut self) {
        let quota_held = self.quota_held;
        self.quota_held = 0;
        if quota_held > 0
            && let Err(error) =
                SCHEDULER
                    .lock()
                    .unwrap()
                    .release_port(quota_held, self.dst, self.device.clone())
        {
            tracing::warn!(target: "punch", %error, quota_held, "failed to release predictor quota during drop");
        }

        let bind_uris = self.probes.drain_bind_uris();
        let futures: Vec<_> = bind_uris
            .into_iter()
            .map(|bind_uri| self.ifaces.unbind(bind_uri))
            .collect();
        if !futures.is_empty() {
            tokio::spawn(
                async move {
                    futures::future::join_all(futures).await;
                }
                .in_current_span(),
            );
        }
    }
}
