use std::{
    collections::{HashMap, VecDeque},
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use qbase::{frame::PunchHelloFrame, net::route::Link};
use qprotocol::{Dock, EphemeralSocket, UdpSocket};

use super::{
    scheduler::SCHEDULER,
    tx::{PunchId, Transaction},
};

const MAX_CONCURRENT_SOCKETS: usize = 60;
const MIN_PORT: u16 = 1024;
const MAX_PROBES: u32 = 300;
const PACING_INTERVAL: Duration = Duration::from_millis(20);
const FIRST_PROBE_ID: u32 = 1;
const PACKET_TTL: u8 = 64;

struct PendingProbe {
    socket: EphemeralSocket,
    port: u16,
}

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

    fn allocate_probe_id(&mut self) -> u32 {
        let id = self.next_probe_id;
        self.next_probe_id = self.next_probe_id.wrapping_add(1).max(FIRST_PROBE_ID);
        id
    }

    fn insert(&mut self, id: u32, socket: EphemeralSocket, port: u16) {
        self.active_ports.insert(port, id);
        self.order.push_back(id);
        self.pending.insert(id, PendingProbe { socket, port });
    }

    fn take(&mut self, id: u32) -> Option<EphemeralSocket> {
        let probe = self.pending.remove(&id)?;
        self.active_ports.remove(&probe.port);
        self.order.retain(|&pending| pending != id);
        Some(probe.socket)
    }
}

pub(super) struct PortPredictor {
    bound: SocketAddr,
    dst: SocketAddr,
    device: String,
    probes: ProbeTable,
    quota_held: u32,
    probes_created: u32,
}

impl PortPredictor {
    pub(super) fn new(bound: SocketAddr, dst: SocketAddr) -> io::Result<Self> {
        let source = Dock::global().find_socket(bound).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "source socket unavailable")
        })?;
        let device = match source.bound_device() {
            Some(device) => device.name().to_owned(),
            None => bound.ip().to_string(),
        };
        Ok(Self {
            bound,
            dst,
            device,
            probes: ProbeTable::new(),
            quota_held: 0,
            probes_created: 0,
        })
    }

    async fn acquire_quota(&mut self) -> io::Result<()> {
        poll_fn(|cx| {
            SCHEDULER
                .lock()
                .unwrap()
                .poll_allocate(cx, self.dst, self.device.clone(), 1)
        })
        .await?;
        self.quota_held += 1;
        Ok(())
    }

    fn release_quota(&mut self) -> io::Result<()> {
        SCHEDULER
            .lock()
            .unwrap()
            .release_port(1, self.dst, self.device.clone())?;
        self.quota_held -= 1;
        Ok(())
    }

    fn create_socket(&self) -> io::Result<EphemeralSocket> {
        let port = MIN_PORT + rand::random::<u16>() % (u16::MAX - MIN_PORT);
        let mut target = self.bound;
        target.set_port(port);
        EphemeralSocket::bind(target)
    }

    fn take_matching_done(&mut self, tx: &Transaction) -> Option<EphemeralSocket> {
        let (_, done) = tx.try_punch_done()?;
        self.probes.take(done.probe_id())
    }

    fn release_probe(&mut self, id: u32) -> io::Result<()> {
        if self.probes.take(id).is_some() {
            self.release_quota()?;
        }
        Ok(())
    }

    fn release_all(&mut self) -> io::Result<()> {
        let ids = self.probes.pending.keys().copied().collect::<Vec<_>>();
        for id in ids {
            self.release_probe(id)?;
        }
        Ok(())
    }

    async fn create_and_send_probe<F, Fut>(&mut self, punch_id: PunchId, send: &F) -> io::Result<()>
    where
        F: Fn(Arc<UdpSocket>, Link, u8, PunchHelloFrame) -> Fut + Send + Sync,
        Fut: Future<Output = io::Result<()>> + Send,
    {
        self.acquire_quota().await?;
        self.probes_created += 1;
        let result = async {
            let socket = self.create_socket()?;
            let local = socket.udp_socket().local_addr()?;
            let probe_id = self.probes.allocate_probe_id();
            let hello = PunchHelloFrame::new(punch_id.local_seq, punch_id.remote_seq, probe_id);
            send(
                socket.udp_socket().clone(),
                Link::new(local, self.dst),
                PACKET_TTL,
                hello,
            )
            .await?;
            self.probes.insert(probe_id, socket, local.port());
            Ok(())
        }
        .await;
        if result.is_err() {
            self.release_quota()?;
        }
        result
    }

    /// Keep the original 300-probe matrix branch and its 60-socket/20ms pacing.
    pub(super) async fn predict<F, Fut>(
        &mut self,
        punch_id: PunchId,
        tx: Arc<Transaction>,
        send: F,
    ) -> io::Result<Option<EphemeralSocket>>
    where
        F: Fn(Arc<UdpSocket>, Link, u8, PunchHelloFrame) -> Fut + Send + Sync,
        Fut: Future<Output = io::Result<()>> + Send,
    {
        while self.probes_created < MAX_PROBES {
            if let Some(socket) = self.take_matching_done(&tx) {
                self.release_quota()?;
                self.release_all()?;
                return Ok(Some(socket));
            }
            while self.probes.pending.len() >= MAX_CONCURRENT_SOCKETS {
                let Some(oldest) = self.probes.order.front().copied() else {
                    break;
                };
                self.release_probe(oldest)?;
            }
            if let Err(error) = self.create_and_send_probe(punch_id, &send).await {
                tracing::trace!(target: "punch", %error, "probe send failed");
            }
            if tx.try_punch_done().is_none() {
                let _ = tokio::time::timeout(PACING_INTERVAL, tx.wait_punch_done()).await;
            }
        }
        if let Some(socket) = self.take_matching_done(&tx) {
            self.release_quota()?;
            self.release_all()?;
            return Ok(Some(socket));
        }
        self.release_all()?;
        Ok(None)
    }
}

impl Drop for PortPredictor {
    fn drop(&mut self) {
        if self.quota_held > 0 {
            let _ = SCHEDULER.lock().unwrap().release_port(
                self.quota_held,
                self.dst,
                self.device.clone(),
            );
            self.quota_held = 0;
        }
    }
}
