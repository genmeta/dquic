use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::{Arc, LazyLock, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use qbase::net::{AddrFamily, Family};
use tokio::time::Instant;

pub static SCHEDULER: LazyLock<Arc<Mutex<Scheduler>>> = LazyLock::new(|| Arc::new(Mutex::new(Scheduler::new())));

const MAX_SOCKETS_PER_DEVICE: u32 = 300;
const MAX_PORTS_PER_DEVICE: u32 = 600;
const MAX_TOTAL_SOCKETS: u32 = 600;
const MAX_TOTAL_PORTS: u32 = 1200;
const PORT_COOLING_INTERVAL: Duration = Duration::from_secs(60);

pub struct Scheduler {
    devices: HashMap<DeviceKey, DeviceLedger>,
    pub(crate) total_sockets: u32,
    pub(crate) total_ports: u32,
    cooling: VecDeque<(Instant, u32)>,
    waiters: VecDeque<Waker>,
}

impl Scheduler {
    fn new() -> Self {
        Self { devices: HashMap::new(), total_sockets: 0, total_ports: 0, cooling: VecDeque::new(), waiters: VecDeque::new() }
    }

    fn reap_cooling(&mut self) {
        let now = Instant::now();
        self.cooling.retain(|(time, count)| {
            if now - *time > PORT_COOLING_INTERVAL {
                self.total_ports = self.total_ports.saturating_sub(*count);
                false
            } else {
                true
            }
        });
    }

    fn global_available(&self) -> u32 {
        let by_socket = MAX_TOTAL_SOCKETS.saturating_sub(self.total_sockets);
        let by_port = MAX_TOTAL_PORTS.saturating_sub(self.total_ports);
        by_socket.min(by_port)
    }

    pub fn poll_allocate(&mut self, cx: &Context, dest: SocketAddr, device: String, count: u32) -> Poll<io::Result<u32>> {
        self.reap_cooling();
        let global_avail = self.global_available();

        let key = DeviceKey::new(device.clone(), dest.ip().family());
        let ledger = self.devices.entry(key).or_insert_with(DeviceLedger::new);
        ledger.reap_cooling();
        let device_avail = ledger.available();
        let granted = global_avail.min(device_avail).min(count);

        tracing::trace!(target: "punch",
            global_avail, device_avail, granted, count,
            total_sockets = self.total_sockets, total_ports = self.total_ports,
            "Poll allocate"
        );

        if granted > 0 {
            ledger.sockets += granted;
            ledger.ports += granted;
            *ledger.per_dest.entry(dest).or_insert(0) += granted;

            self.total_sockets += granted;
            self.total_ports += granted;

            tracing::trace!(target: "punch", ?dest, device, granted, "Port allocated");
            Poll::Ready(Ok(granted))
        } else {
            if !self.waiters.iter().any(|w| w.will_wake(cx.waker())) {
                self.waiters.push_back(cx.waker().clone());
            }
            tracing::trace!(target: "punch", ?dest, device, count, "Port allocation pending");
            Poll::Pending
        }
    }

    pub fn release_port(&mut self, count: u32, dst: SocketAddr, device: String) -> io::Result<()> {
        let key = DeviceKey::new(device.clone(), dst.ip().family());

        let ledger = self.devices.get_mut(&key).ok_or_else(|| {
            tracing::trace!(target: "punch", ?dst, device, "Device not found");
            io::Error::other("device not found")
        })?;

        if ledger.sockets < count {
            tracing::trace!(target: "punch", sockets = ledger.sockets, count, ?dst, "Insufficient sockets");
            return Err(io::Error::other("insufficient sockets"));
        }
        let dest_count = ledger.per_dest.get(&dst).copied().unwrap_or(0);
        if dest_count < count {
            tracing::trace!(target: "punch", ?dst, dest_count, count, "Socket count mismatch");
            return Err(io::Error::other("socket count mismatch"));
        }

        // Device: release sockets immediately, ports enter cooling
        ledger.sockets -= count;
        let now = Instant::now();
        ledger.cooling.push_back((now, count));
        if dest_count > count {
            ledger.per_dest.insert(dst, dest_count - count);
        } else {
            ledger.per_dest.remove(&dst);
        }

        // Global: release sockets immediately, ports enter cooling
        self.total_sockets = self.total_sockets.saturating_sub(count);
        self.cooling.push_back((now, count));

        tracing::trace!(target: "punch", ?dst, device, count, "Port released");

        for waker in self.waiters.drain(..) {
            waker.wake();
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DeviceKey {
    device: String,
    family: Family,
}

impl DeviceKey {
    fn new(device: String, family: Family) -> Self {
        Self { device, family }
    }
}

struct DeviceLedger {
    sockets: u32,
    ports: u32,
    cooling: VecDeque<(Instant, u32)>,
    per_dest: HashMap<SocketAddr, u32>,
}

impl DeviceLedger {
    fn new() -> Self {
        Self { sockets: 0, ports: 0, cooling: VecDeque::new(), per_dest: HashMap::new() }
    }

    fn reap_cooling(&mut self) {
        let now = Instant::now();
        self.cooling.retain(|(time, count)| {
            if now - *time > PORT_COOLING_INTERVAL {
                self.ports = self.ports.saturating_sub(*count);
                false
            } else {
                true
            }
        });
    }

    fn available(&self) -> u32 {
        let by_socket = MAX_SOCKETS_PER_DEVICE.saturating_sub(self.sockets);
        let by_port = MAX_PORTS_PER_DEVICE.saturating_sub(self.ports);
        by_socket.min(by_port)
    }
}
