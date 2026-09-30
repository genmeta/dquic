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

pub static SCHEDULER: LazyLock<Arc<Mutex<Scheduler>>> =
    LazyLock::new(|| Arc::new(Mutex::new(Scheduler::new())));

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
        Self {
            devices: HashMap::new(),
            total_sockets: 0,
            total_ports: 0,
            cooling: VecDeque::new(),
            waiters: VecDeque::new(),
        }
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

    pub fn poll_allocate(
        &mut self,
        cx: &Context,
        dest: SocketAddr,
        device: String,
        count: u32,
    ) -> Poll<io::Result<u32>> {
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
        Self {
            sockets: 0,
            ports: 0,
            cooling: VecDeque::new(),
            per_dest: HashMap::new(),
        }
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }

    fn test_cx() -> Context<'static> {
        Context::from_waker(Waker::noop())
    }

    #[test]
    fn test_scheduler_new() {
        let s = Scheduler::new();
        assert_eq!(s.total_sockets, 0);
        assert_eq!(s.total_ports, 0);
        assert!(s.devices.is_empty());
        assert!(s.cooling.is_empty());
    }

    #[test]
    fn test_allocation_success() {
        let mut s = Scheduler::new();
        let cx = test_cx();
        let dest = test_addr();

        let result = s.poll_allocate(&cx, dest, "eth0".into(), 10);
        assert!(matches!(result, Poll::Ready(Ok(10))));

        assert_eq!(s.total_sockets, 10);
        assert_eq!(s.total_ports, 10);

        let key = DeviceKey::new("eth0".into(), dest.ip().family());
        let ledger = s.devices.get(&key).unwrap();
        assert_eq!(ledger.sockets, 10);
        assert_eq!(ledger.ports, 10);
        assert_eq!(*ledger.per_dest.get(&dest).unwrap(), 10);
    }

    #[test]
    fn test_allocation_pending() {
        let mut s = Scheduler::new();
        let cx = test_cx();
        let dest = test_addr();

        // Fill device to its limit
        let _ = s.poll_allocate(&cx, dest, "eth0".into(), MAX_SOCKETS_PER_DEVICE);

        let result = s.poll_allocate(&cx, dest, "eth0".into(), 1);
        assert!(matches!(result, Poll::Pending));
        assert_eq!(s.waiters.len(), 1);
    }

    #[test]
    fn test_release_port() {
        let mut s = Scheduler::new();
        let cx = test_cx();
        let dest = test_addr();

        let _ = s.poll_allocate(&cx, dest, "eth0".into(), 10);
        assert!(s.release_port(10, dest, "eth0".into()).is_ok());

        assert_eq!(s.total_sockets, 0);
        assert_eq!(s.cooling.len(), 1);

        let key = DeviceKey::new("eth0".into(), dest.ip().family());
        let ledger = s.devices.get(&key).unwrap();
        assert_eq!(ledger.sockets, 0);
        assert!(!ledger.per_dest.contains_key(&dest));
    }

    #[test]
    fn test_global_limits() {
        let mut s = Scheduler::new();
        let cx = test_cx();
        let dest = test_addr();

        // Fill eth0 to device limit (300)
        let r1 = s.poll_allocate(&cx, dest, "eth0".into(), MAX_SOCKETS_PER_DEVICE);
        assert!(matches!(r1, Poll::Ready(Ok(c)) if c == MAX_SOCKETS_PER_DEVICE));
        assert_eq!(s.total_sockets, MAX_SOCKETS_PER_DEVICE);

        // Fill eth1 with remaining global capacity
        let remain = MAX_TOTAL_SOCKETS - MAX_SOCKETS_PER_DEVICE;
        let r2 = s.poll_allocate(&cx, dest, "eth1".into(), remain);
        assert!(matches!(r2, Poll::Ready(Ok(c)) if c == remain));
        assert_eq!(s.total_sockets, MAX_TOTAL_SOCKETS);

        // Global full → Pending
        let r3 = s.poll_allocate(&cx, dest, "eth0".into(), 1);
        assert!(matches!(r3, Poll::Pending));
    }

    #[test]
    fn test_device_limits() {
        let mut s = Scheduler::new();
        let cx = test_cx();
        let dest = test_addr();

        let r = s.poll_allocate(&cx, dest, "eth0".into(), MAX_SOCKETS_PER_DEVICE);
        assert!(matches!(r, Poll::Ready(Ok(c)) if c == MAX_SOCKETS_PER_DEVICE));

        let key = DeviceKey::new("eth0".into(), dest.ip().family());
        assert_eq!(s.devices.get(&key).unwrap().sockets, MAX_SOCKETS_PER_DEVICE);

        let r = s.poll_allocate(&cx, dest, "eth0".into(), MAX_SOCKETS_PER_DEVICE);
        assert!(matches!(r, Poll::Pending));
    }

    #[test]
    fn test_global_not_updated_on_device_pending() {
        let mut s = Scheduler::new();
        let cx = test_cx();
        let dest = test_addr();

        let _ = s.poll_allocate(&cx, dest, "eth0".into(), 10);

        // Manually max out the device
        let key = DeviceKey::new("eth0".into(), dest.ip().family());
        if let Some(ledger) = s.devices.get_mut(&key) {
            ledger.sockets = MAX_SOCKETS_PER_DEVICE;
            ledger.ports = MAX_PORTS_PER_DEVICE;
        }

        // Device full → Pending, global unchanged
        let r = s.poll_allocate(&cx, dest, "eth0".into(), 1);
        assert!(matches!(r, Poll::Pending));
        assert_eq!(s.total_sockets, 10);
        assert_eq!(s.total_ports, 10);
    }

    #[test]
    fn test_mutex_protection() {
        use std::sync::Arc;

        use tokio::sync::Mutex;

        let scheduler = Arc::new(Mutex::new(Scheduler::new()));
        let mut handles = vec![];

        for _ in 0..5 {
            let s = Arc::clone(&scheduler);
            handles.push(std::thread::spawn(move || {
                let mut s = s.blocking_lock();
                s.total_sockets += 1;
                s.total_ports += 1;
                true
            }));
        }

        for h in handles {
            assert!(h.join().unwrap());
        }

        let s = scheduler.try_lock().unwrap();
        assert_eq!(s.total_sockets, 5);
        assert_eq!(s.total_ports, 5);
    }
}
