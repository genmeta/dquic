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
