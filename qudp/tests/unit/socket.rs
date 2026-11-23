use std::net::{Ipv6Addr, SocketAddrV6};

use super::*;

#[test]
fn scope_addr_preserves_link_local_zones_when_system_selects_the_interface() {
    for scope in [0, 7] {
        let addr = SocketAddrV6::new("fe80::1".parse().unwrap(), 4433, 0x12345, scope).into();
        assert_eq!(scope_addr(addr, 0).unwrap(), addr);
    }
}

#[test]
fn scope_addr_fills_link_local_scope_and_preserves_flowinfo() {
    let index = 7;
    let ip = "fe80::1".parse().unwrap();
    let addr = SocketAddrV6::new(ip, 4433, 0x12345, 0);
    let expected = SocketAddrV6::new(ip, 4433, 0x12345, index);
    assert_eq!(scope_addr(addr.into(), index).unwrap(), expected.into());
    assert_eq!(scope_addr(expected.into(), index).unwrap(), expected.into());
}

#[test]
fn scope_addr_rejects_a_conflicting_link_local_interface() {
    let addr = SocketAddrV6::new("fe80::1".parse().unwrap(), 4433, 0x12345, 8);
    let error = scope_addr(addr.into(), 7).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn scope_addr_preserves_addresses_without_a_link_local_zone() {
    let index = 7;
    for ip in [Ipv6Addr::LOCALHOST, Ipv6Addr::UNSPECIFIED, "2001:db8::1".parse().unwrap()] {
        let addr = SocketAddrV6::new(ip, 4433, 0x12345, 0).into();
        assert_eq!(scope_addr(addr, index).unwrap(), addr);
    }
    let addr = "127.0.0.1:4433".parse().unwrap();
    assert_eq!(scope_addr(addr, index).unwrap(), addr);
}
