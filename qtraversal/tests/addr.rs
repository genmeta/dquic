use std::net::SocketAddr;

use qbase::{
    frame::AddAddressFrame,
    net::{NatType, addr::EndpointAddr, route::Link},
};
use qtraversal::addr::PunchAddresses;

#[test]
fn default_group_prefers_nat_priority_and_falls_back_to_another_binding() {
    let mut addresses = PunchAddresses::default();
    let restricted = EndpointAddr::direct("127.0.0.1:5000".parse().unwrap());
    let cone = EndpointAddr::direct("127.0.0.1:5001".parse().unwrap());
    for (endpoint, nat) in [(restricted, NatType::RestrictedPort), (cone, NatType::FullCone)] {
        addresses.add_local(Link::new(endpoint.addr(), endpoint.addr()), 0, nat);
    }
    let remote = AddAddressFrame::new(9, "127.0.0.1:6000".parse().unwrap(), 0, NatType::FullCone);
    assert_eq!(addresses.pick_local(remote).unwrap().link.dst, cone.addr());
    addresses.remove_local_link(Link::new(cone.addr(), cone.addr()));
    assert_eq!(addresses.pick_local(remote).unwrap().link.dst, restricted.addr());
    let other_group = AddAddressFrame::new(9, *remote, 1, NatType::FullCone);
    assert!(addresses.pick_local(other_group).is_none());
    let other_family = AddAddressFrame::new(9, "[::1]:6000".parse().unwrap(), 0, NatType::FullCone);
    assert!(addresses.pick_local(other_family).is_none());
}

#[test]
fn a_shared_address_is_not_a_punch_target_even_with_a_different_peer_sequence() {
    let mut addresses = PunchAddresses::default();
    let endpoint = EndpointAddr::direct("127.0.0.1:5000".parse().unwrap());
    addresses.add_local(Link::new(endpoint.addr(), endpoint.addr()), 0, NatType::FullCone);
    let remote = AddAddressFrame::new(9, endpoint.addr(), 0, NatType::FullCone);
    assert!(addresses.pick_local(remote).is_none());
}

#[test]
fn local_and_remote_addresses_keep_connection_sequences() {
    let mut addresses = PunchAddresses::default();
    let bound: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let link = Link::new(bound, "198.51.100.1:5000".parse().unwrap());
    let local = addresses.add_local(link, 7, NatType::RestrictedCone);
    let remote = AddAddressFrame::new(9, "198.51.100.2:6000".parse().unwrap(), 7, NatType::FullCone);
    assert_eq!(addresses.pick_local(remote).unwrap().frame, local);
    assert!(addresses.add_remote(remote));
    assert!(!addresses.add_remote(remote));
    assert_eq!(addresses.remove_local_link(link).len(), 1);
    assert!(addresses.pick_local(remote).is_none());
}

#[test]
fn loopback_and_bridge_candidates_cannot_pair_in_either_direction() {
    let loopback = EndpointAddr::direct("127.0.0.1:5000".parse().unwrap());
    let bridge = EndpointAddr::direct("192.168.215.0:5001".parse().unwrap());
    for (local, remote) in [(loopback, bridge), (bridge, loopback)] {
        let mut addresses = PunchAddresses::default();
        addresses.add_local(Link::new(local.addr(), local.addr()), 0, NatType::RestrictedPort);
        let remote = AddAddressFrame::new(9, remote.addr(), 0, NatType::RestrictedPort);
        assert!(addresses.pick_local(remote).is_none());
    }
    let mut addresses = PunchAddresses::default();
    addresses.add_local(Link::new(bridge.addr(), bridge.addr()), 0, NatType::RestrictedPort);
    let public = AddAddressFrame::new(9, "8.8.8.8:6000".parse().unwrap(), 0, NatType::RestrictedPort);
    assert!(addresses.pick_local(public).is_some(), "private-to-public NAT candidates remain valid");
}

#[test]
fn removing_a_link_preserves_another_socket_with_the_same_outer_address() {
    let mut addresses = PunchAddresses::default();
    let outer = "8.8.8.8:5000".parse().unwrap();
    let first = Link::new("192.168.1.2:5000".parse().unwrap(), outer);
    let second = Link::new("192.168.1.3:5000".parse().unwrap(), outer);
    let first_frame = addresses.add_local(first, 0, NatType::RestrictedCone);
    let second_frame = addresses.add_local(second, 0, NatType::RestrictedCone);
    let removed = addresses.remove_local_link(first);
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].seq_num.into_u64(), u64::from(first_frame.seq_num()));
    assert_eq!(addresses.local_for_seq(second_frame.seq_num()).unwrap().link, second);
    assert_eq!(addresses.local_frames(), vec![second_frame]);
}
