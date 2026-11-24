use super::*;

#[test]
fn bootstrap_nodes_are_deduplicated_and_snapshots_remain_stable() {
    let protocol = StunProtocol::new();
    assert!(protocol.stun_servers().is_empty());
    let v4 = "192.0.2.1:3478".parse().unwrap();
    let v6 = "[2001:db8::1]:3478".parse().unwrap();
    protocol.set_servers([v4, v6, v4]);
    let first = protocol.stun_servers();
    assert_eq!(&*first, &[v4, v6]);
    protocol.set_servers([v6]);
    assert_eq!(&*protocol.stun_servers(), &[v6]);
    assert_eq!(&*first, &[v4, v6]);
}
