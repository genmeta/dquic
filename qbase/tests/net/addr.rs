use qbase::net::addr::*;

#[test]
fn matches_peer_allows_nat_across_non_loopback_scopes() {
    let endpoints = ["192.168.1.10:4433", "8.8.4.4:50000", "100.64.0.1:4433"]
        .map(|addr| EndpointAddr::direct(addr.parse().unwrap()));
    for local in endpoints {
        for peer in endpoints {
            assert_eq!(local.matches_peer(peer), local != peer);
        }
    }
    let local = endpoints[0];
    assert!(!local.matches_peer(local));
    for invalid_peer in [
        "0.0.0.0:443",
        "1.1.1.1:0",
        "224.0.0.1:443",
        "255.255.255.255:443",
        "[::1]:443",
    ] {
        assert!(!local.matches_peer(EndpointAddr::direct(invalid_peer.parse().unwrap())));
    }
}

#[test]
fn loopback_peers_match_in_both_families_including_mapped_ipv4() {
    for (local, peer, non_loopback) in [
        ("127.0.0.1:4433", "127.0.0.2:443", "1.1.1.1:443"),
        ("127.0.0.1:4433", "127.0.0.2:443", "192.168.1.10:443"),
        ("[::1]:4433", "[::1]:443", "[2001:4860:4860::8888]:443"),
        (
            "[::ffff:127.0.0.1]:4433",
            "[::ffff:127.0.0.2]:443",
            "[fd00::1]:443",
        ),
    ] {
        let local = EndpointAddr::direct(local.parse().unwrap());
        let peer = EndpointAddr::direct(peer.parse().unwrap());
        let non_loopback = EndpointAddr::direct(non_loopback.parse().unwrap());
        assert!(local.matches_peer(peer));
        assert!(!local.matches_peer(non_loopback));
        assert!(!non_loopback.matches_peer(local));
    }
}

#[test]
fn matches_peer_validates_mediated_addresses() {
    let local = EndpointAddr::mediate(
        "127.0.0.1:20002".parse().unwrap(),
        "8.8.4.4:50000".parse().unwrap(),
    );
    let peer = EndpointAddr::mediate(
        "127.0.0.1:20003".parse().unwrap(),
        "1.0.0.1:60000".parse().unwrap(),
    );
    assert!(local.matches_peer(peer));
    assert!(!EndpointAddr::direct(*local).matches_peer(peer));
    for outer in [
        "0.0.0.0:50000",
        "8.8.4.4:0",
        "224.0.0.1:50000",
        "[fd00::1]:50000",
    ] {
        let invalid = EndpointAddr::mediate(*local, outer.parse().unwrap());
        assert!(!invalid.matches_peer(peer));
        assert!(!peer.matches_peer(invalid));
    }
}

#[test]
fn ipv4_public_reachability() {
    for addr in [
        "8.8.8.8:443",
        "192.0.0.9:443",
        "192.0.0.10:443",
        "192.31.196.1:443",
    ] {
        assert!(
            EndpointAddr::direct(addr.parse().unwrap()).is_globally_routable(),
            "{addr} should be publicly reachable"
        );
    }

    for addr in [
        "0.0.0.0:443",
        "10.0.0.1:443",
        "100.64.0.1:443",
        "127.0.0.1:443",
        "169.254.1.1:443",
        "172.16.0.1:443",
        "192.0.0.1:443",
        "192.0.2.1:443",
        "192.88.99.1:443",
        "192.168.1.1:443",
        "198.18.0.1:443",
        "198.51.100.1:443",
        "203.0.113.1:443",
        "224.0.0.1:443",
        "240.0.0.1:443",
        "255.255.255.255:443",
    ] {
        assert!(
            !EndpointAddr::direct(addr.parse().unwrap()).is_globally_routable(),
            "{addr} should not be publicly reachable"
        );
    }
}

#[test]
fn ipv6_public_reachability() {
    for addr in [
        "[64:ff9b::1]:443",
        "[2001:1::1]:443",
        "[2001:1::2]:443",
        "[2001:1::3]:443",
        "[2001:3::1]:443",
        "[2001:4:112::1]:443",
        "[2001:20::1]:443",
        "[2001:30::1]:443",
        "[2001:4860:4860::8888]:443",
    ] {
        assert!(
            EndpointAddr::direct(addr.parse().unwrap()).is_globally_routable(),
            "{addr} should be publicly reachable"
        );
    }

    for addr in [
        "[::]:443",
        "[::1]:443",
        "[::2]:443",
        "[::ffff:c000:201]:443",
        "[64:ff9b:1::1]:443",
        "[100::1]:443",
        "[100:0:0:1::1]:443",
        "[2001::1]:443",
        "[2001:1::4]:443",
        "[2001:2::1]:443",
        "[2001:10::1]:443",
        "[2001:db8::1]:443",
        "[2002::1]:443",
        "[3fff::1]:443",
        "[4000::1]:443",
        "[5f00::1]:443",
        "[fd00::1]:443",
        "[fec0::1]:443",
        "[fe80::1]:443",
        "[ff02::1]:443",
    ] {
        assert!(
            !EndpointAddr::direct(addr.parse().unwrap()).is_globally_routable(),
            "{addr} should not be publicly reachable"
        );
    }
}

#[test]
fn mediate_endpoint_is_publicly_reachable_through_its_agent() {
    assert!(
        EndpointAddr::mediate(
            "8.8.8.8:3478".parse().unwrap(),
            "192.168.1.2:50000".parse().unwrap(),
        )
        .is_globally_routable()
    );
}
