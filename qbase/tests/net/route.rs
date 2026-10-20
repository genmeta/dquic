use qbase::net::{addr::EndpointAddr, route::*};

#[test]
fn pathway_scope_classifies_remote_endpoints() {
    let local = "127.0.0.1:4433".parse::<EndpointAddr>().unwrap();
    for (remote, expected) in [
        ("127.0.0.1:4433", Scope::Loopback),
        ("[::1]:4433", Scope::Loopback),
        ("[::ffff:127.0.0.1]:4433", Scope::Loopback),
        ("192.168.1.1:4433", Scope::Internal),
        ("169.254.1.1:4433", Scope::Internal),
        ("[fd00::1]:4433", Scope::Internal),
        ("[fe80::1]:4433", Scope::Internal),
        ("[::ffff:192.168.1.1]:4433", Scope::Internal),
        ("1.1.1.1:4433", Scope::External),
        ("[2001:4860:4860::8888]:4433", Scope::External),
        ("8.8.8.8:3478-192.168.1.1:4433", Scope::External),
    ] {
        let pathway = Pathway::new(local, remote.parse().unwrap());
        for scope in [Scope::Loopback, Scope::Internal, Scope::External] {
            assert_eq!(
                pathway.belongs_to(scope.into()),
                scope == expected,
                "{remote}",
            );
        }
        assert!(pathway.belongs_to(Scopes::ALL), "{remote}");
        assert_eq!(
            pathway.belongs_to(Scope::Loopback | Scope::Internal),
            expected != Scope::External,
            "{remote}",
        );
    }
}

#[test]
fn pathway_scope_excludes_unroutable_remote_endpoints() {
    let local = "127.0.0.1:4433".parse::<EndpointAddr>().unwrap();
    for remote in [
        "0.0.0.0:4433",
        "192.0.2.1:4433",
        "224.0.0.1:4433",
        "[::]:4433",
        "[2001:db8::1]:4433",
    ] {
        let pathway = Pathway::new(local, remote.parse().unwrap());
        assert!(!pathway.belongs_to(Scopes::ALL), "{remote}");
    }
}

#[test]
fn test_endpoint_addr_from_str() {
    // Test direct format
    let addr = "127.0.0.1:8080".parse::<EndpointAddr>().unwrap();
    assert!(matches!(addr, EndpointAddr::Direct { .. }));

    // Test agent format
    let addr = "127.0.0.1:8080-192.168.1.1:9000"
        .parse::<EndpointAddr>()
        .unwrap();
    assert!(matches!(addr, EndpointAddr::Mediate { .. }));

    // Test with whitespace
    let addr = "  127.0.0.1:8080  -  192.168.1.1:9000  "
        .parse::<EndpointAddr>()
        .unwrap();
    assert!(matches!(addr, EndpointAddr::Mediate { .. }));

    // Test invalid format
    assert!("invalid".parse::<EndpointAddr>().is_err());
}
