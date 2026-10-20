use std::{
    io,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use qbase::net::Family;
use qprotocol::bind_uri::{BindUri, ParseError, Scheme};

#[test]
fn invalid_uri() {
    assert!(matches!(
        BindUri::from_str("iface://"),
        Err(ParseError::InvalidUri(_))
    ));
}

#[test]
fn missing_scheme() {
    assert!(matches!(
        BindUri::from_str("invalid_uri"),
        Err(ParseError::NoScheme)
    ));
}

#[test]
fn invalid_scheme() {
    assert!(matches!(
        BindUri::from_str("invalid://example.com"),
        Err(ParseError::Unsupported(_))
    ));
}

#[test]
fn has_path() {
    assert!(matches!(
        BindUri::from_str("iface://v4.wlan0/1234"),
        Err(ParseError::Malformed)
    ));
}

#[test]
fn missing_ip_family() {
    assert!(matches!(
        BindUri::from_str("iface://wlan0:8080"),
        Err(ParseError::NoFamily)
    ));
}

#[test]
fn missing_port() {
    assert!(matches!(
        BindUri::from_str("iface://v4.wlan0"),
        Err(ParseError::NoPort)
    ));
}

#[test]
fn invalid_ip_family() {
    assert!(matches!(
        BindUri::from_str("iface://invalid.wlan0:8080"),
        Err(ParseError::UnknownFamily)
    ));
}

#[test]
fn invalid_ip_addr() {
    assert!(matches!(
        BindUri::from_str("inet://example.com:8080"),
        Err(ParseError::InvalidIpAddr(..))
    ));
}

#[test]
fn iface_bind_uri() {
    let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?temporary=true").unwrap();
    assert_eq!(bind_uri.scheme(), Scheme::Iface);
    let (family, interface, port) = bind_uri.as_iface_bind_uri().unwrap();
    assert_eq!(family, Family::V4);
    assert_eq!(interface, "wlan0");
    assert_eq!(port, 8080);
    assert_eq!(
        bind_uri.prop(BindUri::TEMPORARY_PROP).as_deref(),
        Some("true")
    );
}

#[test]
fn inet_bind_uri() {
    let bind_uri = BindUri::from_str("inet://127.0.0.1:7777").unwrap();
    assert_eq!(bind_uri.scheme(), Scheme::Inet);
    let addr = bind_uri.as_inet_bind_uri().unwrap();
    assert_eq!(
        addr,
        SocketAddr::new(IpAddr::V4("127.0.0.1".parse().unwrap()), 7777)
    );
    assert!(bind_uri.as_uri().query().is_none());
}

#[test]
fn interface_not_found() {
    let bind_uri = BindUri::from_str(
        "iface://v4.ygiubiougbuyasiudbahsdbadfbkjadbhvkjabvckagdoiuehfjoiajhrpfhrbovhaelvkamdjkfs:8080",
    )
    .unwrap();
    assert!(SocketAddr::try_from(bind_uri).is_err_and(|e| e.kind() == io::ErrorKind::NotFound))
}

#[test]
fn iface_binding_retains_device_index() {
    let (device_name, iface, ip) = netdev::get_interfaces()
        .into_iter()
        .find_map(|iface| {
            let device_name = iface
                .name
                .trim_start_matches('{')
                .trim_end_matches('}')
                .to_owned();
            iface
                .ipv4
                .first()
                .map(|ipnet| (device_name, iface.clone(), ipnet.addr()))
        })
        .expect("test host should have at least one IPv4 interface");

    let bind_uri = BindUri::from_str(&format!("iface://v4.{device_name}:8080")).unwrap();
    let binding = bind_uri.resolve_binding().unwrap();

    assert_eq!(binding.addr, SocketAddr::new(IpAddr::V4(ip), 8080));
    assert_eq!(
        binding.device.as_ref().map(|device| device.name.as_str()),
        Some(iface.name.as_str())
    );
    assert_eq!(
        binding.device.as_ref().map(|device| device.index),
        Some(iface.index)
    );
}

#[test]
fn to_socket_addr() {
    let bind_uri = BindUri::from_str("inet://127.0.0.1:8080").unwrap();
    assert_eq!(
        SocketAddr::try_from(bind_uri).unwrap(),
        "127.0.0.1:8080".parse().unwrap()
    );
}

#[test]
fn alloc_port() {
    let bind_uri = BindUri::from_str("inet://0.0.0.0:0").unwrap();
    assert_ne!(bind_uri.clone().alloc_port(), bind_uri.clone().alloc_port());
}

#[test]
fn reconcile_candidate_ignores_only_alloc_port_id() {
    let first = BindUri::from_str("inet://0.0.0.0:0")
        .expect("valid bind uri")
        .alloc_port();
    let second = BindUri::from_str("inet://0.0.0.0:0")
        .expect("valid bind uri")
        .alloc_port();

    assert_ne!(first, second, "full BindUri identity keeps alloc_port_id");
    assert!(
        first.matches_reconcile_candidate(&second),
        "reconciliation ignores alloc_port_id"
    );
    assert!(
        second.matches_reconcile_candidate(&first),
        "reconciliation matching is symmetric"
    );
}

#[test]
fn reconcile_candidate_keeps_bind_uri_props_semantic() {
    let base = BindUri::from_str("iface://v4.wlan0:0").expect("valid bind uri");

    let mut temporary = base.clone();
    temporary.add_prop(BindUri::TEMPORARY_PROP, "true");
    assert!(!base.matches_reconcile_candidate(&temporary));
    assert!(!temporary.matches_reconcile_candidate(&base));

    let mut stun = base.clone();
    stun.enable_stun();
    assert!(!base.matches_reconcile_candidate(&stun));
    assert!(!stun.matches_reconcile_candidate(&base));

    let stun_server = base.clone().with_stun_server("stun.example.com:3478");
    assert!(!base.matches_reconcile_candidate(&stun_server));
    assert!(!stun_server.matches_reconcile_candidate(&base));

    let relay = base.clone().with_relay("relay.example.com:3478");
    assert!(!base.matches_reconcile_candidate(&relay));
    assert!(!relay.matches_reconcile_candidate(&base));
}

#[test]
#[should_panic]
fn alloc_port_for_non_zero_port1() {
    let bind_uri = BindUri::from_str("inet://127.0.0.1:8080").unwrap();
    bind_uri.alloc_port();
}

#[test]
#[should_panic]
fn alloc_port_for_non_zero_port2() {
    let bind_uri = BindUri::from_str("inet://v4.lo:12345").unwrap();
    bind_uri.alloc_port();
}

#[test]
fn temporary() {
    let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?temporary=true").unwrap();
    assert!(bind_uri.is_temporary());
    let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?temporary=false").unwrap();
    assert!(!bind_uri.is_temporary());
    let bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
    assert!(!bind_uri.is_temporary());
    let bind_uri =
        BindUri::from_str("iface://v4.C5563ED1-2BC9-42C5-8177-59F2F0AF37C8:8080").unwrap();
    assert!(!bind_uri.is_temporary());

    let mut bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
    bind_uri.add_prop(BindUri::TEMPORARY_PROP, "true");
    assert_eq!(
        bind_uri.to_string(),
        "iface://v4.wlan0:8080/?temporary=true"
    );
    assert!(bind_uri.is_temporary());
}

#[test]
fn stun_enabled() {
    let mut bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
    assert!(!bind_uri.is_stun_enabled());

    bind_uri.enable_stun();
    assert!(bind_uri.is_stun_enabled());

    let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?stun=true").unwrap();
    assert!(bind_uri.is_stun_enabled());

    let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?stun=false").unwrap();
    assert!(!bind_uri.is_stun_enabled());
}

#[test]
fn stun_server() {
    let bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
    assert!(bind_uri.stun_server().is_none());

    let bind_uri = bind_uri.with_stun_server("stun.example.com:3478");
    assert_eq!(
        bind_uri.stun_server().as_deref(),
        Some("stun.example.com:3478")
    );

    let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?stun_server=stun.genmeta.net").unwrap();
    assert_eq!(bind_uri.stun_server().as_deref(), Some("stun.genmeta.net"));
}

#[test]
fn relay() {
    let bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
    assert!(bind_uri.relay().is_none());

    let bind_uri = bind_uri.with_relay("turn.example.com:3478");
    assert_eq!(bind_uri.relay().as_deref(), Some("turn.example.com:3478"));

    let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?relay=turn.genmeta.net").unwrap();
    assert_eq!(bind_uri.relay().as_deref(), Some("turn.genmeta.net"));
}
