use qbase::net::Family;

use super::*;

fn addr(value: &str) -> SocketAddr {
    value.parse().unwrap()
}

fn direct(value: &str) -> EndpointAddr {
    EndpointAddr::direct(addr(value))
}

fn mediate(agent: &str, outer: &str) -> EndpointAddr {
    EndpointAddr::mediate(addr(agent), addr(outer))
}

fn drain(receiver: &mut mpsc::UnboundedReceiver<AddressEvent>) -> Vec<AddressEvent> {
    std::iter::from_fn(|| receiver.try_recv().ok()).collect()
}

fn mdns(nic: &str, family: Family) -> Source {
    Source::Mdns {
        nic: nic.into(),
        family,
    }
}

#[test]
fn dns_sources_select_registered_interfaces_without_ip_inference() {
    let book = AddressBook::new();
    let lan0 = addr("192.168.1.10:4433");
    let lan1 = addr("192.168.1.10:4434");
    let unknown = addr("192.168.1.20:4433");
    let dev0 = qudp::BoundDevice::new("lan0", 7).unwrap();
    let dev1 = qudp::BoundDevice::new("lan1", 8).unwrap();
    book.insert(lan0, lan0.into(), Scope::Internal, Some(&dev0))
        .unwrap();
    book.insert(lan1, lan1.into(), Scope::Internal, Some(&dev1))
        .unwrap();
    book.insert(unknown, unknown.into(), Scope::Internal, None)
        .unwrap();
    let peer = direct("192.168.1.30:443");
    assert_eq!(
        book.pathways_to(peer, &mdns("lan0", Family::V4)),
        vec![Pathway::new(lan0.into(), peer)]
    );
    assert_eq!(
        book.pathways_to(peer, &mdns("lan1", Family::V4)),
        vec![Pathway::new(lan1.into(), peer)]
    );
    for source in [
        Source::System,
        Source::Dht,
        Source::Http {
            server: "dns".into(),
        },
        Source::H3 {
            server: "dns".into(),
        },
    ] {
        assert_eq!(book.pathways_to(peer, &source).len(), 3);
    }
    assert!(
        book.pathways_to(peer, &mdns("missing", Family::V4))
            .is_empty()
    );
    assert!(book.pathways_to(peer, &mdns("lan0", Family::V6)).is_empty());
    assert!(
        book.pathways_to(direct("[fd00::10]:443"), &mdns("lan0", Family::V6))
            .is_empty()
    );
    assert!(
        book.pathways_to(direct("127.0.0.1:443"), &mdns("lan0", Family::V4))
            .is_empty()
    );
    let public_peer = direct("1.1.1.1:443");
    assert_eq!(
        book.pathways_to(public_peer, &mdns("lan0", Family::V4)),
        vec![Pathway::new(lan0.into(), public_peer)]
    );
}

#[test]
fn aliases_share_interface_metadata_and_bound_removal_clears_it_for_reuse() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let inner = EndpointAddr::direct(bound);
    let outer = mediate("8.8.8.8:20002", "8.8.4.4:50000");
    let peer = mediate("1.1.1.1:3478", "1.0.0.1:60000");
    let source = mdns("lan0", Family::V4);
    let dev0 = qudp::BoundDevice::new("lan0", 7).unwrap();
    let dev1 = qudp::BoundDevice::new("lan1", 8).unwrap();
    book.insert(bound, inner, Scope::Internal, Some(&dev0))
        .unwrap();
    book.insert(bound, outer, Scope::External, Some(&dev0))
        .unwrap();
    assert_eq!(
        book.pathways_to(peer, &source),
        vec![Pathway::new(outer, peer)]
    );
    let new_outer = mediate("8.8.8.8:20002", "8.8.4.4:50001");
    let mut events = book.subscribe_punch(Scopes::ALL);
    drain(&mut events);
    assert!(matches!(
        book.insert(bound, new_outer, Scope::External, Some(&dev1)),
        Err(AddressBookError::ConflictingInterface(_))
    ));
    assert!(drain(&mut events).is_empty());
    assert_eq!(
        book.pathways_to(peer, &source),
        vec![Pathway::new(outer, peer)]
    );
    book.replace(outer, new_outer).unwrap();
    book.remove(inner);
    assert_eq!(
        book.pathways_to(peer, &source),
        vec![Pathway::new(new_outer, peer)]
    );
    book.remove_bound(bound);
    book.insert(bound, outer, Scope::External, None).unwrap();
    assert!(book.pathways_to(peer, &source).is_empty());
    assert_eq!(
        book.pathways_to(peer, &Source::System),
        vec![Pathway::new(outer, peer)]
    );
    book.remove_bound(bound);
    book.insert(bound, outer, Scope::External, Some(&dev1))
        .unwrap();
    assert!(book.pathways_to(peer, &source).is_empty());
    assert_eq!(
        book.pathways_to(peer, &mdns("lan1", Family::V4)),
        vec![Pathway::new(outer, peer)]
    );
}

#[test]
fn ipv6_scope_must_match_the_registered_interface_index() {
    let book = AddressBook::new();
    let matching = addr("[fe80::10%7]:4433");
    let conflicting = addr("[fe80::10%8]:4433");
    let device = qudp::BoundDevice::new("lan0", 7).unwrap();
    for bound in [matching, conflicting] {
        book.insert(bound, bound.into(), Scope::Internal, Some(&device))
            .unwrap();
    }
    let peer = direct("[fe80::20%7]:443");
    assert_eq!(
        book.pathways_to(peer, &mdns("lan0", Family::V6)),
        vec![Pathway::new(matching.into(), peer)]
    );
}

#[test]
fn interface_names_are_canonical_identifiers_without_string_guessing() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let device = qudp::BoundDevice::new("{adapter-id}", 7).unwrap();
    book.insert(bound, bound.into(), Scope::Internal, Some(&device))
        .unwrap();
    let peer = direct("192.168.1.20:443");
    assert_eq!(
        book.pathways_to(peer, &mdns("{adapter-id}", Family::V4)),
        vec![Pathway::new(bound.into(), peer)]
    );
    assert!(
        book.pathways_to(peer, &mdns("adapter-id", Family::V4))
            .is_empty()
    );
    assert!(
        book.pathways_to(peer, &mdns("Wi-Fi", Family::V4))
            .is_empty()
    );
}

#[test]
fn inner_binding_snapshot_rejects_a_zero_bound_port() {
    let book = AddressBook::new();
    let device = qudp::BoundDevice::new("lan0", 7).unwrap();
    book.insert(
        addr("192.168.1.12:0"),
        direct("192.168.1.12:4433"),
        Scope::Internal,
        Some(&device),
    )
    .unwrap();
    assert!(book.inner_bindings().is_empty());
}
