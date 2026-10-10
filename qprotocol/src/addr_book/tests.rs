use std::sync::Barrier;

use AddressEvent::{Added, BoundRemoved, Removed};
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

#[test]
fn publishes_inner_to_mdns_and_outer_to_ddns() {
    let bound = addr("192.168.1.10:4433");
    let inner = EndpointAddr::direct(bound);
    let outer = direct("203.0.113.10:50000");
    let book = AddressBook::new();
    let mdns = book.subscribe_mdns(bound);
    let ddns = book.subscribe_ddns();

    book.insert(bound, inner, Scope::Internal, None).unwrap();
    book.insert(bound, outer, Scope::External, None).unwrap();

    assert_eq!(book.mdns_endpoints(bound).as_ref(), &[inner]);
    assert_eq!(book.ddns_endpoints().as_ref(), &[outer]);
    assert_eq!(mdns.borrow().as_ref(), &[inner]);
    assert_eq!(ddns.borrow().as_ref(), &[outer]);

    book.remove_bound(bound);
    assert!(book.mdns_endpoints(bound).is_empty());
    assert!(book.ddns_endpoints().is_empty());
    assert!(mdns.borrow().is_empty());
    assert!(ddns.borrow().is_empty());
}

#[test]
fn dns_snapshots_survive_without_receivers_and_only_relevant_watchers_change() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let other_bound = addr("192.168.1.11:4433");
    let inner = EndpointAddr::direct(bound);
    let outer = direct("8.8.4.4:50000");
    book.insert(bound, inner, Scope::Internal, None).unwrap();
    book.insert(bound, outer, Scope::External, None).unwrap();

    let mut ddns = book.subscribe_ddns();
    let mut mdns = book.subscribe_mdns(bound);
    let other_mdns = book.subscribe_mdns(other_bound);
    assert_eq!(ddns.borrow_and_update().as_ref(), &[outer]);
    assert_eq!(mdns.borrow_and_update().as_ref(), &[inner]);

    assert!(book.set_nat(bound, NatType::FullCone));
    assert!(!ddns.has_changed().unwrap());
    assert!(!mdns.has_changed().unwrap());
    assert!(!other_mdns.has_changed().unwrap());

    assert_eq!(book.remove(outer), Some(bound));
    assert!(ddns.has_changed().unwrap());
    assert!(ddns.borrow_and_update().is_empty());
    assert!(!mdns.has_changed().unwrap());

    assert_eq!(book.remove(inner), Some(bound));
    assert!(mdns.has_changed().unwrap());
    assert!(!ddns.has_changed().unwrap());
    assert!(!other_mdns.has_changed().unwrap());
    assert_eq!(book.nat(bound), Some(NatType::FullCone));
}

#[test]
fn punch_replays_ready_endpoints_and_refreshes_external_classifications() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let inner = EndpointAddr::direct(bound);
    let outer = direct("8.8.4.4:50000");
    let alias = direct("8.8.4.4:50001");
    let loopback = direct("127.0.0.1:4433");
    book.set_nat(bound, NatType::FullCone);
    book.insert(bound, inner, Scope::Internal, None).unwrap();
    book.insert(bound, outer, Scope::External, None).unwrap();
    book.insert(bound, alias, Scope::External, None).unwrap();
    book.insert(loopback.addr(), loopback, Scope::Internal, None)
        .unwrap();

    let mut external = book.subscribe_punch(Scope::External);
    let mut internal = book.subscribe_punch(Scope::Internal);
    let mut local = book.subscribe_punch(Scope::Loopback);
    assert_eq!(
        drain(&mut external),
        vec![
            Added {
                bound,
                endpoint: outer,
                nat: NatType::FullCone
            },
            Added {
                bound,
                endpoint: alias,
                nat: NatType::FullCone
            },
        ]
    );
    assert_eq!(
        drain(&mut internal),
        vec![Added {
            bound,
            endpoint: inner,
            nat: NatType::FullCone
        },]
    );
    assert_eq!(
        drain(&mut local),
        vec![Added {
            bound: loopback.addr(),
            endpoint: loopback,
            nat: NatType::FullCone,
        }]
    );

    assert!(book.set_nat(bound, NatType::RestrictedPort));
    assert_eq!(
        drain(&mut external),
        vec![
            Added {
                bound,
                endpoint: outer,
                nat: NatType::RestrictedPort
            },
            Added {
                bound,
                endpoint: alias,
                nat: NatType::RestrictedPort
            },
        ]
    );
    assert!(drain(&mut internal).is_empty());
    assert!(drain(&mut local).is_empty());
    assert!(!book.set_nat(bound, NatType::RestrictedPort));
    assert!(drain(&mut external).is_empty());
}

#[test]
fn external_advertisements_wait_for_nat_in_both_live_and_initial_subscriptions() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let inner = EndpointAddr::direct(bound);
    let outer = direct("8.8.4.4:50000");
    let alias = direct("8.8.4.4:50001");
    let mut live = book.subscribe_punch(Scopes::ALL);
    book.insert(bound, inner, Scope::Internal, None).unwrap();
    book.insert(bound, outer, Scope::External, None).unwrap();
    book.insert(bound, alias, Scope::External, None).unwrap();
    let mut replay = book.subscribe_punch(Scopes::ALL);
    let local = Added {
        bound,
        endpoint: inner,
        nat: NatType::FullCone,
    };
    assert_eq!(drain(&mut live), vec![local]);
    assert_eq!(drain(&mut replay), vec![local]);
    assert_eq!(book.nat(bound), None);
    assert_eq!(book.ddns_endpoints().as_ref(), &[outer, alias]);

    book.set_nat(bound, NatType::RestrictedCone);
    book.set_nat(bound, NatType::Symmetric);
    let expected = [NatType::RestrictedCone, NatType::Symmetric]
        .into_iter()
        .flat_map(|nat| {
            [outer, alias].map(|endpoint| Added {
                bound,
                endpoint,
                nat,
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(drain(&mut live), expected);
    assert_eq!(drain(&mut replay), expected);
    let mut classified = book.subscribe_punch(Scope::External);
    assert_eq!(drain(&mut classified), expected[2..]);
}

#[test]
fn endpoints_carry_current_classification_after_insertion_or_scope_reentry() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let inner = EndpointAddr::direct(bound);
    let outer = direct("8.8.4.4:50000");
    let mut events = book.subscribe_punch(Scope::External);
    book.insert(bound, inner, Scope::Internal, None).unwrap();
    book.set_nat(bound, NatType::RestrictedCone);
    assert!(drain(&mut events).is_empty());

    book.insert(bound, outer, Scope::External, None).unwrap();
    assert_eq!(
        drain(&mut events),
        vec![Added {
            bound,
            endpoint: outer,
            nat: NatType::RestrictedCone
        },]
    );
    book.remove(outer);
    assert_eq!(
        drain(&mut events),
        vec![Removed {
            bound,
            endpoint: outer
        }]
    );
    book.set_nat(bound, NatType::Symmetric);
    assert!(drain(&mut events).is_empty());
    book.insert(bound, outer, Scope::External, None).unwrap();
    assert_eq!(
        drain(&mut events),
        vec![Added {
            bound,
            endpoint: outer,
            nat: NatType::Symmetric
        },]
    );
}

#[test]
fn replacing_an_endpoint_keeps_nat_and_publishes_final_dns_snapshot() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let old = direct("8.8.4.4:50000");
    let new = direct("8.8.4.4:60000");
    book.insert(bound, old, Scope::External, None).unwrap();
    book.set_nat(bound, NatType::RestrictedPort);
    let mut events = book.subscribe_punch(Scope::External);
    drain(&mut events);
    let mut ddns = book.subscribe_ddns();
    assert_eq!(ddns.borrow_and_update().as_ref(), &[old]);

    book.replace(old, new).unwrap();
    assert_eq!(
        drain(&mut events),
        vec![
            Removed {
                bound,
                endpoint: old
            },
            Added {
                bound,
                endpoint: new,
                nat: NatType::RestrictedPort
            }
        ]
    );
    assert_eq!(ddns.borrow_and_update().as_ref(), &[new]);
    assert_eq!(book.nat(bound), Some(NatType::RestrictedPort));

    book.replace(new, new).unwrap();
    assert!(drain(&mut events).is_empty());
    assert!(!ddns.has_changed().unwrap());
}

#[test]
fn replacement_filters_old_and_new_scopes_independently() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let old = direct("127.0.0.1:4433");
    let new = EndpointAddr::direct(bound);
    book.insert(bound, old, Scope::Internal, None).unwrap();
    book.set_nat(bound, NatType::FullCone);
    let mut loopback = book.subscribe_punch(Scope::Loopback);
    let mut internal = book.subscribe_punch(Scope::Internal);
    let mut external = book.subscribe_punch(Scope::External);
    drain(&mut loopback);

    book.replace(old, new).unwrap();
    assert_eq!(
        drain(&mut loopback),
        vec![Removed {
            bound,
            endpoint: old
        }]
    );
    assert_eq!(
        drain(&mut internal),
        vec![Added {
            bound,
            endpoint: new,
            nat: NatType::FullCone
        },]
    );
    assert!(drain(&mut external).is_empty());

    book.replace(new, old).unwrap();
    assert_eq!(
        drain(&mut internal),
        vec![Removed {
            bound,
            endpoint: new
        }]
    );
    assert_eq!(
        drain(&mut loopback),
        vec![Added {
            bound,
            endpoint: old,
            nat: NatType::FullCone
        },]
    );
    assert!(drain(&mut external).is_empty());
}

#[test]
fn failed_mutations_preserve_directory_and_do_not_notify() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let old = direct("8.8.4.4:50000");
    let occupied = direct("1.1.1.1:50000");
    let absent = direct("1.0.0.1:50000");
    book.insert(bound, old, Scope::External, None).unwrap();
    book.insert(bound, occupied, Scope::External, None).unwrap();
    let mut events = book.subscribe_punch(Scope::External);
    drain(&mut events);
    let ddns = book.subscribe_ddns();
    let before = book.ddns_endpoints();

    assert!(matches!(
        book.replace(old, occupied),
        Err(AddressBookError::Duplicate(_))
    ));
    assert!(matches!(
        book.replace(absent, old),
        Err(AddressBookError::NotFound(_))
    ));
    assert!(matches!(
        book.insert(bound, old, Scope::Internal, None),
        Err(AddressBookError::Duplicate(_))
    ));
    assert!(book.remove(absent).is_none());
    assert_eq!(book.ddns_endpoints(), before);
    assert!(!ddns.has_changed().unwrap());
    assert!(drain(&mut events).is_empty());
}

#[test]
fn removing_a_binding_notifies_past_subscribers_and_clears_nat_for_reuse() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let inner = EndpointAddr::direct(bound);
    let outer = direct("8.8.4.4:50000");
    book.insert(bound, inner, Scope::Internal, None).unwrap();
    book.insert(bound, outer, Scope::External, None).unwrap();
    book.set_nat(bound, NatType::FullCone);
    let mut external = book.subscribe_punch(Scope::External);
    let mut internal = book.subscribe_punch(Scope::Internal);
    let mut local = book.subscribe_punch(Scope::Loopback);
    drain(&mut external);
    drain(&mut internal);

    book.remove(outer);
    assert_eq!(
        drain(&mut external),
        vec![Removed {
            bound,
            endpoint: outer
        }]
    );
    assert_eq!(book.remove_bound(bound), vec![inner]);
    assert_eq!(drain(&mut external), vec![BoundRemoved { bound }]);
    assert_eq!(
        drain(&mut internal),
        vec![
            Removed {
                bound,
                endpoint: inner
            },
            BoundRemoved { bound }
        ]
    );
    assert!(drain(&mut local).is_empty());
    assert_eq!(book.nat(bound), None);
    assert!(book.remove_bound(bound).is_empty());
    assert!(drain(&mut external).is_empty());
    assert!(drain(&mut internal).is_empty());

    book.insert(bound, outer, Scope::External, None).unwrap();
    assert!(drain(&mut external).is_empty());
    book.remove(outer);
    drain(&mut external);
    // Even when the last endpoint was individually removed and NAT was never known,
    // the subsequent binding withdrawal must still reach the previous subscriber.
    assert!(book.remove_bound(bound).is_empty());
    assert_eq!(drain(&mut external), vec![BoundRemoved { bound }]);
}

#[test]
fn disconnected_subscribers_do_not_interfere_with_remaining_receivers() {
    let book = AddressBook::new();
    let bound = addr("127.0.0.1:4433");
    let endpoint = EndpointAddr::direct(bound);
    let abandoned = book.subscribe_punch(Scopes::ALL);
    let mut active = book.subscribe_punch(Scopes::ALL);
    drop(abandoned);
    book.insert(bound, endpoint, Scope::Internal, None).unwrap();
    assert_eq!(
        drain(&mut active),
        vec![Added {
            bound,
            endpoint,
            nat: NatType::FullCone
        }]
    );
    assert_eq!(book.state.lock().unwrap().punch_subscribers.len(), 1);
    drop(book);
    assert_eq!(
        active.try_recv(),
        Err(mpsc::error::TryRecvError::Disconnected)
    );
}

#[test]
fn concurrent_subscription_and_updates_have_no_gap_or_duplicate_additions() {
    let bound = addr("192.168.1.10:4433");
    let old = EndpointAddr::direct(bound);
    let new = direct("192.168.1.10:4434");
    for _ in 0..64 {
        let book = AddressBook::new();
        let barrier = Barrier::new(2);
        std::thread::scope(|threads| {
            let writer = threads.spawn(|| {
                barrier.wait();
                book.insert(bound, old, Scope::Internal, None).unwrap();
                book.set_nat(bound, NatType::RestrictedPort);
                book.replace(old, new).unwrap();
            });
            barrier.wait();
            let mut events = book.subscribe_punch(Scope::Internal);
            let mdns = book.subscribe_mdns(bound);
            writer.join().unwrap();

            let mut endpoints = HashMap::new();
            for event in drain(&mut events) {
                match event {
                    Added {
                        bound,
                        endpoint,
                        nat: advertised,
                    } => {
                        assert_eq!(advertised, NatType::FullCone);
                        assert!(endpoints.insert(endpoint, bound).is_none());
                    }
                    Removed { bound, endpoint } => {
                        assert_eq!(endpoints.remove(&endpoint), Some(bound));
                    }
                    BoundRemoved { .. } => panic!("binding was not withdrawn"),
                }
            }
            assert_eq!(endpoints, HashMap::from([(new, bound)]));
            assert_eq!(book.nat(bound), Some(NatType::RestrictedPort));
            assert_eq!(mdns.borrow().as_ref(), &[new]);
        });
    }
}

#[test]
fn direct_pathways_exclude_loopback_for_non_loopback_peers_and_allow_nat() {
    let book = AddressBook::new();
    let first = addr("192.168.1.10:4433");
    let second = addr("192.168.1.20:4433");
    let loopback = addr("127.0.0.1:4433");
    let v6 = addr("[fd00::1]:4433");
    let v6_loopback = addr("[::1]:4433");
    for bound in [second, first, loopback, v6, v6_loopback] {
        book.insert(bound, EndpointAddr::direct(bound), Scope::Internal, None)
            .unwrap();
    }
    book.insert(first, direct("8.8.4.4:50000"), Scope::External, None)
        .unwrap();
    for peer in [direct("1.1.1.1:443"), direct("192.168.1.30:443")] {
        let mut expected = [first.into(), second.into(), direct("8.8.4.4:50000")]
            .map(|local| Pathway::new(local, peer));
        expected.sort_unstable();
        assert_eq!(book.pathways_to(peer, &Source::System), expected);
    }
    let v6_peer = direct("[2001:4860:4860::8888]:443");
    assert_eq!(
        book.pathways_to(v6_peer, &Source::System),
        vec![Pathway::new(v6.into(), v6_peer)]
    );
    assert!(
        book.pathways_to(loopback.into(), &Source::System)
            .is_empty()
    );
    for (peer, locals) in [
        (direct("127.0.0.1:4434"), vec![loopback.into()]),
        (direct("[::1]:4434"), vec![v6_loopback.into()]),
    ] {
        let mut expected = locals
            .into_iter()
            .map(|local| Pathway::new(local, peer))
            .collect::<Vec<_>>();
        expected.sort_unstable();
        assert_eq!(book.pathways_to(peer, &Source::System), expected);
    }
}

#[test]
fn mediated_pathways_require_an_existing_mediated_return_endpoint() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let outer = direct("8.8.4.4:50000");
    let local = mediate("8.8.8.8:20002", "8.8.4.4:50000");
    let peer = mediate("1.1.1.1:20002", "1.0.0.1:60000");
    book.insert(bound, bound.into(), Scope::Internal, None)
        .unwrap();
    book.insert(bound, outer, Scope::External, None).unwrap();
    assert!(book.pathways_to(peer, &Source::System).is_empty());
    book.insert(bound, local, Scope::External, None).unwrap();
    assert_eq!(
        book.pathways_to(peer, &Source::System),
        vec![Pathway::new(local, peer)]
    );
    let new = mediate("8.8.8.8:20002", "8.8.4.4:60000");
    book.replace(local, new).unwrap();
    assert_eq!(
        book.pathways_to(peer, &Source::System),
        vec![Pathway::new(new, peer)]
    );
    book.remove_bound(bound);
    assert!(book.pathways_to(peer, &Source::System).is_empty());
}

#[tokio::test]
async fn different_relays_keep_registered_local_endpoints_for_every_nat_type() {
    let book = AddressBook::new();
    let socket = Arc::new(UdpSocket::bind(addr("127.0.0.1:0")).unwrap());
    let bound = socket.local_addr().unwrap();
    let outer = direct("8.8.4.4:50000");
    let local = mediate("127.0.0.1:20002", "8.8.4.4:50000");
    let peer = mediate("127.0.0.1:20003", "1.0.0.1:60000");
    let protocol = crate::QuicProtocol::new();
    for endpoint in [bound.into(), outer, local] {
        protocol.register(endpoint, &socket).unwrap();
    }
    book.insert_inner(&socket, bound.into()).unwrap();
    book.insert_outer(&socket, outer).unwrap();
    book.insert_outer(&socket, local).unwrap();
    for nat in [
        NatType::RestrictedCone,
        NatType::RestrictedPort,
        NatType::Symmetric,
        NatType::Dynamic,
        NatType::FullCone,
    ] {
        book.set_nat(bound, nat);
        let paths = book.pathways_to(peer, &Source::System);
        assert_eq!(paths, vec![Pathway::new(local, peer)]);
        assert!(Arc::ptr_eq(
            &protocol.find_socket(paths[0].local()).unwrap(),
            &socket
        ));
        let direct_peer = direct("127.0.0.1:1");
        let expected = vec![Pathway::new(bound.into(), direct_peer)];
        assert_eq!(book.pathways_to(direct_peer, &Source::System), expected);
    }
    book.remove(local);
    assert!(book.pathways_to(peer, &Source::System).is_empty());
    protocol.unregister(bound);
    assert!(protocol.find_socket(local).is_none());
}

#[test]
fn invalid_bootstrap_endpoints_do_not_produce_candidates() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    book.insert(bound, bound.into(), Scope::Internal, None)
        .unwrap();
    for peer in [
        direct("0.0.0.0:443"),
        direct("1.1.1.1:0"),
        direct("224.0.0.1:443"),
        mediate("0.0.0.0:3478", "1.0.0.1:60000"),
        mediate("1.1.1.1:3478", "[2001:4860:4860::8888]:60000"),
    ] {
        assert!(book.pathways_to(peer, &Source::System).is_empty(), "{peer}");
    }
}

#[tokio::test]
async fn wildcard_socket_bindings_do_not_exclude_published_endpoints() {
    let socket = UdpSocket::bind(addr("0.0.0.0:0")).unwrap();
    let book = AddressBook::new();
    for (local, peer) in [
        (direct("8.8.4.4:50000"), direct("1.1.1.1:443")),
        (
            mediate("8.8.8.8:20002", "8.8.4.4:50000"),
            mediate("1.1.1.1:20002", "1.0.0.1:60000"),
        ),
    ] {
        book.insert_outer(&socket, local).unwrap();
        assert_eq!(
            book.pathways_to(peer, &Source::System),
            vec![Pathway::new(local, peer)]
        );
    }
}

fn mdns(nic: &str, family: Family) -> Source {
    Source::Mdns {
        nic: nic.into(),
        family,
    }
}

fn loopback_device() -> qudp::BoundDevice {
    let interface = netdev::get_interfaces()
        .into_iter()
        .find(|interface| {
            interface
                .ipv4
                .iter()
                .any(|ip| ip.addr() == std::net::Ipv4Addr::LOCALHOST)
        })
        .expect("loopback interface");
    qudp::BoundDevice::new(interface.name, interface.index).unwrap()
}

#[tokio::test]
async fn public_insertions_read_the_socket_binding_and_do_not_retain_it() {
    let device = loopback_device();
    let socket = Arc::new(UdpSocket::bind_to_device(addr("127.0.0.1:0"), device.clone()).unwrap());
    let bound = socket.local_addr().unwrap();
    let book = AddressBook::new();
    let inner = EndpointAddr::direct(bound);
    let outer = direct("8.8.4.4:50000");
    book.insert_inner(&socket, inner).unwrap();
    book.insert_outer(&socket, outer).unwrap();
    assert_eq!(
        book.state.lock().unwrap().interfaces.get(&bound),
        Some(&Some(device.clone()))
    );
    assert_eq!(book.mdns_endpoints(bound).as_ref(), &[inner]);
    assert_eq!(book.ddns_endpoints().as_ref(), &[outer]);
    let peer = direct("127.0.0.1:1");
    let expected = vec![Pathway::new(inner, peer)];
    assert_eq!(
        book.pathways_to(peer, &mdns(device.name(), Family::V4)),
        expected
    );

    let mut events = book.subscribe_punch(Scopes::ALL);
    drain(&mut events);
    assert!(matches!(
        book.insert_inner(&socket, inner),
        Err(AddressBookError::Duplicate(_))
    ));
    assert!(drain(&mut events).is_empty());

    let weak = Arc::downgrade(&socket);
    drop(socket);
    assert!(weak.upgrade().is_none());
    assert_eq!(book.mdns_endpoints(bound).as_ref(), &[inner]);
}

#[tokio::test]
async fn an_unscoped_socket_does_not_satisfy_an_mdns_interface_constraint() {
    let socket = UdpSocket::bind(addr("127.0.0.1:0")).unwrap();
    let bound = socket.local_addr().unwrap();
    let book = AddressBook::new();
    book.insert_inner(&socket, bound.into()).unwrap();
    book.insert_outer(&socket, direct("8.8.4.4:50000")).unwrap();
    assert_eq!(
        book.state.lock().unwrap().interfaces.get(&bound),
        Some(&None)
    );
    let peer = direct("127.0.0.1:1");
    let expected = vec![Pathway::new(bound.into(), peer)];
    assert_eq!(book.pathways_to(peer, &Source::System), expected);
    assert!(
        book.pathways_to(peer, &mdns(loopback_device().name(), Family::V4))
            .is_empty()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn post_binding_updates_metadata_and_requires_withdrawal_before_republication() {
    let mut socket = UdpSocket::bind(addr("127.0.0.1:0")).unwrap();
    let bound = socket.local_addr().unwrap();
    let book = AddressBook::new();
    book.insert_inner(&socket, bound.into()).unwrap();
    let device = loopback_device();
    socket.bind_device(device.name()).unwrap();
    assert_eq!(socket.bound_device(), Some(&device));
    let mut events = book.subscribe_punch(Scopes::ALL);
    drain(&mut events);
    assert!(matches!(
        book.insert_outer(&socket, direct("8.8.4.4:50000")),
        Err(AddressBookError::ConflictingInterface(_))
    ));
    assert!(book.ddns_endpoints().is_empty());
    assert!(drain(&mut events).is_empty());

    book.remove_bound(bound);
    book.insert_inner(&socket, bound.into()).unwrap();
    let peer = direct("127.0.0.1:1");
    assert_eq!(
        book.pathways_to(peer, &mdns(device.name(), Family::V4)),
        vec![Pathway::new(bound.into(), peer)]
    );
    assert!(
        socket
            .bind_device("missing-interface-for-address-book-test")
            .is_err()
    );
    assert_eq!(socket.bound_device(), Some(&device));
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
fn inner_binding_snapshot_filters_and_deduplicates_actual_metadata() {
    let book = AddressBook::new();
    let device = qudp::BoundDevice::new("lan0", 7).unwrap();
    let bound = addr("192.168.1.10:4433");
    book.insert(
        bound,
        direct("192.168.1.10:4433"),
        Scope::Internal,
        Some(&device),
    )
    .unwrap();
    book.insert(
        bound,
        direct("192.168.1.10:4434"),
        Scope::Internal,
        Some(&device),
    )
    .unwrap();
    book.insert(
        addr("127.0.0.1:4433"),
        direct("127.0.0.1:4433"),
        Scope::Loopback,
        Some(&device),
    )
    .unwrap();
    book.insert(
        addr("192.168.1.11:4433"),
        direct("192.168.1.11:4433"),
        Scope::Internal,
        None,
    )
    .unwrap();
    book.insert(
        addr("192.168.1.12:0"),
        direct("192.168.1.12:0"),
        Scope::Internal,
        Some(&device),
    )
    .unwrap();
    assert_eq!(book.inner_bindings(), vec![(bound, device)]);
    book.remove_bound(bound);
    assert!(book.inner_bindings().is_empty());
}

#[test]
fn relay_dns_snapshot_keeps_each_agent_and_withdraws_replaced_mapping() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let first = mediate("8.8.8.8:20002", "1.1.1.1:51000");
    let second = mediate("8.8.4.4:20002", "1.1.1.1:51000");
    let replacement = mediate("8.8.8.8:20002", "1.1.1.1:52000");
    book.set_nat(bound, NatType::RestrictedPort);
    book.insert(bound, first, Scope::External, None).unwrap();
    book.insert(bound, second, Scope::External, None).unwrap();
    let mut events = book.subscribe_punch(Scope::External);
    let replay = drain(&mut events);
    assert_eq!(replay.len(), 2);
    assert!(replay.iter().all(|event| matches!(
        event,
        Added {
            endpoint: EndpointAddr::Mediate { .. },
            nat: NatType::RestrictedPort,
            ..
        }
    )));
    let mut expected = vec![first, second];
    expected.sort_unstable();
    assert_eq!(book.ddns_endpoints().as_ref(), expected.as_slice());
    book.replace(first, replacement).unwrap();
    let mut expected = vec![replacement, second];
    expected.sort_unstable();
    assert_eq!(book.ddns_endpoints().as_ref(), expected.as_slice());
    assert_eq!(
        drain(&mut events),
        vec![
            Removed {
                bound,
                endpoint: first
            },
            Added {
                bound,
                endpoint: replacement,
                nat: NatType::RestrictedPort
            }
        ]
    );
    book.remove_bound(bound);
    assert!(book.ddns_endpoints().is_empty());
    assert_eq!(book.nat(bound), None);
}
