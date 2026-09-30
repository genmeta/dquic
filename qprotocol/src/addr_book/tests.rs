use std::sync::Barrier;

use AddressEvent::{Added, BoundRemoved, NatDetected, Removed};

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
fn publishes_inner_to_mdns_and_outer_agent_to_ddns() {
    let bound = addr("192.168.1.10:4433");
    let inner = EndpointAddr::direct(bound);
    let outer = direct("203.0.113.10:50000");
    let agent = mediate("198.51.100.1:3478", "203.0.113.10:50000");
    let book = AddressBook::new();
    let mdns = book.subscribe_mdns(bound);
    let ddns = book.subscribe_ddns();

    book.insert_inner(bound, inner).unwrap();
    book.insert_outer(bound, outer).unwrap();
    book.insert_agent(bound, agent).unwrap();

    assert_eq!(book.mdns_endpoints(bound).as_ref(), &[inner]);
    assert_eq!(book.ddns_endpoints().as_ref(), &[outer, agent]);
    assert_eq!(mdns.borrow().as_ref(), &[inner]);
    assert_eq!(ddns.borrow().as_ref(), &[outer, agent]);

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
    book.insert_inner(bound, inner).unwrap();
    book.insert_outer(bound, outer).unwrap();

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
fn limits_agents_per_bound_and_replacement_does_not_consume_another_slot() {
    let bound = addr("192.168.1.10:4433");
    let book = AddressBook::new();
    let agents = (3478..3482)
        .map(|port| mediate(&format!("8.8.8.8:{port}"), "8.8.4.4:50000"))
        .collect::<Vec<_>>();
    for &endpoint in &agents[..3] {
        book.insert_agent(bound, endpoint).unwrap();
    }
    assert!(matches!(
        book.insert_agent(bound, agents[3]),
        Err(AddressBookError::TooManyAgents)
    ));
    book.replace(agents[0], agents[3]).unwrap();
    assert_eq!(book.ddns_endpoints().len(), 3);
    assert!(!book.ddns_endpoints().contains(&agents[0]));
    assert!(book.ddns_endpoints().contains(&agents[3]));
}

#[test]
fn punch_replays_only_in_scope_endpoints_and_one_nat_per_binding() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let inner = EndpointAddr::direct(bound);
    let outer = direct("8.8.4.4:50000");
    let agent = mediate("8.8.8.8:3478", "8.8.4.4:50000");
    let loopback = direct("127.0.0.1:4433");
    book.set_nat(bound, NatType::FullCone);
    book.insert_inner(bound, inner).unwrap();
    book.insert_outer(bound, outer).unwrap();
    book.insert_agent(bound, agent).unwrap();
    book.insert_inner(loopback.addr(), loopback).unwrap();

    let mut external = book.subscribe_punch(Scope::External);
    let mut internal = book.subscribe_punch(Scope::Internal);
    let mut local = book.subscribe_punch(Scope::Loopback);
    assert_eq!(
        drain(&mut external),
        vec![
            NatDetected {
                bound,
                nat: NatType::FullCone
            },
            Added {
                bound,
                endpoint: outer
            },
            Added {
                bound,
                endpoint: agent
            },
        ]
    );
    assert_eq!(
        drain(&mut internal),
        vec![
            NatDetected {
                bound,
                nat: NatType::FullCone
            },
            Added {
                bound,
                endpoint: inner
            },
        ]
    );
    assert_eq!(
        drain(&mut local),
        vec![Added {
            bound: loopback.addr(),
            endpoint: loopback
        }]
    );

    assert!(book.set_nat(bound, NatType::RestrictedPort));
    let event = NatDetected {
        bound,
        nat: NatType::RestrictedPort,
    };
    assert_eq!(drain(&mut external), vec![event]);
    assert_eq!(drain(&mut internal), vec![event]);
    assert!(drain(&mut local).is_empty());
    assert!(!book.set_nat(bound, NatType::RestrictedPort));
    assert!(drain(&mut external).is_empty());
}

#[test]
fn nat_arriving_before_endpoint_or_while_out_of_scope_is_replayed() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let inner = EndpointAddr::direct(bound);
    let agent = mediate("8.8.8.8:3478", "8.8.4.4:50000");
    let mut events = book.subscribe_punch(Scope::External);
    book.insert_inner(bound, inner).unwrap();
    book.set_nat(bound, NatType::RestrictedCone);
    assert!(drain(&mut events).is_empty());

    book.insert_agent(bound, agent).unwrap();
    assert_eq!(
        drain(&mut events),
        vec![
            NatDetected {
                bound,
                nat: NatType::RestrictedCone
            },
            Added {
                bound,
                endpoint: agent
            },
        ]
    );
    book.remove(agent);
    assert_eq!(
        drain(&mut events),
        vec![Removed {
            bound,
            endpoint: agent
        }]
    );
    book.set_nat(bound, NatType::Symmetric);
    assert!(drain(&mut events).is_empty());
    book.insert_agent(bound, agent).unwrap();
    assert_eq!(
        drain(&mut events),
        vec![
            NatDetected {
                bound,
                nat: NatType::Symmetric
            },
            Added {
                bound,
                endpoint: agent
            },
        ]
    );
}

#[test]
fn replacing_an_endpoint_keeps_nat_and_publishes_final_dns_snapshot() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let old = mediate("8.8.8.8:3478", "8.8.4.4:50000");
    let new = mediate("8.8.8.8:3478", "8.8.4.4:60000");
    book.insert_agent(bound, old).unwrap();
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
                endpoint: new
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
    book.insert_inner(bound, old).unwrap();
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
        vec![
            NatDetected {
                bound,
                nat: NatType::FullCone
            },
            Added {
                bound,
                endpoint: new
            },
        ]
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
        vec![
            NatDetected {
                bound,
                nat: NatType::FullCone
            },
            Added {
                bound,
                endpoint: old
            },
        ]
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
    let agent = mediate("8.8.8.8:3478", "8.8.4.4:50000");
    book.insert_outer(bound, old).unwrap();
    book.insert_outer(bound, occupied).unwrap();
    let mut events = book.subscribe_punch(Scope::External);
    drain(&mut events);
    let ddns = book.subscribe_ddns();
    let before = book.ddns_endpoints();

    assert!(matches!(
        book.replace(old, occupied),
        Err(AddressBookError::Duplicate(_))
    ));
    assert!(matches!(
        book.replace(old, agent),
        Err(AddressBookError::ExpectedDirect)
    ));
    assert!(matches!(
        book.replace(absent, old),
        Err(AddressBookError::NotFound(_))
    ));
    assert!(matches!(
        book.insert_inner(bound, old),
        Err(AddressBookError::Duplicate(_))
    ));
    assert!(matches!(
        book.insert_agent(bound, absent),
        Err(AddressBookError::ExpectedMediate)
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
    book.insert_inner(bound, inner).unwrap();
    book.insert_outer(bound, outer).unwrap();
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

    book.insert_outer(bound, outer).unwrap();
    assert_eq!(
        drain(&mut external),
        vec![Added {
            bound,
            endpoint: outer
        }]
    );
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
    book.insert_inner(bound, endpoint).unwrap();
    assert_eq!(drain(&mut active), vec![Added { bound, endpoint }]);
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
                book.insert_inner(bound, old).unwrap();
                book.set_nat(bound, NatType::RestrictedPort);
                book.replace(old, new).unwrap();
            });
            barrier.wait();
            let mut events = book.subscribe_punch(Scope::Internal);
            let mdns = book.subscribe_mdns(bound);
            writer.join().unwrap();

            let mut endpoints = HashMap::new();
            let mut nat = None;
            for event in drain(&mut events) {
                match event {
                    Added { bound, endpoint } => {
                        assert!(endpoints.insert(endpoint, bound).is_none());
                    }
                    Removed { bound, endpoint } => {
                        assert_eq!(endpoints.remove(&endpoint), Some(bound));
                    }
                    NatDetected { nat: detected, .. } => nat = Some(detected),
                    BoundRemoved { .. } => panic!("binding was not withdrawn"),
                }
            }
            assert_eq!(endpoints, HashMap::from([(new, bound)]));
            assert_eq!(nat, Some(NatType::RestrictedPort));
            assert_eq!(mdns.borrow().as_ref(), &[new]);
        });
    }
}

#[test]
fn direct_pathways_use_actual_bindings_and_filter_scope_and_family() {
    let book = AddressBook::new();
    let first = addr("192.168.1.10:4433");
    let second = addr("192.168.1.20:4433");
    let loopback = addr("127.0.0.1:4433");
    let v6 = addr("[fd00::1]:4433");
    for bound in [second, first, loopback, v6] {
        book.insert_inner(bound, EndpointAddr::direct(bound))
            .unwrap();
    }
    book.insert_outer(first, direct("8.8.4.4:50000")).unwrap();
    book.insert_agent(first, mediate("8.8.8.8:3478", "8.8.4.4:50000"))
        .unwrap();
    let peer = direct("1.1.1.1:443");
    assert_eq!(
        book.pathways_to(peer),
        vec![
            Pathway::new(first.into(), peer),
            Pathway::new(second.into(), peer)
        ]
    );
    let local_peer = direct("127.0.0.1:4434");
    assert_eq!(
        book.pathways_to(local_peer),
        vec![Pathway::new(loopback.into(), local_peer)]
    );
    let v6_peer = direct("[2001:4860:4860::8888]:443");
    assert_eq!(
        book.pathways_to(v6_peer),
        vec![Pathway::new(v6.into(), v6_peer)]
    );
    assert!(book.pathways_to(loopback.into()).is_empty());
}

#[test]
fn mediated_pathways_require_a_compatible_return_endpoint() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    let local = mediate("8.8.8.8:3478", "8.8.4.4:50000");
    let outer = direct("8.8.4.4:50000");
    let peer = mediate("1.1.1.1:3478", "1.0.0.1:60000");
    book.insert_inner(bound, bound.into()).unwrap();
    assert!(book.pathways_to(peer).is_empty());
    book.insert_agent(bound, local).unwrap();
    assert_eq!(book.pathways_to(peer), vec![Pathway::new(local, peer)]);
    book.insert_outer(bound, outer).unwrap();
    assert_eq!(
        book.pathways_to(peer),
        vec![Pathway::new(outer, peer), Pathway::new(local, peer)]
    );
    let new = mediate("8.8.8.8:3478", "8.8.4.4:60000");
    book.replace(local, new).unwrap();
    book.remove(outer);
    assert_eq!(book.pathways_to(peer), vec![Pathway::new(new, peer)]);
    book.remove_bound(bound);
    assert!(book.pathways_to(peer).is_empty());
}

#[test]
fn invalid_bootstrap_endpoints_do_not_produce_candidates() {
    let book = AddressBook::new();
    let bound = addr("192.168.1.10:4433");
    book.insert_inner(bound, bound.into()).unwrap();
    for peer in [
        direct("0.0.0.0:443"),
        direct("1.1.1.1:0"),
        direct("224.0.0.1:443"),
        mediate("0.0.0.0:3478", "1.0.0.1:60000"),
        mediate("1.1.1.1:3478", "[2001:4860:4860::8888]:60000"),
    ] {
        assert!(book.pathways_to(peer).is_empty(), "{peer}");
    }

    let wildcard = AddressBook::new();
    wildcard
        .insert_outer(addr("0.0.0.0:4433"), direct("8.8.4.4:50000"))
        .unwrap();
    assert!(wildcard.pathways_to(direct("1.1.1.1:443")).is_empty());
}
