use std::{collections::HashMap, net::SocketAddr, sync::Barrier};

use Candidate::{Invalid, New};
use qbase::net::{NatType, addr::EndpointAddr, route::Link};
use qprotocol::{
    ArcAddrBook,
    addr_book2::{AddressBookError, Candidate},
};
use tokio::sync::mpsc;

fn new_book() -> ArcAddrBook {
    ArcAddrBook::new()
}

fn addr(value: &str) -> SocketAddr {
    value.parse().unwrap()
}

fn direct(value: &str) -> EndpointAddr {
    EndpointAddr::direct(addr(value))
}

fn drain(receiver: &mut mpsc::UnboundedReceiver<Candidate>) -> Vec<Candidate> {
    std::iter::from_fn(|| receiver.try_recv().ok()).collect()
}

fn observed(book: &ArcAddrBook) -> HashMap<Link, NatType> {
    let (sender, mut receiver) = mpsc::unbounded_channel();
    book.attach(sender);
    drain(&mut receiver)
        .into_iter()
        .map(|event| match event {
            New { link, nat } => (link, nat),
            Invalid { .. } => panic!("expected initial candidate replay"),
        })
        .collect()
}

fn invalidated(receiver: &mut mpsc::UnboundedReceiver<Candidate>) -> Vec<Link> {
    let mut links = drain(receiver)
        .into_iter()
        .map(|event| match event {
            Invalid { link } => link,
            New { .. } => panic!("expected candidate withdrawal"),
        })
        .collect::<Vec<_>>();
    links.sort_unstable_by_key(|link| (link.src, link.dst));
    links
}

#[test]
fn endpoint_changes_do_not_notify_candidate_observers_or_change_nat_records() {
    let book = new_book();
    let sock_addr = addr("192.168.1.10:4000");
    let endpoint = direct("8.8.4.4:50000");
    let link = Link::new(sock_addr, endpoint.addr());
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    let mut endpoints = book.subscribe_endpoints();
    book.add_sock_addr(sock_addr);
    assert!(drain(&mut events).is_empty());
    book.add_candidate(link, NatType::RestrictedPort);
    assert_eq!(drain(&mut events), vec![New { link, nat: NatType::RestrictedPort }]);
    book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    assert!(drain(&mut events).is_empty());
    assert_eq!(*endpoints.borrow_and_update(), vec![endpoint, sock_addr.into()]);
    book.del_endpoint_addr(endpoint);
    assert!(drain(&mut events).is_empty());
    assert_eq!(book.try_get_nat_type(link), Some(NatType::RestrictedPort));
    assert_eq!(*endpoints.borrow_and_update(), vec![sock_addr.into()]);
}

#[test]
fn mdns_queries_only_registered_socket_ips_and_selects_a_stable_port() {
    let book = new_book();
    let first = addr("192.168.1.10:4000");
    let second = addr("192.168.1.10:5000");
    let v6 = addr("[fd00::10]:4000");
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    for sock_addr in [second, v6, first] {
        assert!(book.add_sock_addr(sock_addr));
    }
    assert!(!book.add_sock_addr(first));
    assert_eq!(book.mdns_query(first.ip()), Some(first));
    assert_eq!(book.mdns_query(v6.ip()), Some(v6));
    assert_eq!(book.mdns_query(addr("192.168.1.11:4000").ip()), None);
    let mut expected = vec![first.into(), second.into(), v6.into()];
    expected.sort_unstable();
    assert_eq!(*book.subscribe_endpoints().borrow(), expected);
    assert!(observed(&book).is_empty());
    assert!(drain(&mut events).is_empty());
    book.del_sock_addr(first);
    assert_eq!(book.mdns_query(first.ip()), Some(second));
}

#[test]
fn candidate_updates_only_refresh_their_exact_link() {
    let book = new_book();
    let sock_addr = addr("192.168.1.10:4000");
    let first_link = Link::new(sock_addr, addr("8.8.4.4:50000"));
    let second_link = Link::new(sock_addr, addr("8.8.4.4:50001"));
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    book.add_candidate(first_link, NatType::RestrictedCone);
    assert_eq!(book.try_get_nat_type(second_link), None);
    book.add_candidate(second_link, NatType::Symmetric);
    assert_eq!(
        drain(&mut events),
        vec![New { link: first_link, nat: NatType::RestrictedCone }, New { link: second_link, nat: NatType::Symmetric },]
    );
    assert_eq!(observed(&book), HashMap::from([(first_link, NatType::RestrictedCone), (second_link, NatType::Symmetric),]));
    book.add_candidate(first_link, NatType::RestrictedPort);
    assert_eq!(drain(&mut events), vec![New { link: first_link, nat: NatType::RestrictedPort }]);
    assert_eq!(book.try_get_nat_type(second_link), Some(NatType::Symmetric));
}

#[test]
fn duplicate_candidates_are_silent_and_nat_changes_refresh_the_link() {
    let book = new_book();
    let link = Link::new(addr("192.168.1.10:4000"), addr("8.8.4.4:50000"));
    book.add_candidate(link, NatType::RestrictedPort);
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    assert_eq!(drain(&mut events), vec![New { link, nat: NatType::RestrictedPort }]);
    assert!(!book.add_candidate(link, NatType::RestrictedPort));
    assert!(drain(&mut events).is_empty());
    assert!(book.add_candidate(link, NatType::FullCone));
    assert_eq!(drain(&mut events), vec![New { link, nat: NatType::FullCone }]);
    assert_eq!(book.try_get_nat_type(link), Some(NatType::FullCone));
    assert_eq!(observed(&book), HashMap::from([(link, NatType::FullCone)]));
}

#[test]
fn the_same_outer_address_on_different_sockets_has_independent_nat_records() {
    let book = new_book();
    let first = addr("192.168.1.10:4000");
    let second = addr("192.168.1.10:4001");
    let outer = addr("8.8.4.4:50000");
    for sock_addr in [first, second] {
        book.add_sock_addr(sock_addr);
    }
    book.add_candidate(Link::new(first, outer), NatType::RestrictedPort);
    book.add_candidate(Link::new(second, outer), NatType::Symmetric);
    assert_eq!(book.try_get_nat_type(Link::new(first, outer)), Some(NatType::RestrictedPort));
    assert_eq!(book.try_get_nat_type(Link::new(second, outer)), Some(NatType::Symmetric));
}

#[test]
fn removing_all_endpoint_aliases_keeps_the_candidate_and_its_replay() {
    let book = new_book();
    let sock_addr = addr("192.168.1.10:4000");
    let agent = addr("8.8.8.8:3478");
    let outer = addr("8.8.4.4:50000");
    let link = Link::new(sock_addr, outer);
    let direct = EndpointAddr::direct(outer);
    let mediate = EndpointAddr::mediate(agent, outer);
    book.add_sock_addr(sock_addr);
    book.add_candidate(link, NatType::Symmetric);
    book.add_endpoint_addr(sock_addr, direct).unwrap();
    book.add_endpoint_addr(sock_addr, mediate).unwrap();
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    drain(&mut events);
    assert_eq!(book.del_endpoint_addr(direct), Some(sock_addr));
    assert_eq!(book.del_endpoint_addr(direct), None);
    assert_eq!(book.del_endpoint_addr(mediate), Some(sock_addr));
    assert!(drain(&mut events).is_empty());
    assert_eq!(*book.subscribe_endpoints().borrow(), vec![sock_addr.into()]);
    assert_eq!(observed(&book), HashMap::from([(link, NatType::Symmetric)]));
    assert!(book.del_candidate(link));
    assert_eq!(drain(&mut events), vec![Invalid { link }]);
}

#[test]
fn socket_removal_cleans_endpoints_and_independent_candidates() {
    let book = new_book();
    let sock_addr = addr("192.168.1.10:4000");
    let other = addr("192.168.1.11:4000");
    let endpoint = direct("8.8.4.4:50000");
    let link = Link::new(sock_addr, endpoint.addr());
    let unmapped_link = Link::new(sock_addr, addr("8.8.4.4:50001"));
    let other_link = Link::new(other, endpoint.addr());
    for inner in [sock_addr, other] {
        book.add_sock_addr(inner);
    }
    book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    book.add_candidate(link, NatType::Symmetric);
    book.add_candidate(unmapped_link, NatType::RestrictedPort);
    book.add_candidate(other_link, NatType::RestrictedCone);
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    drain(&mut events);
    book.del_sock_addr(sock_addr);
    assert_eq!(invalidated(&mut events), vec![link, unmapped_link]);
    assert_eq!(*book.subscribe_endpoints().borrow(), vec![other.into()]);
    assert_eq!(observed(&book), HashMap::from([(other_link, NatType::RestrictedCone)]));
    assert_eq!(book.try_get_nat_type(link), None);
    assert_eq!(book.try_get_nat_type(unmapped_link), None);
    book.del_sock_addr(sock_addr);
    assert!(drain(&mut events).is_empty());
    book.add_sock_addr(sock_addr);
    assert!(drain(&mut events).is_empty());
    book.add_candidate(link, NatType::FullCone);
    assert_eq!(drain(&mut events), vec![New { link, nat: NatType::FullCone }]);
}

#[test]
fn conflicting_endpoint_owners_are_rejected_without_changing_candidates() {
    let book = new_book();
    let first = addr("192.168.1.10:4000");
    let second = addr("192.168.1.11:4000");
    let endpoint = direct("8.8.4.4:50000");
    let link = Link::new(first, endpoint.addr());
    for inner in [first, second] {
        book.add_sock_addr(inner);
    }
    book.add_candidate(link, NatType::Symmetric);
    book.add_endpoint_addr(first, endpoint).unwrap();
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    drain(&mut events);
    let endpoints = book.subscribe_endpoints();
    assert!(matches!(book.add_endpoint_addr(second, endpoint), Err(AddressBookError::AddressInUse(value)) if value == endpoint));
    assert!(matches!(book.add_endpoint_addr(first, second.into()), Err(AddressBookError::AddressInUse(_))));
    assert!(!book.add_endpoint_addr(first, first.into()).unwrap());
    assert!(!endpoints.has_changed().unwrap());
    assert_eq!(*endpoints.borrow(), vec![endpoint, first.into(), second.into()]);
    assert_eq!(observed(&book), HashMap::from([(link, NatType::Symmetric)]));
    assert!(drain(&mut events).is_empty());
}

#[test]
fn wildcard_bindings_publish_endpoints_without_implicit_candidates() {
    let book = new_book();
    let sock_addr = addr("0.0.0.0:4000");
    let endpoint = direct("8.8.4.4:50000");
    let link = Link::new(sock_addr, endpoint.addr());
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    book.add_sock_addr(sock_addr);
    book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    assert_eq!(*book.subscribe_endpoints().borrow(), vec![sock_addr.into(), endpoint]);
    assert!(drain(&mut events).is_empty());
    assert!(observed(&book).is_empty());
    book.add_candidate(link, NatType::FullCone);
    assert_eq!(drain(&mut events), vec![New { link, nat: NatType::FullCone }]);
}

#[test]
fn subscription_replay_and_concurrent_updates_form_one_ordered_view() {
    let sock_addr = addr("192.168.1.10:4000");
    let endpoint = direct("8.8.4.4:50000");
    let link = Link::new(sock_addr, endpoint.addr());
    for _ in 0..32 {
        let book = new_book();
        let barrier = Barrier::new(2);
        std::thread::scope(|threads| {
            let writer = threads.spawn(|| {
                barrier.wait();
                book.add_sock_addr(sock_addr);
                book.add_candidate(link, NatType::Symmetric);
                book.add_endpoint_addr(sock_addr, endpoint).unwrap();
                book.del_endpoint_addr(endpoint);
                book.del_candidate(link);
            });
            barrier.wait();
            let (sender, mut events) = mpsc::unbounded_channel();
            book.attach(sender);
            let endpoints = book.subscribe_endpoints();
            writer.join().unwrap();
            let mut view = HashMap::new();
            for event in drain(&mut events) {
                match event {
                    New { link, nat } => assert!(view.insert(link, nat).is_none()),
                    Invalid { link } => assert!(view.remove(&link).is_some()),
                }
            }
            assert!(view.is_empty());
            assert_eq!(*endpoints.borrow(), vec![sock_addr.into()]);
        });
    }
}

#[test]
fn closed_subscribers_do_not_affect_other_receivers_and_dropping_the_book_closes_them() {
    let book = new_book();
    let (sender, abandoned) = mpsc::unbounded_channel();
    book.attach(sender);
    let (sender, mut active) = mpsc::unbounded_channel();
    book.attach(sender);
    drop(abandoned);
    let link = Link::new(addr("192.168.1.10:4000"), addr("8.8.4.4:50000"));
    book.add_candidate(link, NatType::FullCone);
    assert_eq!(drain(&mut active), vec![New { link, nat: NatType::FullCone }]);
    drop(book);
    assert_eq!(active.try_recv(), Err(mpsc::error::TryRecvError::Disconnected));
}

#[test]
fn endpoint_snapshots_update_immediately_and_nat_changes_do_not_repeat_them() {
    let book = new_book();
    let other_handle = book.clone();
    let mut endpoints = book.subscribe_endpoints();
    let sock_addr = addr("192.168.1.10:4000");
    let endpoint = direct("8.8.4.4:50000");
    assert!(book.add_sock_addr(sock_addr));
    assert_eq!(*endpoints.borrow_and_update(), vec![sock_addr.into()]);
    assert!(!other_handle.add_sock_addr(sock_addr));
    assert!(!book.add_endpoint_addr(sock_addr, sock_addr.into()).unwrap());
    assert_eq!(book.del_endpoint_addr(sock_addr.into()), None);
    assert!(!endpoints.has_changed().unwrap());
    book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    assert!(endpoints.has_changed().unwrap());
    assert_eq!(*endpoints.borrow_and_update(), vec![endpoint, sock_addr.into()]);
    assert!(!other_handle.add_endpoint_addr(sock_addr, endpoint).unwrap());
    book.add_candidate(Link::new(sock_addr, endpoint.addr()), NatType::RestrictedPort);
    book.add_candidate(Link::new(sock_addr, endpoint.addr()), NatType::Symmetric);
    assert!(!endpoints.has_changed().unwrap());
    book.del_endpoint_addr(endpoint);
    assert!(endpoints.has_changed().unwrap());
    assert_eq!(*endpoints.borrow_and_update(), vec![sock_addr.into()]);
    assert_eq!(other_handle.del_endpoint_addr(endpoint), None);
    other_handle.del_sock_addr(sock_addr);
    book.del_sock_addr(sock_addr);
    assert!(endpoints.has_changed().unwrap());
    assert!(endpoints.borrow().is_empty());
}

#[test]
#[should_panic(expected = "socket address and Direct endpoint must be registered together")]
fn adding_a_socket_asserts_that_its_direct_endpoint_is_not_owned_by_another_socket() {
    let book = new_book();
    let sock_addr = addr("192.168.1.10:4000");
    let mapped = direct("8.8.4.4:50000");
    book.add_sock_addr(sock_addr);
    book.add_candidate(Link::new(sock_addr, mapped.addr()), NatType::Symmetric);
    book.add_endpoint_addr(sock_addr, mapped).unwrap();
    book.add_sock_addr(mapped.addr());
}

#[test]
fn loopback_sockets_are_queryable_and_published_as_direct_endpoints() {
    let book = new_book();
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    let mut endpoints = book.subscribe_endpoints();
    for sock_addr in [addr("127.0.0.1:4000"), addr("127.0.0.2:4000"), addr("[::1]:4000"), addr("[::ffff:127.0.0.1]:4000")] {
        assert!(book.add_sock_addr(sock_addr));
        assert!(!book.add_sock_addr(sock_addr));
        assert_eq!(book.mdns_query(sock_addr.ip()), Some(sock_addr));
        assert!(observed(&book).is_empty());
        assert!(drain(&mut events).is_empty());
        assert!(endpoints.has_changed().unwrap());
        assert_eq!(*endpoints.borrow_and_update(), vec![sock_addr.into()]);
        book.del_sock_addr(sock_addr);
        book.del_sock_addr(sock_addr);
        assert_eq!(book.mdns_query(sock_addr.ip()), None);
        assert!(drain(&mut events).is_empty());
        assert!(endpoints.has_changed().unwrap());
        assert!(endpoints.borrow_and_update().is_empty());
        assert!(!endpoints.has_changed().unwrap());
    }
}

#[test]
fn attach_replays_candidates_without_matching_endpoints_and_fans_out_changes() {
    let book = new_book();
    let sock_addr = addr("127.0.0.1:4000");
    let agent = addr("8.8.8.8:3478");
    let first_link = Link::new(sock_addr, addr("8.8.4.4:50000"));
    let second_link = Link::new(sock_addr, addr("8.8.4.4:50001"));
    book.add_sock_addr(sock_addr);
    book.add_candidate(second_link, NatType::FullCone);
    book.add_candidate(first_link, NatType::RestrictedPort);
    let (sender, mut first) = mpsc::unbounded_channel();
    book.attach(sender);
    let replay = vec![New { link: first_link, nat: NatType::RestrictedPort }, New { link: second_link, nat: NatType::FullCone }];
    assert_eq!(drain(&mut first), replay);
    let (sender, mut second) = mpsc::unbounded_channel();
    book.attach(sender);
    assert_eq!(drain(&mut second), replay);
    assert!(drain(&mut first).is_empty());
    book.add_endpoint_addr(sock_addr, EndpointAddr::mediate(agent, first_link.dst)).unwrap();
    assert!(drain(&mut first).is_empty());
    assert!(drain(&mut second).is_empty());
    book.add_candidate(first_link, NatType::Symmetric);
    for receiver in [&mut first, &mut second] {
        assert_eq!(drain(receiver), vec![New { link: first_link, nat: NatType::Symmetric }]);
    }
    book.del_candidate(first_link);
    for receiver in [&mut first, &mut second] {
        assert_eq!(drain(receiver), vec![Invalid { link: first_link }]);
    }
    let abandoned = mpsc::unbounded_channel();
    drop(abandoned.1);
    book.attach(abandoned.0);
    book.del_sock_addr(sock_addr);
    assert_eq!(drain(&mut first), vec![Invalid { link: second_link }]);
    assert_eq!(drain(&mut second), vec![Invalid { link: second_link }]);
}

#[test]
fn explicitly_registered_internal_candidates_notify_every_observer() {
    let book = new_book();
    let link = Link::new(addr("192.168.1.10:4000"), addr("192.168.1.11:5000"));
    let (sender, mut first) = mpsc::unbounded_channel();
    book.attach(sender);
    let (sender, mut second) = mpsc::unbounded_channel();
    book.attach(sender);
    book.add_candidate(link, NatType::FullCone);
    for receiver in [&mut first, &mut second] {
        assert_eq!(drain(receiver), vec![New { link, nat: NatType::FullCone }]);
    }
    assert!(book.del_candidate(link));
    assert!(!book.del_candidate(link));
    for receiver in [&mut first, &mut second] {
        assert_eq!(drain(receiver), vec![Invalid { link }]);
    }
}

#[test]
fn removing_a_loopback_socket_also_withdraws_its_unclassified_mappings() {
    let book = new_book();
    let sock_addr = addr("127.0.0.1:4000");
    let endpoint = direct("8.8.4.4:50000");
    book.add_sock_addr(sock_addr);
    book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    let endpoints = book.subscribe_endpoints();
    let (sender, mut candidates) = mpsc::unbounded_channel();
    book.attach(sender);
    assert_eq!(*endpoints.borrow(), vec![endpoint, sock_addr.into()]);
    assert!(drain(&mut candidates).is_empty());
    book.del_sock_addr(sock_addr);
    assert!(endpoints.has_changed().unwrap());
    assert!(endpoints.borrow().is_empty());
    assert!(drain(&mut candidates).is_empty());
}

#[test]
fn endpoint_and_candidate_registration_can_arrive_in_either_order() {
    let sock_addr = addr("192.168.1.10:4000");
    let endpoint = direct("8.8.4.4:50000");
    let link = Link::new(sock_addr, endpoint.addr());
    for candidate_first in [false, true] {
        let book = new_book();
        let (sender, mut events) = mpsc::unbounded_channel();
        book.attach(sender);
        if candidate_first {
            book.add_candidate(link, NatType::RestrictedCone);
            assert_eq!(drain(&mut events), vec![New { link, nat: NatType::RestrictedCone }]);
        }
        book.add_endpoint_addr(sock_addr, endpoint).unwrap();
        assert!(drain(&mut events).is_empty());
        if !candidate_first {
            assert!(observed(&book).is_empty());
            book.add_candidate(link, NatType::RestrictedCone);
            assert_eq!(drain(&mut events), vec![New { link, nat: NatType::RestrictedCone }]);
        }
        assert_eq!(observed(&book), HashMap::from([(link, NatType::RestrictedCone)]));
        assert_eq!(*book.subscribe_endpoints().borrow(), vec![endpoint]);
    }
}

#[test]
fn mediate_endpoints_can_be_removed_without_candidate_events() {
    let book = new_book();
    let sock_addr = addr("192.168.1.10:4000");
    let endpoint = EndpointAddr::mediate(addr("8.8.8.8:3478"), addr("8.8.4.4:50000"));
    book.add_sock_addr(sock_addr);
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    assert_eq!(book.del_endpoint_addr(endpoint), Some(sock_addr));
    assert!(drain(&mut events).is_empty());
    assert!(observed(&book).is_empty());
}

#[test]
fn internal_endpoints_do_not_create_implicit_full_cone_candidates() {
    let book = new_book();
    let sock_addr = addr("192.168.1.10:4000");
    let agent = addr("8.8.8.8:3478");
    let outer = addr("192.168.1.11:5000");
    let link = Link::new(sock_addr, outer);
    book.add_sock_addr(sock_addr);
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    for endpoint in [EndpointAddr::direct(outer), EndpointAddr::mediate(agent, outer)] {
        book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    }
    assert!(drain(&mut events).is_empty());
    assert!(observed(&book).is_empty());
    book.add_candidate(link, NatType::FullCone);
    assert_eq!(drain(&mut events), vec![New { link, nat: NatType::FullCone }]);
    assert_eq!(observed(&book), HashMap::from([(link, NatType::FullCone)]));
}

#[test]
fn candidates_for_absent_sockets_are_added_then_removed_by_the_ordered_lifecycle() {
    let book = new_book();
    let sock_addr = addr("192.168.1.10:4000");
    let endpoint = direct("8.8.4.4:50000");
    let link = Link::new(sock_addr, endpoint.addr());
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    book.add_candidate(link, NatType::Symmetric);
    assert_eq!(drain(&mut events), vec![New { link, nat: NatType::Symmetric }]);
    book.del_sock_addr(sock_addr);
    assert_eq!(drain(&mut events), vec![Invalid { link }]);
    assert!(observed(&book).is_empty());
    assert!(book.subscribe_endpoints().borrow().is_empty());
}

#[test]
fn nat_results_can_precede_socket_registration_and_are_cleaned_up_on_removal() {
    let book = new_book();
    let sock_addr = addr("8.8.4.4:4000");
    let link = Link::new(sock_addr, sock_addr);
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    assert!(book.add_candidate(link, NatType::RestrictedPort));
    assert!(!book.add_candidate(link, NatType::RestrictedPort));
    assert_eq!(drain(&mut events), vec![New { link, nat: NatType::RestrictedPort }]);
    assert!(book.add_sock_addr(sock_addr));
    assert!(drain(&mut events).is_empty());
    book.del_sock_addr(sock_addr);
    assert_eq!(drain(&mut events), vec![Invalid { link }]);
    assert_eq!(book.try_get_nat_type(link), None);
}

#[test]
fn removing_a_candidate_keeps_all_communication_endpoints() {
    let book = new_book();
    let sock_addr = addr("192.168.1.10:4000");
    let agent = addr("8.8.8.8:3478");
    let outer = addr("8.8.4.4:50000");
    let link = Link::new(sock_addr, outer);
    book.add_sock_addr(sock_addr);
    let direct = EndpointAddr::direct(outer);
    let mediate = EndpointAddr::mediate(agent, outer);
    for endpoint in [direct, mediate] {
        book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    }
    book.add_candidate(link, NatType::Symmetric);
    let endpoints = book.subscribe_endpoints();
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    drain(&mut events);
    assert!(book.del_candidate(link));
    assert_eq!(drain(&mut events), vec![Invalid { link }]);
    assert_eq!(*endpoints.borrow(), vec![direct, sock_addr.into(), mediate]);
    assert!(!endpoints.has_changed().unwrap());
    assert!(!book.del_candidate(link));
    assert!(observed(&book).is_empty());
    assert!(drain(&mut events).is_empty());
}

#[test]
fn public_socket_endpoints_are_observable_before_nat_classification() {
    let book = new_book();
    let sock_addr = addr("8.8.4.4:4000");
    let link = Link::new(sock_addr, sock_addr);
    let mut endpoints = book.subscribe_endpoints();
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach(sender);
    book.add_sock_addr(sock_addr);
    assert!(endpoints.has_changed().unwrap());
    assert_eq!(*endpoints.borrow_and_update(), vec![sock_addr.into()]);
    assert!(drain(&mut events).is_empty());
    book.add_candidate(link, NatType::RestrictedPort);
    assert_eq!(drain(&mut events), vec![New { link, nat: NatType::RestrictedPort }]);
    assert!(!endpoints.has_changed().unwrap());
}

#[test]
fn endpoint_snapshots_retain_latest_state_for_late_and_slow_receivers() {
    let book = new_book();
    let sock_addr = addr("192.168.1.10:4000");
    let endpoint = direct("8.8.4.4:50000");
    let replacement = direct("8.8.4.4:50001");
    book.add_sock_addr(sock_addr);
    book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    let mut first = book.subscribe_endpoints();
    let mut second = book.subscribe_endpoints();
    let replay = vec![endpoint, sock_addr.into()];
    assert_eq!(*first.borrow(), replay);
    assert_eq!(*second.borrow(), replay);
    assert!(!first.has_changed().unwrap());
    book.del_endpoint_addr(endpoint);
    book.add_endpoint_addr(sock_addr, replacement).unwrap();
    for receiver in [&mut first, &mut second] {
        assert!(receiver.has_changed().unwrap());
        assert_eq!(*receiver.borrow_and_update(), vec![replacement, sock_addr.into()]);
    }
    drop(first);
    drop(second);
    book.del_endpoint_addr(replacement);
    let late = book.subscribe_endpoints();
    assert_eq!(*late.borrow(), vec![sock_addr.into()]);
    drop(book);
    assert!(late.has_changed().is_err());
}

#[test]
fn global_handles_share_the_same_directory() {
    let book = ArcAddrBook::global().clone();
    let sock_addr = addr("127.0.0.77:4000");
    let endpoints = book.subscribe_endpoints();
    assert!(ArcAddrBook::global().add_sock_addr(sock_addr));
    assert_eq!(book.mdns_query(sock_addr.ip()), Some(sock_addr));
    assert_eq!(*endpoints.borrow(), vec![sock_addr.into()]);
    book.del_sock_addr(sock_addr);
    assert_eq!(ArcAddrBook::global().mdns_query(sock_addr.ip()), None);
    assert!(endpoints.borrow().is_empty());
}
