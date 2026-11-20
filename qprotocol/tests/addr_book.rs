use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    sync::{Arc, Barrier},
};

use Candidate::{Invalid, New};
use futures::FutureExt;
use qbase::net::{
    NatType,
    addr::EndpointAddr,
    route::{Link, Scope, Scopes},
};
use qprotocol::{
    ArcAddrBook,
    addr_book::{AddressBookError, Candidate},
};
use qresolve::{Publish, PublishFuture};
use tokio::sync::mpsc;

#[derive(Debug)]
struct TestPublisher(mpsc::UnboundedSender<Vec<EndpointAddr>>);

impl fmt::Display for TestPublisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("test publisher")
    }
}

impl Publish for TestPublisher {
    fn publish<'a>(&'a self, endpoints: &mut dyn Iterator<Item = EndpointAddr>) -> PublishFuture<'a> {
        let endpoints = endpoints.collect();
        Box::pin(async move {
            self.0.send(endpoints).unwrap();
            Ok(())
        })
    }
}

// Exercise initial publication through the public publisher interface.
fn published(book: &ArcAddrBook) -> Vec<EndpointAddr> {
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let observation = book.clone().change_then_publish_with_scope(Arc::new(TestPublisher(sender)), Scopes::ALL);
    assert!(observation.now_or_never().is_none());
    receiver.try_recv().unwrap()
}

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
    book.attach_puncher(sender);
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
    book.attach_puncher(sender);
    book.add_sock_addr(sock_addr);
    assert!(drain(&mut events).is_empty());
    book.add_candidate(link, NatType::RestrictedPort);
    assert_eq!(drain(&mut events), vec![New { link, nat: NatType::RestrictedPort }]);
    book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    assert!(drain(&mut events).is_empty());
    assert_eq!(published(&book), vec![endpoint, sock_addr.into()]);
    book.del_endpoint_addr(endpoint);
    assert!(drain(&mut events).is_empty());
    assert_eq!(book.try_get_nat_type(link), Some(NatType::RestrictedPort));
    assert_eq!(published(&book), vec![sock_addr.into()]);
}

#[test]
fn mdns_queries_only_registered_socket_ips_and_selects_a_stable_port() {
    let book = new_book();
    let first = addr("192.168.1.10:4000");
    let second = addr("192.168.1.10:5000");
    let v6 = addr("[fd00::10]:4000");
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach_puncher(sender);
    for sock_addr in [second, v6, first] {
        assert!(book.add_sock_addr(sock_addr));
    }
    assert!(!book.add_sock_addr(first));
    assert_eq!(book.mdns_query(first.ip()), Some(first));
    assert_eq!(book.mdns_query(v6.ip()), Some(v6));
    assert_eq!(book.mdns_query(addr("192.168.1.11:4000").ip()), None);
    let mut expected = vec![first.into(), second.into(), v6.into()];
    expected.sort_unstable();
    assert_eq!(published(&book), expected);
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
    book.attach_puncher(sender);
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
    book.attach_puncher(sender);
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
    book.attach_puncher(sender);
    drain(&mut events);
    assert_eq!(book.del_endpoint_addr(direct), Some(sock_addr));
    assert_eq!(book.del_endpoint_addr(direct), None);
    assert_eq!(book.del_endpoint_addr(mediate), Some(sock_addr));
    assert!(drain(&mut events).is_empty());
    assert_eq!(published(&book), vec![sock_addr.into()]);
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
    book.attach_puncher(sender);
    drain(&mut events);
    book.del_sock_addr(sock_addr);
    assert_eq!(invalidated(&mut events), vec![link, unmapped_link]);
    assert_eq!(published(&book), vec![other.into()]);
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
    book.attach_puncher(sender);
    drain(&mut events);
    assert!(matches!(book.add_endpoint_addr(second, endpoint), Err(AddressBookError::AddressInUse(value)) if value == endpoint));
    assert!(matches!(book.add_endpoint_addr(first, second.into()), Err(AddressBookError::AddressInUse(_))));
    assert!(!book.add_endpoint_addr(first, first.into()).unwrap());

    assert_eq!(published(&book), vec![endpoint, first.into(), second.into()]);
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
    book.attach_puncher(sender);
    book.add_sock_addr(sock_addr);
    book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    assert_eq!(published(&book), vec![endpoint]);
    assert_eq!(book.mdns_query(sock_addr.ip()), Some(sock_addr));
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
            book.attach_puncher(sender);
            writer.join().unwrap();
            let mut view = HashMap::new();
            for event in drain(&mut events) {
                match event {
                    New { link, nat } => assert!(view.insert(link, nat).is_none()),
                    Invalid { link } => assert!(view.remove(&link).is_some()),
                }
            }
            assert!(view.is_empty());
            assert_eq!(published(&book), vec![sock_addr.into()]);
        });
    }
}

#[test]
fn closed_subscribers_do_not_affect_other_receivers_and_dropping_the_book_closes_them() {
    let book = new_book();
    let (sender, abandoned) = mpsc::unbounded_channel();
    book.attach_puncher(sender);
    let (sender, mut active) = mpsc::unbounded_channel();
    book.attach_puncher(sender);
    drop(abandoned);
    let link = Link::new(addr("192.168.1.10:4000"), addr("8.8.4.4:50000"));
    book.add_candidate(link, NatType::FullCone);
    assert_eq!(drain(&mut active), vec![New { link, nat: NatType::FullCone }]);
    drop(book);
    assert_eq!(active.try_recv(), Err(mpsc::error::TryRecvError::Disconnected));
}

#[tokio::test]
async fn publisher_sends_initial_updates_and_ignores_unchanged_or_nat_only_changes() {
    let book = new_book();
    let (sender, mut publications) = mpsc::unbounded_channel();
    let observation = book.clone().change_then_publish_with_scope(Arc::new(TestPublisher(sender)), Scopes::ALL);
    tokio::pin!(observation);
    assert!(futures::poll!(&mut observation).is_pending());
    assert_eq!(publications.try_recv().unwrap(), vec![]);
    let sock_addr = addr("192.168.1.10:4000");
    let endpoint = direct("8.8.4.4:50000");
    assert!(book.add_sock_addr(sock_addr));
    assert!(futures::poll!(&mut observation).is_pending());
    assert_eq!(publications.try_recv().unwrap(), vec![sock_addr.into()]);
    assert!(!book.add_sock_addr(sock_addr));
    assert!(!book.add_endpoint_addr(sock_addr, sock_addr.into()).unwrap());
    assert_eq!(book.del_endpoint_addr(sock_addr.into()), None);
    assert!(futures::poll!(&mut observation).is_pending());
    assert_eq!(publications.try_recv(), Err(mpsc::error::TryRecvError::Empty));
    book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    assert!(futures::poll!(&mut observation).is_pending());
    assert_eq!(publications.try_recv().unwrap(), vec![endpoint, sock_addr.into()]);
    assert!(!book.add_endpoint_addr(sock_addr, endpoint).unwrap());
    book.add_candidate(Link::new(sock_addr, endpoint.addr()), NatType::RestrictedPort);
    book.add_candidate(Link::new(sock_addr, endpoint.addr()), NatType::Symmetric);
    assert!(futures::poll!(&mut observation).is_pending());
    assert_eq!(publications.try_recv(), Err(mpsc::error::TryRecvError::Empty));
    book.del_endpoint_addr(endpoint);
    assert!(futures::poll!(&mut observation).is_pending());
    assert_eq!(publications.try_recv().unwrap(), vec![sock_addr.into()]);
    assert_eq!(book.del_endpoint_addr(endpoint), None);
    book.del_sock_addr(sock_addr);
    book.del_sock_addr(sock_addr);
    assert!(futures::poll!(&mut observation).is_pending());
    assert_eq!(publications.try_recv().unwrap(), vec![]);
    drop(book);
    assert!(futures::poll!(&mut observation).is_ready(), "observation must not keep the book alive");
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
    book.attach_puncher(sender);
    for sock_addr in [addr("127.0.0.1:4000"), addr("127.0.0.2:4000"), addr("[::1]:4000"), addr("[::ffff:127.0.0.1]:4000")] {
        assert!(book.add_sock_addr(sock_addr));
        assert!(!book.add_sock_addr(sock_addr));
        assert_eq!(book.mdns_query(sock_addr.ip()), Some(sock_addr));
        assert!(observed(&book).is_empty());
        assert!(drain(&mut events).is_empty());

        assert_eq!(published(&book), vec![sock_addr.into()]);
        book.del_sock_addr(sock_addr);
        book.del_sock_addr(sock_addr);
        assert_eq!(book.mdns_query(sock_addr.ip()), None);
        assert!(drain(&mut events).is_empty());

        assert!(published(&book).is_empty());
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
    book.attach_puncher(sender);
    let replay = vec![New { link: first_link, nat: NatType::RestrictedPort }, New { link: second_link, nat: NatType::FullCone }];
    assert_eq!(drain(&mut first), replay);
    let (sender, mut second) = mpsc::unbounded_channel();
    book.attach_puncher(sender);
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
    book.attach_puncher(abandoned.0);
    book.del_sock_addr(sock_addr);
    assert_eq!(drain(&mut first), vec![Invalid { link: second_link }]);
    assert_eq!(drain(&mut second), vec![Invalid { link: second_link }]);
}

#[test]
fn explicitly_registered_internal_candidates_notify_every_observer() {
    let book = new_book();
    let link = Link::new(addr("192.168.1.10:4000"), addr("192.168.1.11:5000"));
    let (sender, mut first) = mpsc::unbounded_channel();
    book.attach_puncher(sender);
    let (sender, mut second) = mpsc::unbounded_channel();
    book.attach_puncher(sender);
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
    let (sender, mut candidates) = mpsc::unbounded_channel();
    book.attach_puncher(sender);
    assert_eq!(published(&book), vec![endpoint, sock_addr.into()]);
    assert!(drain(&mut candidates).is_empty());
    book.del_sock_addr(sock_addr);

    assert!(published(&book).is_empty());
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
        book.attach_puncher(sender);
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
        assert_eq!(published(&book), vec![endpoint]);
    }
}

#[test]
fn mediate_endpoints_can_be_removed_without_candidate_events() {
    let book = new_book();
    let sock_addr = addr("192.168.1.10:4000");
    let endpoint = EndpointAddr::mediate(addr("8.8.8.8:3478"), addr("8.8.4.4:50000"));
    book.add_sock_addr(sock_addr);
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach_puncher(sender);
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
    book.attach_puncher(sender);
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
    book.attach_puncher(sender);
    book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    book.add_candidate(link, NatType::Symmetric);
    assert_eq!(drain(&mut events), vec![New { link, nat: NatType::Symmetric }]);
    book.del_sock_addr(sock_addr);
    assert_eq!(drain(&mut events), vec![Invalid { link }]);
    assert!(observed(&book).is_empty());
    assert!(published(&book).is_empty());
}

#[test]
fn nat_results_can_precede_socket_registration_and_are_cleaned_up_on_removal() {
    let book = new_book();
    let sock_addr = addr("8.8.4.4:4000");
    let link = Link::new(sock_addr, sock_addr);
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach_puncher(sender);
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
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach_puncher(sender);
    drain(&mut events);
    assert!(book.del_candidate(link));
    assert_eq!(drain(&mut events), vec![Invalid { link }]);
    assert_eq!(published(&book), vec![direct, sock_addr.into(), mediate]);

    assert!(!book.del_candidate(link));
    assert!(observed(&book).is_empty());
    assert!(drain(&mut events).is_empty());
}

#[test]
fn public_socket_endpoints_are_observable_before_nat_classification() {
    let book = new_book();
    let sock_addr = addr("8.8.4.4:4000");
    let link = Link::new(sock_addr, sock_addr);
    let (sender, mut events) = mpsc::unbounded_channel();
    book.attach_puncher(sender);
    book.add_sock_addr(sock_addr);

    assert_eq!(published(&book), vec![sock_addr.into()]);
    assert!(drain(&mut events).is_empty());
    book.add_candidate(link, NatType::RestrictedPort);
    assert_eq!(drain(&mut events), vec![New { link, nat: NatType::RestrictedPort }]);
}

#[tokio::test]
async fn publishers_receive_the_latest_list_independently_and_late_attachments_replay_it() {
    let book = new_book();
    let sock_addr = addr("192.168.1.10:4000");
    let endpoint = direct("8.8.4.4:50000");
    let replacement = direct("8.8.4.4:50001");
    book.add_sock_addr(sock_addr);
    book.add_endpoint_addr(sock_addr, endpoint).unwrap();
    let (first_sender, mut first) = mpsc::unbounded_channel();
    let (second_sender, mut second) = mpsc::unbounded_channel();
    let first_task = book.clone().change_then_publish_with_scope(Arc::new(TestPublisher(first_sender)), Scopes::ALL);
    let second_task = book.clone().change_then_publish_with_scope(Arc::new(TestPublisher(second_sender)), Scopes::ALL);
    tokio::pin!(first_task, second_task);
    assert!(futures::poll!(&mut first_task).is_pending());
    assert!(futures::poll!(&mut second_task).is_pending());
    let replay = vec![endpoint, sock_addr.into()];
    assert_eq!(first.try_recv().unwrap(), replay);
    assert_eq!(second.try_recv().unwrap(), replay);
    book.del_endpoint_addr(endpoint);
    book.add_endpoint_addr(sock_addr, replacement).unwrap();
    assert!(futures::poll!(&mut first_task).is_pending());
    assert!(futures::poll!(&mut second_task).is_pending());
    assert_eq!(first.try_recv().unwrap(), vec![replacement, sock_addr.into()]);
    assert_eq!(second.try_recv().unwrap(), vec![replacement, sock_addr.into()]);
    book.del_endpoint_addr(replacement);
    assert_eq!(published(&book), vec![sock_addr.into()]);
    drop(book);
    assert!(futures::poll!(&mut first_task).is_ready());
    assert!(futures::poll!(&mut second_task).is_ready());
}

#[test]
fn global_handles_share_the_same_directory() {
    let book = ArcAddrBook::global().clone();
    let sock_addr = addr("127.0.0.77:4000");
    assert!(ArcAddrBook::global().add_sock_addr(sock_addr));
    assert_eq!(book.mdns_query(sock_addr.ip()), Some(sock_addr));
    assert_eq!(published(&book), vec![sock_addr.into()]);
    book.del_sock_addr(sock_addr);
    assert_eq!(ArcAddrBook::global().mdns_query(sock_addr.ip()), None);
    assert!(published(&book).is_empty());
}

#[test]
fn matches_direct_peers_by_family_and_loopback_scope_without_nat() {
    let book = new_book();
    let private_v4 = direct("192.168.1.10:4000");
    let public_v4 = direct("8.8.4.4:5000");
    let private_v6 = direct("[fd00::10]:4000");
    let public_v6 = direct("[2001:4860::1]:5000");
    let loopback_v4 = direct("127.0.0.1:4000");
    let loopback_v6 = direct("[::1]:4000");
    for endpoint in [private_v4, public_v4, private_v6, public_v6, loopback_v4, loopback_v6, direct("0.0.0.0:4000")] {
        book.add_sock_addr(endpoint.addr());
    }
    for (peer, mut expected) in [
        (direct("1.1.1.1:443"), vec![private_v4, public_v4]),
        (direct("[2606:4700::1]:443"), vec![private_v6, public_v6]),
        (direct("127.0.0.2:443"), vec![loopback_v4]),
        (direct("[::1]:443"), vec![loopback_v6]),
        (public_v4, vec![private_v4]),
    ] {
        expected.sort_unstable();
        assert_eq!(book.matches(peer).as_slice(), expected.as_slice());
    }
    for peer in [direct("0.0.0.0:443"), direct("1.1.1.1:0"), direct("224.0.0.1:443")] {
        assert!(book.matches(peer).is_empty());
    }
    assert!(observed(&book).is_empty(), "matching endpoints does not require candidates");
}

#[test]
fn matches_uses_current_endpoints_and_returns_an_independent_result() {
    let book = new_book();
    let bound = addr("192.168.1.10:4000");
    let peer = direct("1.1.1.1:443");
    let alias = direct("8.8.4.4:50000");
    assert!(book.matches(peer).is_empty());
    book.add_sock_addr(bound);
    book.add_candidate(Link::new(bound, addr("8.8.8.8:50001")), NatType::RestrictedCone);
    book.add_endpoint_addr(bound, alias).unwrap();
    let matched = book.matches(peer);
    book.del_endpoint_addr(alias);
    assert_eq!(book.matches(peer).as_slice(), &[EndpointAddr::direct(bound)]);
    let mut expected = vec![EndpointAddr::direct(bound), alias];
    expected.sort_unstable();
    assert_eq!(matched.as_slice(), expected.as_slice());
    book.del_sock_addr(bound);
    assert!(book.matches(peer).is_empty());
}

#[test]
fn matches_mediated_peers_preserves_local_agents_and_mappings() {
    let book = new_book();
    let bound = addr("192.168.1.10:4000");
    book.add_sock_addr(bound);
    let first = EndpointAddr::mediate(addr("8.8.8.8:20002"), addr("8.8.4.4:50000"));
    let second = EndpointAddr::mediate(addr("1.0.0.1:20002"), first.addr());
    let v6 = EndpointAddr::mediate(addr("[2606:4700::1]:20002"), addr("[2001:4860::1]:50000"));
    let invalid = EndpointAddr::mediate(addr("8.8.8.8:20002"), addr("[2001:4860::1]:50000"));
    for endpoint in [first, second, v6, invalid] {
        book.add_endpoint_addr(bound, endpoint).unwrap();
    }
    let peer = EndpointAddr::mediate(addr("9.9.9.9:20002"), addr("1.1.1.1:60000"));
    let mut expected = vec![first, second];
    expected.sort_unstable();
    assert_eq!(book.matches(peer).as_slice(), expected.as_slice());
    let peer_v6 = EndpointAddr::mediate(addr("[2606:4700::2]:20002"), addr("[2001:4860::2]:60000"));
    assert_eq!(book.matches(peer_v6).as_slice(), &[v6]);
    assert!(book.matches(EndpointAddr::mediate(addr("9.9.9.9:0"), peer.addr())).is_empty());
}

#[test]
fn matches_returns_all_matching_endpoints_beyond_inline_capacity() {
    let book = new_book();
    let expected = (1..=6).map(|last| EndpointAddr::direct(([192, 168, 1, last], 4000).into())).collect::<Vec<_>>();
    for endpoint in &expected {
        book.add_sock_addr(endpoint.addr());
    }
    assert_eq!(book.matches(direct("1.1.1.1:443")).as_slice(), expected.as_slice());
}

#[tokio::test]
async fn publishers_filter_requested_scopes_and_publish_empty_lists_on_withdrawal() {
    let book = new_book();
    let bound = addr("192.168.1.10:4000");
    let loopback = addr("127.0.0.1:4000");
    let outer = direct("8.8.4.4:50000");
    let mediate = EndpointAddr::mediate(addr("8.8.8.8:20002"), outer.addr());
    for socket in [bound, loopback, addr("0.0.0.0:4000")] {
        book.add_sock_addr(socket);
    }
    book.add_endpoint_addr(bound, outer).unwrap();
    book.add_endpoint_addr(bound, mediate).unwrap();
    let (external_sender, mut external) = mpsc::unbounded_channel();
    let (internal_sender, mut internal) = mpsc::unbounded_channel();
    let external_task = book.clone().change_then_publish_with_scope(Arc::new(TestPublisher(external_sender)), Scope::External.into());
    let internal_task =
        book.clone().change_then_publish_with_scope(Arc::new(TestPublisher(internal_sender)), Scope::Loopback | Scope::Internal);
    tokio::pin!(external_task, internal_task);
    assert!(futures::poll!(&mut external_task).is_pending());
    assert!(futures::poll!(&mut internal_task).is_pending());
    assert_eq!(external.try_recv().unwrap(), vec![outer, mediate]);
    assert_eq!(internal.try_recv().unwrap(), vec![loopback.into(), bound.into()]);
    book.del_endpoint_addr(outer);
    book.del_endpoint_addr(mediate);
    assert!(futures::poll!(&mut external_task).is_pending());
    assert!(external.try_recv().unwrap().is_empty(), "an empty list withdraws previously published addresses");
}

#[tokio::test]
async fn slow_publication_releases_directory_locks_and_coalesces_updates_and_can_be_cancelled() {
    use std::{sync::Mutex, time::Duration};

    use tokio::sync::oneshot;

    #[derive(Debug)]
    struct SlowPublisher {
        publisher: TestPublisher,
        finish: Mutex<Option<oneshot::Receiver<()>>>,
    }

    impl fmt::Display for SlowPublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("slow publisher")
        }
    }

    impl Publish for SlowPublisher {
        fn publish<'a>(&'a self, endpoints: &mut dyn Iterator<Item = EndpointAddr>) -> PublishFuture<'a> {
            let pending = self.publisher.publish(endpoints);
            let finish = self.finish.lock().unwrap().take();
            Box::pin(async move {
                pending.await?;
                if let Some(finish) = finish {
                    finish.await.unwrap();
                }
                Ok(())
            })
        }
    }

    let book = new_book();
    let bound = addr("192.168.1.10:4000");
    let outer = direct("8.8.4.4:50000");
    let replacement = direct("8.8.4.4:50001");
    book.add_sock_addr(bound);
    book.add_endpoint_addr(bound, outer).unwrap();
    let (sender, mut publications) = mpsc::unbounded_channel();
    let (finish, blocked) = oneshot::channel();
    let publisher = Arc::new(SlowPublisher { publisher: TestPublisher(sender), finish: Mutex::new(Some(blocked)) });
    let weak = Arc::downgrade(&publisher);
    let task = tokio::spawn(book.clone().change_then_publish_with_scope(publisher, Scopes::ALL));
    assert_eq!(tokio::time::timeout(Duration::from_secs(1), publications.recv()).await.unwrap().unwrap(), vec![outer, bound.into()]);
    // Writes must complete while the first publish is awaiting its response.
    book.del_endpoint_addr(outer);
    book.add_endpoint_addr(bound, replacement).unwrap();
    assert_eq!(publications.try_recv(), Err(mpsc::error::TryRecvError::Empty));
    finish.send(()).unwrap();
    assert_eq!(tokio::time::timeout(Duration::from_secs(1), publications.recv()).await.unwrap().unwrap(), vec![replacement, bound.into()]);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(weak.upgrade().is_none(), "cancelling observation releases the publisher");
    book.del_sock_addr(bound);
    assert_eq!(publications.try_recv(), Err(mpsc::error::TryRecvError::Disconnected));
}

#[tokio::test]
async fn publication_failure_does_not_stop_subsequent_updates() {
    use std::{
        io,
        sync::atomic::{AtomicBool, Ordering},
    };

    #[derive(Debug)]
    struct FailOncePublisher(TestPublisher, AtomicBool);

    impl fmt::Display for FailOncePublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("fail-once publisher")
        }
    }

    impl Publish for FailOncePublisher {
        fn publish<'a>(&'a self, endpoints: &mut dyn Iterator<Item = EndpointAddr>) -> PublishFuture<'a> {
            let pending = self.0.publish(endpoints);
            let fail = self.1.swap(false, Ordering::Relaxed);
            Box::pin(async move {
                pending.await?;
                if fail {
                    return Err(io::Error::other("backend unavailable"));
                }
                Ok(())
            })
        }
    }

    let book = new_book();
    let (sender, mut publications) = mpsc::unbounded_channel();
    let publisher = Arc::new(FailOncePublisher(TestPublisher(sender), AtomicBool::new(true)));
    let observation = book.clone().change_then_publish_with_scope(publisher, Scopes::ALL);
    tokio::pin!(observation);
    assert!(futures::poll!(&mut observation).is_pending());
    assert!(publications.try_recv().unwrap().is_empty());
    let bound = addr("192.168.1.10:4000");
    book.add_sock_addr(bound);
    assert!(futures::poll!(&mut observation).is_pending());
    assert_eq!(publications.try_recv().unwrap(), vec![bound.into()]);
    drop(book);
    assert!(futures::poll!(&mut observation).is_ready());
}
