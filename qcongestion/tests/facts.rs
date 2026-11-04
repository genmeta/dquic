use std::sync::{Arc, Barrier};

use qbase::role::Role;

// White-box access keeps the ACK transition crate-private.
#[path = "../src/facts.rs"]
#[allow(dead_code)]
mod facts;

use facts::HandshakeFacts;

const EVENTS: [fn(&HandshakeFacts) -> bool; 7] = [
    HandshakeFacts::on_initial_received,
    HandshakeFacts::install_handshake_key,
    HandshakeFacts::on_handshake_sent,
    HandshakeFacts::on_handshake_received,
    HandshakeFacts::on_handshake_acked,
    HandshakeFacts::on_tls_finished,
    HandshakeFacts::on_handshake_done,
];

#[test]
fn each_fact_reports_only_its_first_transition() {
    for role in [Role::Client, Role::Server] {
        let facts = HandshakeFacts::with_role(role);
        assert!(!facts.has_received_initial());
        for event in EVENTS {
            assert!(event(&facts));
        }
        for event in EVENTS {
            assert!(!event(&facts));
        }
        assert!(facts.has_received_initial());
    }
}

#[test]
fn concurrent_updates_claim_each_fact_once() {
    let facts = Arc::new(HandshakeFacts::with_role(Role::Client));
    for event in EVENTS {
        let barrier = Barrier::new(8);
        let winners = std::thread::scope(|scope| {
            let workers = (0..8)
                .map(|_| {
                    let barrier = &barrier;
                    let facts = &facts;
                    scope.spawn(move || {
                        barrier.wait();
                        event(facts)
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .filter(|first| *first)
                .count()
        });
        assert_eq!(winners, 1);
        assert!(!event(&facts));
    }
}
