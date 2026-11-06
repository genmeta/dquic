use std::sync::{Arc, Barrier};

use qbase::{handshake::HandshakeFacts, role::Role};

const EVENTS: [fn(&HandshakeFacts) -> bool; 8] = [
    HandshakeFacts::on_path_selected,
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
            workers.into_iter().map(|worker| worker.join().unwrap()).filter(|first| *first).count()
        });
        assert_eq!(winners, 1);
        assert!(!event(&facts));
    }
}

#[test]
fn quitting_multipath_handshaking_is_shared_and_events_cannot_restart_it() {
    for role in [Role::Client, Role::Server] {
        let facts = Arc::new(HandshakeFacts::with_role(role));
        assert!(facts.is_mp_handshaking());
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let facts = facts.clone();
                scope.spawn(move || facts.quit_mp_handshaking());
            }
        });
        assert!(!facts.is_mp_handshaking());
        for event in EVENTS {
            event(&facts);
            assert!(!facts.is_mp_handshaking());
        }
    }
}
