use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use qbase::{
    Epoch,
    error::ErrorKind,
    frame::{Frame, PathChallengeFrame, io::ReceiveFrame},
    role::Role,
};

use crate::{
    Paths,
    common::path_fixtures::{paths, paths_with_timeouts, pathway},
};

#[tokio::test(start_paused = true)]
async fn idle_timeout_notifies_close_without_a_path_or_tick_task() {
    let paths = paths_with_timeouts(Role::Server, Duration::from_secs(5), Duration::ZERO);
    let start = tokio::time::Instant::now();
    paths.idle().on_rcvd_at(start).unwrap().unwrap();
    let reason = paths.terminator.clone().await;
    assert!(matches!(reason, crate::Error::Quic(error)
        if error.kind() == ErrorKind::None && error.reason() == "connection idle timeout"));
    assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(8));
}

#[tokio::test(start_paused = true)]
async fn cancelled_idle_timer_does_not_request_close() {
    let paths = paths_with_timeouts(Role::Server, Duration::from_secs(5), Duration::ZERO);
    let notification = crate::common::observe_close(&paths.terminator.clone());
    let idle = paths.idle();
    idle.on_rcvd_at(tokio::time::Instant::now())
        .unwrap()
        .unwrap();
    tokio::task::yield_now().await;
    idle.cancel();
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    assert!(notification.notified().is_none());
}

#[tokio::test]
async fn client_paths_are_exempt_without_local_challenges() {
    let (paths, mature) = super::send::mature_phase(Role::Client, Duration::ZERO);
    let first = paths.add_path(pathway(30002));
    let second = paths.add_path(pathway(30003));
    let incoming = paths.on_incoming_path(pathway(30004));
    for path in [&first, &second, &incoming] {
        assert!(path.is_validated());
        assert_eq!(crate::common::path_credit(path), usize::MAX);
        assert_eq!(super::selection(&paths, path), u8::MAX);
    }
    paths.select_path(&first);
    assert_eq!(super::selection(&paths, &first), 1);
    assert_eq!(super::selection(&paths, &second), 0);
    assert_eq!(super::selection(&paths, &incoming), 0);
    assert!(second.is_validated());
    super::enter_mature(&paths, &mature);
    assert!(paths.add_path(pathway(30005)).is_validated());
    assert!(
        matches!(super::borrow(&first), std::task::Poll::Ready(Some(cid)) if *cid == mature.peer_cid())
    );
    assert!(super::borrow(&second).is_pending());
    super::confirm_handshake(&paths);
    let added = paths.add_path(pathway(30006));
    assert!(Arc::ptr_eq(&added, &paths.add_path(added.pathway)));
    paths.start_validation(&added);
    tokio::task::yield_now().await;
    for path in paths.snapshot() {
        assert_eq!(super::selection(&paths, &path), 2);
        assert!(path.is_validated());
        assert_eq!(crate::common::path_credit(&path), usize::MAX);
        assert!(super::take_validation_frames(&path).is_empty());
        assert!(paths.validations.get(&path.pathway).unwrap().is_validated());
    }
    paths
        .validations
        .recv_frame((added.pathway, PathChallengeFrame::from_slice(&[7; 8])))
        .unwrap();
    assert!(matches!(
        super::take_validation_frames(&added).as_slice(),
        [Frame::PathResponse(_)]
    ));
    paths.remove(&first);
    assert!(paths.add_path(pathway(30008)).is_validated());
    paths.retire_all();
}

#[tokio::test]
async fn selecting_a_live_handshake_path_stops_crypto_replay() {
    for role in [Role::Client, Role::Server] {
        let is_mp_handshaking = Arc::new(AtomicBool::new(true));
        let paths = crate::common::initial_paths_with_timeouts(
            role,
            qbase::cid::ConnectionId::from_slice(b"localcid"),
            qbase::cid::ConnectionId::from_slice(b"original"),
            crate::common::initial_keys(role == Role::Server),
            Duration::ZERO,
            Duration::ZERO,
            is_mp_handshaking.clone(),
        );
        let stale = paths.add_path(pathway(30002));
        paths.remove(&stale);
        let selected = paths.add_path(pathway(30002));
        paths.select_path(&stale);
        assert!(is_mp_handshaking.load(Ordering::Relaxed));
        paths.select_path(&selected);
        assert!(!is_mp_handshaking.load(Ordering::Relaxed));
        paths.retire_all();
    }
}

#[tokio::test]
async fn removed_undecided_path_cannot_override_selection() {
    let paths = paths(Role::Client);
    let stale = paths.add_path(pathway(30002));
    let selected = paths.add_path(pathway(30003));
    paths.remove(&stale);
    paths.select_path(&selected);
    paths.select_path(&stale);
    assert_eq!(super::selection(&paths, &selected), 1);
    paths.retire_all();
}

#[tokio::test]
async fn initial_cid_is_reserved_only_after_path_selection() {
    let (paths, mature) = super::send::mature_phase(Role::Server, Duration::ZERO);
    let first = paths.add_path(pathway(30002));
    let second = paths.add_path(pathway(30003));
    paths.cids.attach_remote(mature.cid_registry.remote.clone());
    assert!(
        matches!(super::borrow(&first), std::task::Poll::Ready(Some(cid)) if *cid == paths.cids.initial_dcid())
    );
    assert!(
        matches!(super::borrow(&second), std::task::Poll::Ready(Some(cid)) if *cid == paths.cids.initial_dcid())
    );
    paths.select_path(&second);
    assert!(super::borrow(&first).is_pending());
    assert!(
        matches!(super::borrow(&second), std::task::Poll::Ready(Some(cid)) if *cid == mature.peer_cid())
    );
    paths.retire_all();
}

#[tokio::test]
async fn removing_selected_path_does_not_allow_suspended_paths_to_reselect() {
    let paths = paths(Role::Client);
    let first = paths.add_path(pathway(30002));
    let second = paths.add_path(pathway(30003));
    paths.select_path(&first);
    paths.remove(&first);
    let added = paths.add_path(pathway(30004));
    assert_eq!(super::selection(&paths, &added), 0);
    paths.select_path(&second);
    paths.select_path(&added);
    assert!(
        paths
            .snapshot()
            .iter()
            .all(|path| super::selection(&paths, path) == 0)
    );
    paths.retire_all();
}

#[tokio::test]
async fn server_paths_start_guarded_and_responses_are_dispatched_by_pathway() {
    let paths = paths(Role::Server);
    let first = paths.add_path(pathway(30002));
    let second = paths.add_path(pathway(30003));
    assert_eq!(crate::common::path_credit(&first), 0);
    paths.start_validation(&first);
    confirm_validation(&paths);
    paths.start_validation(&first);
    tokio::task::yield_now().await;
    let [Frame::PathChallenge(challenge)] = super::take_validation_frames(&first)[..] else {
        panic!("expected one challenge");
    };
    paths
        .validations
        .recv_frame((
            second.pathway,
            qbase::frame::PathResponseFrame::from(challenge),
        ))
        .unwrap();
    assert!(!second.is_validated());
    paths
        .validations
        .recv_frame((
            first.pathway,
            qbase::frame::PathResponseFrame::from(challenge),
        ))
        .unwrap();
    tokio::task::yield_now().await;
    assert!(first.is_validated());
    assert_eq!(crate::common::path_credit(&first), usize::MAX);
    assert_eq!(crate::common::path_credit(&second), 0);
    assert!(
        paths
            .validations
            .get(&first.pathway)
            .unwrap()
            .is_validated()
    );
    paths.retire_all();
}

#[tokio::test]
async fn first_mismatched_response_fails_even_if_a_matching_response_follows() {
    let paths = paths(Role::Server);
    let path = paths.add_path(pathway(30002));
    confirm_validation(&paths);
    paths.start_validation(&path);
    tokio::task::yield_now().await;
    let [Frame::PathChallenge(challenge)] = super::take_validation_frames(&path)[..] else {
        panic!("expected one challenge");
    };
    let mut mismatched = *challenge;
    mismatched[0] ^= 1;
    let mismatch =
        qbase::frame::PathResponseFrame::from(PathChallengeFrame::from_slice(&mismatched));
    paths
        .validations
        .recv_frame((path.pathway, mismatch))
        .unwrap();
    paths
        .validations
        .recv_frame((
            path.pathway,
            qbase::frame::PathResponseFrame::from(challenge),
        ))
        .unwrap();
    tokio::task::yield_now().await;
    assert!(path.is_retired());
    assert!(!path.is_validated());
    assert!(paths.get(&path.pathway).is_none());
    assert!(paths.validations.get(&path.pathway).is_none());
    assert!(
        matches!(paths.terminator.clone().await, crate::Error::Quic(error) if error.kind() == ErrorKind::NoViablePath)
    );
}

#[tokio::test(start_paused = true)]
async fn validation_retransmits_the_same_challenge_three_times_and_retirement_cancels_waiting() {
    let paths = paths(Role::Server);
    let path = paths.add_path(pathway(30002));
    confirm_validation(&paths);
    paths.start_validation(&path);
    tokio::task::yield_now().await;
    let mut expected = None;
    for _ in 0..4 {
        let [Frame::PathChallenge(challenge)] = super::take_validation_frames(&path)[..] else {
            panic!("expected a retransmitted challenge");
        };
        assert_eq!(*expected.get_or_insert(challenge), challenge);
        assert!(Arc::ptr_eq(&path, &paths.add_path(path.pathway)));
        assert!(Arc::ptr_eq(&path, &paths.on_incoming_path(path.pathway)));
        tokio::task::yield_now().await;
        assert!(super::take_validation_frames(&path).is_empty());
        tokio::time::advance(path.cc.pto_base(Epoch::Data) * 3).await;
        tokio::task::yield_now().await;
    }
    assert!(path.is_retired());
    assert!(paths.get(&path.pathway).is_none());
    assert!(paths.validations.get(&path.pathway).is_none());
    assert!(
        matches!(paths.terminator.clone().await, crate::Error::Quic(error) if error.kind() == ErrorKind::NoViablePath)
    );

    let paths = self::paths(Role::Server);
    let replacement = paths.add_path(pathway(30002));
    confirm_validation(&paths);
    paths.start_validation(&replacement);
    tokio::task::yield_now().await;
    let response = replacement.validation.respond();
    paths.remove(&replacement);
    assert!(response.await.is_err());
    tokio::task::yield_now().await;
    assert!(paths.validations.get(&replacement.pathway).is_none());
}

#[tokio::test]
async fn revalidation_starts_a_new_task_on_the_registered_validation() {
    let paths = paths(Role::Server);
    let path = paths.add_path(pathway(30002));
    confirm_validation(&paths);
    for round in 0..2 {
        if round == 1 {
            let previous = path.validation.respond();
            path.validation.revalidate().unwrap();
            assert_eq!(previous.await.unwrap(), None);
            assert_eq!(crate::common::path_credit(&path), 0);
            assert!(!paths.validations.get(&path.pathway).unwrap().is_validated());
        }
        paths.start_validation(&path);
        tokio::task::yield_now().await;
        let [Frame::PathChallenge(challenge)] = super::take_validation_frames(&path)[..] else {
            panic!("expected this round's challenge");
        };
        paths
            .validations
            .recv_frame((
                path.pathway,
                qbase::frame::PathResponseFrame::from(challenge),
            ))
            .unwrap();
        tokio::task::yield_now().await;
        assert!(path.is_validated());
        assert!(paths.validations.get(&path.pathway).unwrap().is_validated());
    }
    paths.retire_all();
}

#[tokio::test]
async fn an_old_validation_task_cannot_remove_a_replacement_at_the_same_pathway() {
    let paths = paths(Role::Server);
    let previous = paths.add_path(pathway(30002));
    confirm_validation(&paths);
    paths.start_validation(&previous);
    tokio::task::yield_now().await;
    paths.remove(&previous);
    let replacement = paths.add_path(previous.pathway);
    assert!(!paths.remove(&previous));
    tokio::task::yield_now().await;
    assert!(Arc::ptr_eq(
        &paths.get(&replacement.pathway).unwrap(),
        &replacement
    ));
    assert!(paths.validations.get(&replacement.pathway).is_some());
    let [Frame::PathChallenge(challenge)] = super::take_validation_frames(&replacement)[..] else {
        panic!("expected the replacement's challenge");
    };
    paths
        .validations
        .recv_frame((
            replacement.pathway,
            qbase::frame::PathResponseFrame::from(challenge),
        ))
        .unwrap();
    tokio::task::yield_now().await;
    assert!(replacement.is_validated());
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn disabled_negotiated_timeout_remains_cancellable_after_activity() {
    let paths = paths(Role::Server);
    paths.update_max_idle_timeout(Duration::MAX);
    paths
        .idle()
        .on_rcvd_at(tokio::time::Instant::now())
        .unwrap()
        .unwrap();
    let waiting = paths.idle().timeout();
    tokio::pin!(waiting);
    assert!(futures::poll!(&mut waiting).is_pending());
    paths.idle().cancel();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), waiting)
            .await
            .unwrap()
            .is_err()
    );
}

// Validation tests do not run TLS or a real handshake sender. Finish a separate
// handshake path so the tested paths remain unvalidated and wait for extra CIDs.
fn confirm_validation(paths: &Arc<Paths>) {
    let selected = qtransport::path::Path::new(
        pathway(39999),
        paths.handshake.clone(),
        qbase::time::heartbeat::ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        paths.loss_resender.clone(),
        &paths.cids,
    );
    paths.cids.select(&selected.cid);
    paths.cids.attach_remote(qbase::cid::ArcRemoteCids::new(
        paths.cids.initial_dcid(),
        2,
        paths.reliable_frames.clone(),
    ));
    paths.handshake.handshake_confirmed();
    paths.cids.confirm_handshake();
    selected.retire();
}
