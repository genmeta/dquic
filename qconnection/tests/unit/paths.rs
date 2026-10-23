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
async fn existing_and_new_paths_observe_shared_handshake_progress_on_tick() {
    use qcongestion::Transport as _;

    let paths = paths(Role::Client);
    let first = paths.add_path(pathway(30002));
    first.cc.on_pkt_rcvd(Epoch::Initial, 0, true);
    first.cc.on_pkt_rcvd(Epoch::Handshake, 0, true);
    assert!(first.cc.need_ack(Epoch::Initial).is_some());
    assert!(first.cc.need_ack(Epoch::Handshake).is_some());

    paths.on_handshake_sent();
    first.cc.do_tick().unwrap();
    assert!(first.cc.need_ack(Epoch::Initial).is_none());
    assert!(first.cc.need_ack(Epoch::Handshake).is_some());
    let second = paths.add_path(pathway(30003));
    second.cc.do_tick().unwrap();
    second.cc.on_pkt_rcvd(Epoch::Initial, 0, true);
    second.cc.on_pkt_rcvd(Epoch::Handshake, 0, true);
    assert!(second.cc.need_ack(Epoch::Initial).is_none());
    assert!(second.cc.need_ack(Epoch::Handshake).is_some());

    paths.handshake.handshake_confirmed();
    for path in [&first, &second] {
        path.cc.do_tick().unwrap();
        assert!(path.cc.need_ack(Epoch::Initial).is_none());
        assert!(path.cc.need_ack(Epoch::Handshake).is_none());
    }
    let third = paths.add_path(pathway(30004));
    third.cc.do_tick().unwrap();
    for epoch in [Epoch::Initial, Epoch::Handshake] {
        third.cc.on_pkt_rcvd(epoch, 0, true);
        assert!(third.cc.need_ack(epoch).is_none());
    }
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn clean_stops_idle_expiry_and_releases_paths_spaces_and_recovery() {
    use qbase::packet::PacketContent;
    use qcongestion::Transport as _;
    use tokio::time::Instant;

    let paths = paths_with_timeouts(Role::Server, Duration::from_secs(5), Duration::ZERO);
    let initial = crate::common::initial_space(&paths.spaces);
    let first = paths.add_path(pathway(30002));
    let second = paths.add_path(pathway(30003));
    let response = first.validation.respond();
    for path in [&first, &second] {
        for epoch in [Epoch::Initial, Epoch::Handshake] {
            path.cc.on_pkt_sent(epoch, 0, true, 1200, true, None);
        }
    }
    paths.clean();
    paths.clean();

    assert!(paths.entries.lock().unwrap().is_empty());
    assert!(paths.spaces.read_guard().is_empty());
    assert!(paths.loss_resender.read_guard().is_empty());
    assert!(initial.keys.get().is_err());
    assert!(paths.idle().timeout().await.is_err());
    assert!(response.await.is_err());
    tokio::time::advance(Duration::from_secs(10)).await;
    for path in [&first, &second] {
        assert!(paths.validations.get(&path.pathway).is_none());
        assert!(path.validation.credit().is_err());
        assert!(matches!(super::borrow(path), std::task::Poll::Ready(None)));
        assert!(
            path.heartbeat
                .on_rcvd_at(PacketContent::EffectivePayload, Instant::now())
                .is_err()
        );
        path.cc.do_tick().unwrap();
        assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Initial), 0);
        assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Handshake), 0);
    }
    paths.terminator.terminate();
    crate::common::wait_for_sender_exit(&first).await;
    crate::common::wait_for_sender_exit(&second).await;
}

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
    let incoming = paths.get_or_create_path(&pathway(30004));
    for path in [&first, &second, &incoming] {
        assert!(path.validation.is_validated());
        assert_eq!(crate::common::path_credit(path), usize::MAX);
        assert_eq!(super::selection(&paths, path), u8::MAX);
    }
    paths.select_path(&first);
    assert_eq!(super::selection(&paths, &first), 1);
    assert_eq!(super::selection(&paths, &second), 0);
    assert_eq!(super::selection(&paths, &incoming), 0);
    assert!(second.validation.is_validated());
    super::enter_mature(&paths, &mature);
    assert!(paths.add_path(pathway(30005)).validation.is_validated());
    assert!(
        matches!(super::borrow(&first), std::task::Poll::Ready(Some(cid)) if *cid == mature.peer_cid())
    );
    assert!(super::borrow(&second).is_pending());
    super::confirm_handshake(&paths);
    let added = paths.add_path(pathway(30006));
    assert!(Arc::ptr_eq(&added, &paths.add_path(added.pathway)));
    paths.start_validation(&added);
    tokio::task::yield_now().await;
    for path in paths.entries.lock().unwrap().values() {
        assert_eq!(super::selection(&paths, path), 2);
        assert!(path.validation.is_validated());
        assert_eq!(crate::common::path_credit(path), usize::MAX);
        assert!(super::take_validation_frames(path).is_empty());
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
    paths.del_path(&first.pathway);
    assert!(paths.add_path(pathway(30008)).validation.is_validated());
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
        paths.del_path(&stale.pathway);
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
    paths.del_path(&stale.pathway);
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
    paths.del_path(&first.pathway);
    let added = paths.add_path(pathway(30004));
    assert_eq!(super::selection(&paths, &added), 0);
    paths.select_path(&second);
    paths.select_path(&added);
    assert!(
        paths
            .entries
            .lock()
            .unwrap()
            .values()
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
    assert!(!second.validation.is_validated());
    paths
        .validations
        .recv_frame((
            first.pathway,
            qbase::frame::PathResponseFrame::from(challenge),
        ))
        .unwrap();
    tokio::task::yield_now().await;
    assert!(first.validation.is_validated());
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
    assert!(path.validation.is_cancelled());
    assert!(!path.validation.is_validated());
    assert!(!paths.entries.lock().unwrap().contains_key(&path.pathway));
    assert!(paths.validations.get(&path.pathway).is_none());
    assert!(
        matches!(paths.terminator.clone().await, crate::Error::Quic(error) if error.kind() == ErrorKind::NoViablePath)
    );
}

#[tokio::test(start_paused = true)]
async fn failed_validation_removes_its_path_and_stops_its_sender_without_closing_other_paths() {
    let paths = paths(Role::Server);
    let live = paths.add_path(pathway(30002));
    live.validation.enter_validated().unwrap();
    let failed = paths.add_path(pathway(30003));
    confirm_validation(&paths);
    let close = crate::common::observe_close(&paths.terminator);
    paths.start_validation(&failed);
    tokio::task::yield_now().await;
    let [Frame::PathChallenge(challenge)] = super::take_validation_frames(&failed)[..] else {
        panic!("expected one challenge");
    };
    let mut mismatched = *challenge;
    mismatched[0] ^= 1;
    paths
        .validations
        .recv_frame((
            failed.pathway,
            qbase::frame::PathResponseFrame::from(PathChallengeFrame::from_slice(&mismatched)),
        ))
        .unwrap();

    crate::common::wait_for_sender_exit(&failed).await;
    assert!(!paths.entries.lock().unwrap().contains_key(&failed.pathway));
    assert!(paths.validations.get(&failed.pathway).is_none());
    assert!(Arc::ptr_eq(
        &paths
            .entries
            .lock()
            .unwrap()
            .get(&live.pathway)
            .cloned()
            .unwrap(),
        &live
    ));
    assert!(close.notified().is_none());
    paths.retire_all();
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
        assert!(Arc::ptr_eq(&path, &paths.get_or_create_path(&path.pathway)));
        tokio::task::yield_now().await;
        assert!(super::take_validation_frames(&path).is_empty());
        tokio::time::advance(path.cc.pto_base(Epoch::Data) * 3).await;
        tokio::task::yield_now().await;
    }
    assert!(path.validation.is_cancelled());
    assert!(!paths.entries.lock().unwrap().contains_key(&path.pathway));
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
    paths.del_path(&replacement.pathway);
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
        assert!(path.validation.is_validated());
        assert!(paths.validations.get(&path.pathway).unwrap().is_validated());
    }
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn old_validation_and_sending_tasks_cannot_remove_a_replacement_at_the_same_pathway() {
    let paths = paths(Role::Server);
    let previous = paths.add_path(pathway(30002));
    confirm_validation(&paths);
    paths.start_validation(&previous);
    tokio::task::yield_now().await;
    paths.del_path(&previous.pathway);
    let replacement = paths.add_path(previous.pathway);
    crate::common::wait_for_sender_exit(&previous).await;
    assert!(Arc::ptr_eq(
        &paths
            .entries
            .lock()
            .unwrap()
            .get(&replacement.pathway)
            .cloned()
            .unwrap(),
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
    assert!(replacement.validation.is_validated());
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
    selected.close();
}
