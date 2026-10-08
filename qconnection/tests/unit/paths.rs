use std::{sync::Arc, time::Duration};

use qbase::{
    Epoch,
    cid::ConnectionId,
    error::ErrorKind,
    frame::PathChallengeFrame,
    net::{addr::EndpointAddr, route::Pathway},
    role::Role,
};
use qtransport::{
    path::{Path, PathState},
};

use crate::Paths;

fn paths(role: Role) -> Arc<Paths> {
    paths_with_timeouts(role, Duration::ZERO, Duration::ZERO)
}

fn paths_with_timeouts(role: Role, max: Duration, defer: Duration) -> Arc<Paths> {
    let keys = qtls::default_provider()
        .cipher_suites
        .iter()
        .find_map(|suite| suite.tls13().and_then(|suite| suite.quic_suite()))
        .unwrap()
        .keys(
            b"original",
            if role == Role::Server {
                tls_backend::Side::Server
            } else {
                tls_backend::Side::Client
            },
            tls_backend::quic::Version::V1,
        )
        .into();
    crate::common::initial_paths_with_timeouts(
        role,
        ConnectionId::from_slice(b"localcid"),
        ConnectionId::from_slice(b"original"),
        keys,
        max,
        defer,
    )
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

fn pathway(port: u16) -> Pathway {
    Pathway::new(
        EndpointAddr::direct(([127, 0, 0, 1], 30001).into()),
        EndpointAddr::direct(([127, 0, 0, 1], port).into()),
    )
}

#[tokio::test]
async fn only_client_initial_paths_are_exempt_and_losing_paths_reset_the_guard() {
    let (paths, mature) = super::send::mature_phase(Role::Client, Duration::ZERO);
    let first = paths.add_path(pathway(30002));
    let second = paths.add_path(pathway(30003));
    assert_eq!(first.state(), PathState::ClientHandshaking);
    assert_eq!(second.amplification_credit(), usize::MAX);
    let incoming = paths.on_incoming_path(pathway(30004));
    assert_eq!(incoming.amplification_credit(), 0);
    assert_eq!(first.selected(), u8::MAX);
    assert_eq!(second.selected(), u8::MAX);
    paths.select_path(&first);
    assert_eq!(first.selected(), 1);
    assert_eq!(second.selected(), 0);
    assert_eq!(incoming.selected(), 0);
    assert_eq!(first.state(), PathState::ClientHandshaking);
    assert_eq!(
        second.state(),
        PathState::AmplifyGuard {
            rcvd_bytes: 0,
            sent_bytes: 0
        }
    );
    assert_eq!(second.amplification_credit(), 0);
    second.on_datagram_received(100);
    second.anti_amplifier.on_sent(200);
    assert_eq!(second.amplification_credit(), 100);
    super::enter_mature(&paths, &mature);
    assert_eq!(paths.add_path(pathway(30005)).amplification_credit(), 0);
    assert!(first.dcid_cell.read().unwrap().is_some());
    assert!(second.dcid_cell.read().unwrap().is_none());
    super::confirm_handshake(&paths);
    assert!(paths.snapshot().iter().all(|path| path.selected() == 2));
    assert!(first.is_validated());
    assert!(!second.is_validated());
    assert_eq!(second.state(), PathState::ClientValidating);
    assert_eq!(second.amplification_credit(), usize::MAX);
    let added = paths.add_path(pathway(30006));
    assert_eq!(added.selected(), 2);
    assert_eq!(added.state(), PathState::ClientValidating);
    paths.select_path(&added);
    assert!(
        paths
            .snapshot()
            .iter()
            .all(|path| path.selected() == Path::HANDSHAKED)
    );
    let validating = paths.responses.lock().unwrap().len();
    assert!(Arc::ptr_eq(&added, &paths.add_path(added.pathway)));
    assert_eq!(paths.responses.lock().unwrap().len(), validating);
    tokio::task::yield_now().await;
    assert!(first.challenge().is_none());
    assert!(second.challenge().is_some());
    assert!(added.challenge().is_some());
    paths.on_path_response(&second, second.challenge().unwrap().into());
    tokio::task::yield_now().await;
    assert!(second.is_validated());
    paths.remove(&first);
    let after_removal = paths.add_path(pathway(30008));
    assert_eq!(after_removal.selected(), Path::HANDSHAKED);
    assert_eq!(after_removal.state(), PathState::ClientValidating);
    paths.retire_all();
}

#[tokio::test]
async fn removed_undecided_path_cannot_override_selection() {
    let paths = paths(Role::Client);
    let stale = paths.add_path(pathway(30002));
    let selected = paths.add_path(pathway(30003));
    paths.remove(&stale);
    paths.select_path(&selected);
    paths.select_path(&stale);
    assert_eq!(selected.selected(), Path::SELECTED);
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
    assert_eq!(added.selected(), Path::SUSPEND);
    paths.select_path(&second);
    paths.select_path(&added);
    assert!(
        paths
            .snapshot()
            .iter()
            .all(|path| path.selected() == Path::SUSPEND)
    );
    paths.retire_all();
}

#[tokio::test]
async fn server_paths_start_guarded_and_only_the_correct_path_response_validates() {
    let paths = paths(Role::Server);
    let first = paths.add_path(pathway(30002));
    let second = paths.add_path(pathway(30003));
    assert_eq!(first.amplification_credit(), 0);
    paths.start_validation(&first);
    assert!(paths.responses.lock().unwrap().is_empty());
    first.handshake_confirmed();
    paths.start_validation(&first);
    paths.start_validation(&first);
    tokio::task::yield_now().await;
    assert_eq!(paths.responses.lock().unwrap().len(), 1);
    let challenge = first.challenge().unwrap();
    paths.on_path_response(&second, challenge.into());
    paths.on_path_response(&first, PathChallengeFrame::from_slice(&[42; 8]).into());
    assert!(!first.is_validated());
    paths.on_path_response(&first, challenge.into());
    tokio::task::yield_now().await;
    assert!(first.is_validated());
    assert_eq!(first.amplification_credit(), usize::MAX);
    assert_eq!(second.amplification_credit(), 0);
    assert!(paths.responses.lock().unwrap().is_empty());
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn validation_times_out_after_three_attempts_and_retirement_cancels_waiting() {
    let paths = paths(Role::Server);
    let path = paths.add_path(pathway(30002));
    path.handshake_confirmed();
    paths.start_validation(&path);
    tokio::task::yield_now().await;
    for _ in 0..3 {
        assert!(path.challenge().is_some());
        tokio::time::advance(path.cc.pto_base(Epoch::Data) * 3).await;
        tokio::task::yield_now().await;
    }
    assert_eq!(path.state(), PathState::Retired);
    assert!(paths.get(&path.pathway).is_none());
    assert!(paths.responses.lock().unwrap().is_empty());
    assert!(
        matches!(paths.terminator.clone().await, crate::Error::Quic(error) if error.kind() == ErrorKind::NoViablePath)
    );
    let paths = self::paths(Role::Server);
    let replacement = paths.add_path(pathway(30002));
    replacement.handshake_confirmed();
    paths.start_validation(&replacement);
    tokio::task::yield_now().await;
    let response = paths
        .responses
        .lock()
        .unwrap()
        .get(&replacement.pathway)
        .unwrap()
        .clone();
    paths.remove(&replacement);
    assert!(response.await.is_err());
    tokio::task::yield_now().await;
    assert!(paths.responses.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn paths_have_independent_heartbeats_and_retirement_cancels_only_one() {
    use qbase::packet::PacketContent;
    use tokio::time::Instant;

    let paths = paths_with_timeouts(
        Role::Server,
        Duration::from_secs(60),
        Duration::from_secs(60),
    );
    let first = paths.add_path(pathway(30002));
    let second = paths.add_path(pathway(30003));
    first
        .heartbeat
        .on_rcvd_at(PacketContent::EffectivePayload, Instant::now())
        .unwrap();
    tokio::time::advance(Duration::from_secs(20)).await;
    assert!(super::take_heartbeat(&first));
    assert!(!super::take_heartbeat(&second));
    paths.remove(&first);
    assert!(
        first
            .heartbeat
            .on_rcvd_at(PacketContent::EffectivePayload, Instant::now())
            .is_err()
    );
    assert!(
        second
            .heartbeat
            .on_rcvd_at(PacketContent::EffectivePayload, Instant::now())
            .is_ok()
    );
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

#[tokio::test(start_paused = true)]
async fn terminator_does_not_retain_paths() {
    let paths = paths(Role::Server);
    let terminator = paths.terminator.clone();
    let weak = Arc::downgrade(&paths);
    drop(paths);
    assert!(weak.upgrade().is_none());
    terminator.close(
        qtransport::CloseReason::Internal(qbase::error::QuicError::with_default_fty(
            ErrorKind::Internal,
            "closed after owner dropped",
        )),
        Duration::from_secs(1),
    );
    assert_eq!(terminator.await.kind(), ErrorKind::Internal);
}
