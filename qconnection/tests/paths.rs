use std::{sync::Arc, time::Duration};

use qbase::{error::ErrorKind, role::Role};

use crate::common::path_fixtures::{paths, paths_with_timeouts, pathway};

mod common;

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
    assert!(common::take_heartbeat(&first));
    assert!(!common::take_heartbeat(&second));
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
    common::retire_all(&paths);
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
