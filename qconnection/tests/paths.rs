use std::{sync::Arc, time::Duration};

use qbase::{error::ErrorKind, role::Role};

use crate::common::path_fixtures::{paths, paths_with_timeouts, pathway};

mod common;

#[tokio::test]
async fn get_admits_a_missing_path() {
    let paths = paths(Role::Server);
    let route = pathway(30002);
    let path = paths.get_or_create_path(&route);
    assert!(paths.entries.lock().unwrap().contains_key(&route));
    assert!(Arc::ptr_eq(&path, &paths.get_or_create_path(&route)));
    assert!(Arc::ptr_eq(&path, &paths.add_path(route)));
    assert!(paths.validations.get(&route).is_some());

    let response = path.validation.respond();
    assert!(paths.del_path(&route));
    assert!(!paths.del_path(&route));
    assert!(paths.entries.lock().unwrap().is_empty());
    assert!(paths.validations.get(&route).is_none());
    assert!(response.await.is_err());
    common::wait_for_sender_exit(&path).await;
    common::retire_all(&paths);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_get_and_add_reuse_the_same_path() {
    let paths = paths(Role::Server);
    let route = pathway(30002);
    let barrier = Arc::new(tokio::sync::Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let paths = paths.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            if index % 2 == 0 {
                paths.get_or_create_path(&route)
            } else {
                paths.add_path(route)
            }
        }));
    }
    let path = tasks.pop().unwrap().await.unwrap();
    for task in tasks {
        assert!(Arc::ptr_eq(&path, &task.await.unwrap()));
    }
    assert_eq!(paths.entries.lock().unwrap().len(), 1);
    common::retire_all(&paths);
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
    assert!(common::take_heartbeat(&first));
    assert!(!common::take_heartbeat(&second));
    paths.del_path(&first.pathway);
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
