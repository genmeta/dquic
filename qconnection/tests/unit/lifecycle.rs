use std::{future::pending, time::Duration};

use qbase::error::{ErrorKind, QuicError};

use crate::{CloseReason, lifecycle::any};

#[tokio::test]
async fn packet_events_retire_initial_but_leave_queue_removal_to_growing() {
    use qbase::{Epoch, role::Role};

    for role in [Role::Client, Role::Server] {
        let paths = crate::common::initial_paths(
            role,
            Default::default(),
            Default::default(),
            crate::common::initial_keys(role == Role::Server),
        );
        let space = crate::common::initial_space(&paths.spaces);
        let spaces = paths.spaces.clone();
        let resender = paths.resender.clone();
        if role == Role::Client {
            paths.on_handshake_received();
        } else {
            paths.on_handshake_sent();
        }
        assert!(space.keys.get().is_ok());
        if role == Role::Client {
            paths.on_handshake_sent();
        } else {
            paths.on_handshake_received();
        }
        assert!(space.keys.get().is_err());
        paths.handshake_confirmed();
        assert_eq!(spaces.read().unwrap().0.len(), 1);
        assert_eq!(resender.read().unwrap().len(), 1);

        super::retire_spaces(&paths, Epoch::Handshake);
        assert!(spaces.read().unwrap().0.is_empty());
        assert!(resender.read().unwrap().is_empty());
        assert!(space.keys.get().is_err());
        paths.retire_all();
    }
}

#[tokio::test]
async fn any_preserves_future_output() {
    let value = String::from("ready");
    let closed = qtransport::terminate::ArcTerminator::no_error();
    assert_eq!(any(async { &value }, closed.clone()).await.unwrap(), &value);
    assert_eq!(
        any(async { Err::<(), _>("failed") }, closed).await.unwrap(),
        Err("failed"),
    );
}

#[tokio::test(start_paused = true)]
async fn any_termination_interrupts_a_pending_future() {
    let closed = qtransport::terminate::ArcTerminator::no_error();
    let waiting = tokio::spawn(any(pending::<()>(), closed.clone()));
    tokio::task::yield_now().await;
    closed.close(
        CloseReason::Internal(QuicError::with_default_fty(
            ErrorKind::ConnectionRefused,
            "connection closed while waiting",
        )),
        Duration::from_secs(1),
    );

    assert!(!waiting.is_finished());
    tokio::time::advance(Duration::from_secs(3)).await;
    let reason = tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(reason, crate::Error::Quic(error)
        if error.kind() == ErrorKind::ConnectionRefused
            && error.reason() == "connection closed while waiting"));
}
