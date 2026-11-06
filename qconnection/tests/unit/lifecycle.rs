use std::{future::pending, time::Duration};

use qbase::error::{ErrorKind, QuicError};

use crate::{CloseReason, lifecycle::any};

#[tokio::test]
async fn confirmation_retires_spaces_and_allows_only_the_first_key_update() {
    use qbase::Epoch;

    for mature in crate::common::spaces::pair() {
        let paths = &mature.paths;
        super::install_data(paths, &mature);
        let path = paths.add_path(crate::common::path_fixtures::pathway(37002));
        paths.progress.on_path_selected(paths, &path);
        assert!(mature.spaces.data.keys.update().is_err());

        std::thread::scope(|scope| {
            for _ in 0..4 {
                let progress = paths.progress.clone();
                scope.spawn(move || {
                    progress.on_handshake_sent();
                    progress.on_handshake_received();
                    progress.on_handshake_done(paths);
                });
            }
        });
        assert!(mature.spaces.initial.keys.get().is_err());
        assert!(mature.spaces.handshake.keys.get().is_err());
        assert_eq!(paths.spaces.read_guard().offset(), Epoch::Data as u64);
        assert_eq!(paths.spaces.read_guard().len(), 1);
        assert_eq!(
            paths.loss_resender.read_guard().offset(),
            Epoch::Data as u64
        );
        assert_eq!(paths.loss_resender.read_guard().len(), 1);
        mature.spaces.data.keys.update().unwrap();

        paths.progress.on_handshake_done(paths);
        assert!(mature.spaces.data.keys.update().is_err());
        assert_eq!(paths.spaces.read_guard().len(), 1);
        paths.retire_all();
        paths.progress.on_handshake_done(paths);
        assert!(paths.spaces.read_guard().is_empty());
        assert!(paths.loss_resender.read_guard().is_empty());
    }
}

#[tokio::test]
async fn progress_preserves_role_specific_crypto_and_key_retirement() {
    use futures::FutureExt;
    use qbase::{Epoch, role::Role};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for (role, mature) in [Role::Client, Role::Server]
        .into_iter()
        .zip(crate::common::spaces::pair())
    {
        let paths = &mature.paths;
        let initial = &mature.spaces.initial;
        let handshake = &mature.spaces.handshake;
        assert!(paths.progress.install_handshake(handshake.clone()));
        assert!(!paths.progress.install_handshake(handshake.clone()));
        assert!(paths.progress.facts().has_handshake_key());
        assert_eq!(paths.spaces.read_guard().len(), 2);
        assert_eq!(paths.loss_resender.read_guard().len(), 2);
        let mut buffer = [0; 1];
        assert!(initial.crypto.reader().read(&mut buffer).await.is_err());
        assert_eq!(
            initial.crypto.writer().write(&[]).await.is_err(),
            role == Role::Client
        );
        assert!(initial.keys.get().is_ok());
        assert!(handshake.keys.get().is_ok());

        paths.progress.on_tls_finished();
        paths.progress.on_tls_finished();
        let received = handshake.crypto.reader().read(&mut buffer).now_or_never();
        if role == Role::Client {
            assert!(received.unwrap().is_err());
            paths.progress.on_handshake_received();
        } else {
            assert!(received.is_none());
            paths.progress.on_handshake_sent();
        }
        assert_eq!(handshake.crypto.writer().write(&[]).await.unwrap(), 0);
        assert!(handshake.keys.get().is_ok());
        assert!(initial.keys.get().is_ok());

        if role == Role::Client {
            paths.progress.on_handshake_sent();
            paths.progress.on_handshake_sent();
        } else {
            paths.progress.on_handshake_received();
            paths.progress.on_handshake_received();
        }
        assert!(initial.keys.get().is_err());
        assert!(handshake.keys.get().is_ok());
        assert_eq!(paths.spaces.read_guard().offset(), Epoch::Handshake as u64);
        assert_eq!(
            paths.loss_resender.read_guard().offset(),
            Epoch::Handshake as u64
        );
        paths.progress.install_data(mature.spaces.data.clone());
        assert_eq!(paths.spaces.read_guard().len(), 2);
        assert_eq!(paths.loss_resender.read_guard().len(), 2);
        assert!(!paths.progress.facts().is_handshake_done());
        assert!(!paths.progress.install_handshake(handshake.clone()));
        assert_eq!(paths.spaces.read_guard().len(), 2);
        assert_eq!(paths.loss_resender.read_guard().len(), 2);
        paths.retire_all();
        paths.progress.on_tls_finished();
        paths.progress.on_handshake_done(paths);
        paths.clean();
        assert!(!paths.progress.facts().is_handshake_done());
        assert!(paths.spaces.read_guard().is_empty());
        assert!(paths.loss_resender.read_guard().is_empty());
    }
}

#[tokio::test]
async fn packet_events_retire_initial_from_both_queues() {
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
        let resender = paths.loss_resender.clone();
        let snapshot = spaces.read_guard().clone();
        if role == Role::Client {
            paths.progress.on_handshake_received();
        } else {
            paths.progress.on_handshake_sent();
        }
        assert!(space.keys.get().is_ok());
        if role == Role::Client {
            paths.progress.on_handshake_sent();
        } else {
            paths.progress.on_handshake_received();
        }
        assert!(space.keys.get().is_err());
        assert!(spaces.read_guard().is_empty());
        assert!(resender.read_guard().is_empty());
        assert_eq!(spaces.read_guard().offset(), Epoch::Handshake as u64);
        assert_eq!(resender.read_guard().offset(), Epoch::Handshake as u64);
        // A sender's older snapshot shares the permanently retired keys.
        assert!(
            snapshot
                .get(Epoch::Initial as u64)
                .unwrap()
                .pn_and_keys()
                .is_none()
        );
        paths.progress.on_handshake_sent();
        paths.progress.on_handshake_received();
        paths.progress.on_handshake_done(&paths);
        assert!(spaces.read_guard().is_empty());
        assert!(resender.read_guard().is_empty());
        assert_eq!(spaces.read_guard().offset(), Epoch::Handshake as u64);
        assert_eq!(resender.read_guard().offset(), Epoch::Handshake as u64);
        assert!(space.keys.get().is_err());
        let handshake = std::sync::Arc::new(qtransport::space::HandshakeSpace::new(
            Default::default(),
            qtransport::keys::ArcKeys::new(std::sync::Arc::new(crate::common::initial_keys(
                role == Role::Server,
            ))),
            paths.progress.facts(),
        ));
        assert!(paths.progress.install_handshake(handshake.clone()));
        paths.progress.on_handshake_sent();
        paths.progress.on_handshake_received();
        assert_eq!(spaces.read_guard().len(), 1);
        assert_eq!(resender.read_guard().len(), 1);
        assert_eq!(
            spaces.read_guard().front().unwrap().0,
            Epoch::Handshake as u64
        );
        assert_eq!(
            resender.read_guard().front().unwrap().0,
            Epoch::Handshake as u64
        );
        assert!(handshake.keys.get().is_ok());
        paths.retire_all();
        assert!(handshake.keys.get().is_err());
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
