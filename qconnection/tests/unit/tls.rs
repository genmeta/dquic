use std::time::Duration;

use qbase::{
    Close, Epoch,
    error::{ErrorKind, QuicError},
};
use qtransport::space::Space;

use crate::{
    TlsContext, common,
    tls::{read_space_to_tls, read_tls_to_space},
};

#[tokio::test]
async fn closed_tls_ignores_input_and_preserves_the_close_reason() {
    let errors: [crate::Error; 3] = [
        QuicError::with_default_fty(ErrorKind::None, "closed").into(),
        QuicError::with_default_fty(ErrorKind::Internal, "failed").into(),
        qbase::error::AppError::new(42u32.into(), "application closed").into(),
    ];
    for error in errors {
        let [_, server] =
            common::backends(false).map(|tls| TlsContext::new(tls, 256 * 1024).unwrap());
        server.close_with_error(error.clone());
        for epoch in Epoch::EPOCHS {
            server.write_msg(epoch, &[1]).unwrap();
            assert_eq!(server.read_msg_at(epoch).await.unwrap_err(), error);
            assert_eq!(server.try_read_msg_at(epoch).unwrap_err(), error);
        }
        assert_eq!(server.read_msg().await.unwrap_err(), error);
        assert_eq!(server.read_keys().await.err(), Some(error.clone()));
        assert_eq!(server.finished().await.err(), Some(error));
    }
}

#[tokio::test(start_paused = true)]
async fn tls_io_exits_naturally_when_the_context_fails() {
    let [_, server] = common::backends(false).map(|tls| TlsContext::new(tls, 256 * 1024).unwrap());
    let spaces = Epoch::EPOCHS.map(|epoch| Space::new(epoch, Default::default(), ()));
    let (paths, closed) = common::paths(qbase::role::Role::Server);
    for space in &spaces {
        closed.register(std::sync::Arc::new(space.crypto.clone()));
    }
    closed.register(std::sync::Arc::new(server.clone()));
    let reads = spaces
        .iter()
        .map(|space| tokio::spawn(read_space_to_tls(server.clone(), space, paths.clone())))
        .collect::<Vec<_>>();
    let writes = spaces
        .iter()
        .map(|space| tokio::spawn(read_tls_to_space(server.clone(), space, paths.clone())))
        .collect::<Vec<_>>();
    tokio::task::yield_now().await;
    server.on_error(QuicError::with_default_fty(ErrorKind::Internal, "connection ended").into());
    tokio::task::yield_now().await;
    assert!(common::observe_close(&closed).notified().is_some());
    assert!(writes.iter().all(|write| !write.is_finished()));
    tokio::time::timeout(Duration::from_secs(4), async {
        for write in writes {
            write.await.unwrap();
        }
        for read in reads {
            read.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn crypto_output_failure_stops_tls_and_all_input_tasks() {
    let [client, _] = common::backends(false).map(|tls| TlsContext::new(tls, 256 * 1024).unwrap());
    let spaces = Epoch::EPOCHS.map(|epoch| Space::new(epoch, Default::default(), ()));
    let (paths, closed) = common::paths(qbase::role::Role::Client);
    for space in &spaces {
        closed.register(std::sync::Arc::new(space.crypto.clone()));
    }
    // ClientHello is still pending, but its destination can no longer accept it.
    spaces[Epoch::Initial].crypto.sender.retire();
    closed.register(std::sync::Arc::new(client.clone()));
    let reads = spaces
        .iter()
        .map(|space| tokio::spawn(read_space_to_tls(client.clone(), space, paths.clone())))
        .collect::<Vec<_>>();
    let writes = spaces
        .iter()
        .map(|space| tokio::spawn(read_tls_to_space(client.clone(), space, paths.clone())))
        .collect::<Vec<_>>();
    tokio::time::timeout(Duration::from_secs(4), async {
        assert!(matches!(closed.await, crate::Error::Quic(_)));
        for write in writes {
            write.await.unwrap();
        }
        for reader in reads {
            reader.await.unwrap();
        }
        assert!(client.read_keys().await.is_err());
    })
    .await
    .unwrap();
}
