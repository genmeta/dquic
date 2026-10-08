use std::{future::pending, time::Duration};

use qbase::{
    error::{ErrorKind, QuicError},
};

use crate::{CloseReason, lifecycle::any};

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
    closed.close(CloseReason::Internal(QuicError::with_default_fty(
        ErrorKind::ConnectionRefused,
        "connection closed while waiting",
    )), Duration::from_secs(1));

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

#[tokio::test]
async fn initial_crypto_receives_close_before_paths_are_created() {
    use std::task::Poll;

    use qbase::{cid::ConnectionId, role::Role};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let initial = crate::common::initial_phase(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        crate::common::initial_keys(false),
    );
    let mut reader = initial.initial_space.crypto.reader();
    let mut buffer = [0; 1];
    let read = reader.read(&mut buffer);
    tokio::pin!(read);
    assert!(futures::poll!(&mut read).is_pending());

    initial.terminator.close(
        CloseReason::Internal(QuicError::with_default_fty(
            ErrorKind::Internal,
            "closed before paths were created",
        )),
        Duration::from_secs(1),
    );
    assert!(matches!(futures::poll!(&mut read), Poll::Ready(Err(_))));
    assert!(
        initial
            .initial_space
            .crypto
            .writer()
            .write_all(b"after close")
            .await
            .is_err()
    );
}
