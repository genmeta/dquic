use std::{future::pending, time::Duration};

use qbase::{
    ArcReceiving,
    error::{ErrorKind, QuicError},
};

use crate::{CloseReason, lifecycle::any};

#[tokio::test]
async fn any_preserves_future_output() {
    let value = String::from("ready");
    let closed = ArcReceiving::default();
    assert_eq!(any(async { &value }, closed.clone()).await.unwrap(), &value);
    assert_eq!(
        any(async { Err::<(), _>("failed") }, closed).await.unwrap(),
        Err("failed"),
    );
}

#[tokio::test]
async fn any_close_interrupts_a_pending_future() {
    let closed = ArcReceiving::default();
    let waiting = tokio::spawn(any(pending::<()>(), closed.clone()));
    tokio::task::yield_now().await;
    closed.set(CloseReason::Internal(QuicError::with_default_fty(
        ErrorKind::ConnectionRefused,
        "connection closed while waiting",
    )));

    let reason = tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(reason, CloseReason::Internal(error)
        if error.kind() == ErrorKind::ConnectionRefused
            && error.reason() == "connection closed while waiting"));
}
