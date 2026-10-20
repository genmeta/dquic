use std::time::Duration;

use qbase::error::{ErrorKind, QuicError};
use qconnection::CloseReason;

mod common;

#[tokio::test]
async fn initial_crypto_receives_close_before_any_path_is_added() {
    use std::task::Poll;

    use qbase::{cid::ConnectionId, role::Role};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let paths = crate::common::initial_paths(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        crate::common::initial_keys(false),
    );
    let mut reader = crate::common::initial_space(&paths.spaces).crypto.reader();
    let mut buffer = [0; 1];
    let read = reader.read(&mut buffer);
    tokio::pin!(read);
    assert!(futures::poll!(&mut read).is_pending());

    paths.terminator.close(
        CloseReason::Internal(QuicError::with_default_fty(
            ErrorKind::Internal,
            "closed before any path was added",
        )),
        Duration::from_secs(1),
    );
    assert!(matches!(futures::poll!(&mut read), Poll::Ready(Err(_))));
    assert!(
        crate::common::initial_space(&paths.spaces)
            .crypto
            .writer()
            .write_all(b"after close")
            .await
            .is_err()
    );
}
