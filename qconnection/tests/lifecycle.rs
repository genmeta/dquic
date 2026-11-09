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
        CloseReason::Internal(QuicError::with_default_fty(ErrorKind::Internal, "closed before any path was added")),
        Duration::from_secs(1),
    );
    assert!(matches!(futures::poll!(&mut read), Poll::Ready(Err(_))));
    assert!(crate::common::initial_space(&paths.spaces).crypto.writer().write_all(b"after close").await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn address_observation_keeps_paths_alive_until_its_current_event_finishes() {
    use std::sync::{Arc, mpsc};

    use qbase::{cid::ConnectionId, role::Role};
    use qprotocol::AddressEvent;

    let paths = common::initial_paths(
        Role::Server,
        ConnectionId::from_slice(b"serverid"),
        ConnectionId::from_slice(b"original"),
        common::initial_keys(true),
    );
    let weak = Arc::downgrade(&paths);
    let local_cids = paths.cid_registry.local.clone();
    let initial = common::initial_space(&paths.spaces);
    let terminator = paths.terminator.clone();
    let (events, received) = tokio::sync::mpsc::unbounded_channel();
    let entered = Arc::new(tokio::sync::Notify::new());
    let notify = entered.clone();
    let (resume, blocked) = mpsc::channel();
    let observer = paths.puncher.observe_endpoints(
        received,
        {
            let paths = paths.clone();
            async move {
                paths.terminator.clone().await;
                drop(paths);
            }
        },
        move |_| {
            notify.notify_one();
            blocked.recv_timeout(Duration::from_secs(3)).unwrap();
        },
    );
    let bound = "127.0.0.1:45001".parse().unwrap();
    events.send(AddressEvent::Removed { bound, endpoint: bound.into() }).unwrap();
    tokio::time::timeout(Duration::from_secs(2), entered.notified()).await.unwrap();
    terminator.terminate();
    drop(paths);
    assert!(weak.upgrade().is_some(), "the current address event still owns the lifetime");
    assert!(local_cids.initial_scid().is_some());
    resume.send(()).unwrap();
    observer.await.unwrap();
    assert!(weak.upgrade().is_none());
    assert!(local_cids.initial_scid().is_none());
    assert!(initial.keys.get().is_err());
}
