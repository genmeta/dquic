mod support {
    pub mod data;
    pub mod tls;
}
use std::sync::Arc;

use bytes::Bytes;
use qbase::error::AppError;
use qtransport::{ArcConnection, Error, terminate::ArcTerminator};

#[tokio::test(start_paused = true)]
async fn borrowed_path_observer_tracks_validation_and_closes_with_the_largest_pto() {
    use std::time::Duration;

    use qbase::{Epoch, net::route::Pathway, time::heartbeat::ArcHeartbeat};
    use qcongestion::HandshakeStatus;
    use qtransport::path::{Path, PathCids};
    use tokio::time::Instant;

    let cids = PathCids::new(Default::default());
    let paths = Arc::new([4401, 4402, 4403].map(|port| {
        Arc::new(Path::new(
            Pathway::new(
                "127.0.0.1:4400".parse().unwrap(),
                format!("127.0.0.1:{port}").parse().unwrap(),
            ),
            Arc::new(HandshakeStatus::new(false)),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            Default::default(),
            &cids,
        ))
    }));
    paths[0].validation.enter_validated().unwrap();
    paths[1]
        .cc
        .set_ack_delays(Duration::ZERO, Duration::from_millis(100));
    paths[2].validation.enter_validated().unwrap();
    paths[2].close();
    let largest = paths[1].cc.pto_base(Epoch::Data);
    assert!(largest > paths[0].cc.pto_base(Epoch::Data));

    let data = support::data::data();
    let terminator = ArcTerminator::no_error();
    let connection = ArcConnection::new(Bytes::new(), data.streams.clone(), terminator.clone())
        .with_path_observer({
            let paths = Arc::downgrade(&paths);
            move |visit| {
                if let Some(paths) = paths.upgrade() {
                    for path in paths.iter() {
                        visit(path);
                    }
                }
            }
        });
    assert_eq!(connection.validated_paths(), [paths[0].pathway]);
    let start = Instant::now();
    connection
        .clone()
        .close(42u32.into(), "close with live paths");
    assert!(matches!(terminator.await, Error::App(error) if error.error_code() == 42));
    assert_eq!(Instant::now() - start, largest * 3);

    paths[1].validation.enter_validated().unwrap();
    assert_eq!(
        connection.validated_paths(),
        [paths[0].pathway, paths[1].pathway]
    );
    paths[0].close();
    assert_eq!(connection.validated_paths(), [paths[1].pathway]);
    let path = Arc::downgrade(&paths[1]);
    drop(paths);
    assert!(path.upgrade().is_none());
    assert!(connection.validated_paths().is_empty());
}

#[tokio::test(start_paused = true)]
async fn connection_keeps_streams_alive_without_retaining_the_data_space() {
    use tokio::io::AsyncWriteExt;

    let space = support::data::data();
    let terminator = ArcTerminator::no_error();
    terminator.register(Arc::new(space.streams.clone()));
    let connection = ArcConnection::new(
        Bytes::from_static(b"h3"),
        space.streams.clone(),
        terminator.clone(),
    );
    let data = Arc::downgrade(&space);
    drop(space);
    assert!(data.upgrade().is_none());

    let (_, mut writer) = connection.open_uni_stream().await.unwrap().unwrap();
    writer.write_all(b"pending").await.unwrap();
    let close = terminator;
    connection.close(42u32.into(), "stop");
    assert!(writer.flush().await.is_err());
    assert!(matches!(
        close.await,
        Error::App(error) if error == AppError::new(42u32.into(), "stop")
    ));
}

#[tokio::test(start_paused = true)]
async fn explicit_close_wakes_the_driver_and_preserves_the_first_reason() {
    let data = support::data::data();
    let terminator = ArcTerminator::no_error();
    terminator.register(Arc::new(data.streams.clone()));
    let connection = ArcConnection::new(
        Bytes::from_static(b"h3"),
        data.streams.clone(),
        terminator.clone(),
    );
    let close = terminator;
    assert!(futures::poll!(std::pin::pin!(close.wait())).is_pending());
    connection.clone().close(42u32.into(), "first");
    connection.close(99u32.into(), "later");
    let Error::App(error) = close.clone().await else {
        panic!("expected application close");
    };
    assert_eq!(error, AppError::new(42u32.into(), "first"));
    assert_eq!(close.await, Error::App(error));
}

#[tokio::test(start_paused = true)]
async fn only_the_last_handle_drop_notifies_the_driver() {
    let data = support::data::data();
    let terminator = ArcTerminator::no_error();
    terminator.register(Arc::new(data.streams.clone()));
    let connection = ArcConnection::new(
        Bytes::from_static(b"h3"),
        data.streams.clone(),
        terminator.clone(),
    );
    let close = terminator;
    drop(connection.clone());
    assert!(futures::poll!(std::pin::pin!(close.wait())).is_pending());
    drop(connection);
    let Error::App(error) = close.await else {
        panic!("expected application close");
    };
    assert_eq!(error.error_code(), 0);
    assert_eq!(error.reason(), "last connection handle dropped");
}
