mod support {
    pub mod data;
    pub mod tls;
}
use std::sync::Arc;

use bytes::Bytes;
use qbase::error::AppError;
use qtransport::{ArcConnection, Error, terminate::ArcTerminator};

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
