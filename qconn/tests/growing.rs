use std::time::Duration;

use futures::FutureExt;
use qbase::{
    ArcReceiving,
    error::{ErrorKind, QuicError},
    frame::{CryptoFrame, io::ReceiveFrame},
};
use qconn::{CloseReason, TlsContext};
use qrecovery::crypto::CryptoStream;
use qtls::{CryptoLevel, InstalledKeys};

mod common;
use common::backends;

fn pair(mutual: bool) -> [TlsContext; 2] {
    backends(mutual).map(|tls| TlsContext::new(tls, 256 * 1024).unwrap())
}

async fn flight(from: &TlsContext, to: &TlsContext, expected: CryptoLevel) {
    let (level, bytes) = tokio::time::timeout(Duration::from_secs(2), from.read_msg())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(level, expected);
    to.write_msg(level, &bytes).unwrap();
}

#[tokio::test]
async fn tls_output_keys_and_parameters_have_independent_consumers() {
    let [client, server] = pair(false);
    assert!(client.read_keys().now_or_never().is_none()); // cancel this pending wait
    assert!(client.read_server_hello().now_or_never().is_none());
    flight(&client, &server, CryptoLevel::Initial).await;
    // Neither output nor key consumption is required to retrieve ClientHello.
    let (name, _) = server.read_client_hello().await.unwrap();
    assert_eq!(name.as_deref(), Some("localhost"));
    assert!(matches!(
        server.read_keys().await.unwrap(),
        InstalledKeys::Handshake(_)
    ));
    assert!(matches!(
        server.read_keys().await.unwrap(),
        InstalledKeys::OneRtt(_)
    ));
    assert!(server.finished().now_or_never().is_none());
    flight(&server, &client, CryptoLevel::Initial).await;
    assert!(matches!(
        client.read_keys().await.unwrap(),
        InstalledKeys::Handshake(_)
    ));
    assert!(client.read_server_hello().now_or_never().is_none());
    flight(&server, &client, CryptoLevel::Handshake).await;
    client.read_server_hello().await.unwrap();
    assert!(matches!(
        client.read_keys().await.unwrap(),
        InstalledKeys::OneRtt(_)
    ));
    assert_eq!(
        client.finished().await.unwrap().remote.unwrap().name(),
        "localhost"
    );
    flight(&client, &server, CryptoLevel::Handshake).await;
    assert!(server.finished().await.unwrap().remote.is_none());
}

#[tokio::test]
async fn tls_error_wakes_each_independent_waiter() {
    let [_, server] = pair(false);
    let msg = tokio::spawn({
        let tls = server.clone();
        async move { tls.read_msg().await.is_err() }
    });
    let keys = tokio::spawn({
        let tls = server.clone();
        async move { tls.read_keys().await.is_err() }
    });
    let hello = tokio::spawn({
        let tls = server.clone();
        async move { tls.read_client_hello().await.is_err() }
    });
    let done = tokio::spawn({
        let tls = server.clone();
        async move { tls.finished().await.is_err() }
    });
    tokio::task::yield_now().await;
    // Actual backend input failure, not a fabricated completion event.
    assert!(server.write_msg(CryptoLevel::Handshake, &[1]).is_err());
    tokio::time::timeout(Duration::from_secs(2), async {
        assert!(msg.await.unwrap());
        assert!(keys.await.unwrap());
        assert!(hello.await.unwrap());
        assert!(done.await.unwrap());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn queued_output_is_bounded_without_waiting_for_its_reader() {
    let [client, server] = backends(false);
    assert!(
        matches!(TlsContext::new(client, 0), Err(error) if error.kind() == ErrorKind::CryptoBufferExceeded)
    );
    let server = TlsContext::new(server, 0).unwrap();
    let [client, _] = pair(false);
    let (level, bytes) = client.read_msg().await.unwrap();
    assert!(
        matches!(server.write_msg(level, &bytes), Err(error) if error.kind() == ErrorKind::CryptoBufferExceeded)
    );
    assert!(server.read_keys().await.is_err());
}

#[tokio::test]
async fn tls_io_exits_naturally_when_the_context_fails() {
    let [_, server] = pair(false);
    let crypto = std::array::from_fn(|_| CryptoStream::new(Default::default()));
    let closed = ArcReceiving::default();
    let reads = [
        CryptoLevel::Initial,
        CryptoLevel::Handshake,
        CryptoLevel::OneRtt,
    ]
    .into_iter()
    .zip(crypto.iter())
    .map(|(level, stream)| {
        tokio::spawn(qconn::tls::read_crypto_stream_to_tls(
            server.clone(),
            level,
            stream.clone(),
            closed.clone(),
        ))
    })
    .collect::<Vec<_>>();
    let write = tokio::spawn(qconn::tls::write_crypto(server.clone(), crypto, closed));
    tokio::task::yield_now().await;
    server.on_error(QuicError::with_default_fty(ErrorKind::Internal, "connection ended").into());
    tokio::time::timeout(Duration::from_secs(2), async {
        write.await.unwrap();
        for read in reads {
            read.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn retiring_initial_reader_leaves_other_tls_input_alive() {
    let [client, server] = pair(false);
    let crypto = CryptoStream::new(Default::default());
    let closed = ArcReceiving::default();
    let reader = tokio::spawn(qconn::tls::read_crypto_stream_to_tls(
        server.clone(),
        CryptoLevel::Initial,
        crypto.clone(),
        closed.clone(),
    ));
    let (_, bytes) = client.read_msg().await.unwrap();
    crypto
        .incoming()
        .recv_frame((
            CryptoFrame::new(0u32.into(), (bytes.len() as u32).into()),
            bytes,
        ))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), server.read_client_hello())
        .await
        .unwrap()
        .unwrap();
    crypto.recver.retire();
    tokio::time::timeout(Duration::from_secs(2), reader)
        .await
        .unwrap()
        .unwrap();
    assert!(closed.clone().now_or_never().is_none());
    assert!(matches!(
        server.read_keys().await.unwrap(),
        InstalledKeys::Handshake(_)
    ));
}

#[tokio::test]
async fn crypto_output_failure_stops_tls_and_all_input_tasks() {
    let [client, _] = pair(false);
    let crypto: [CryptoStream; 3] = std::array::from_fn(|_| CryptoStream::new(Default::default()));
    let closed = ArcReceiving::default();
    // ClientHello is still pending, but its destination can no longer accept it.
    crypto[0].sender.retire();
    let reads = [
        CryptoLevel::Initial,
        CryptoLevel::Handshake,
        CryptoLevel::OneRtt,
    ]
    .into_iter()
    .zip(crypto.iter())
    .map(|(level, stream)| {
        tokio::spawn(qconn::tls::read_crypto_stream_to_tls(
            client.clone(),
            level,
            stream.clone(),
            closed.clone(),
        ))
    })
    .collect::<Vec<_>>();
    let writer = tokio::spawn(qconn::tls::write_crypto(
        client.clone(),
        crypto,
        closed.clone(),
    ));
    tokio::time::timeout(Duration::from_millis(200), async {
        assert!(matches!(
            closed.await.unwrap().unwrap(),
            CloseReason::Internal(_)
        ));
        writer.await.unwrap();
        for reader in reads {
            reader.await.unwrap();
        }
        assert!(client.read_keys().await.is_err());
    })
    .await
    .unwrap();
}
