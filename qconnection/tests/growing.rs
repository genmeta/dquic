use std::{sync::Arc, time::Duration};

use futures::FutureExt;
use qbase::{
    Epoch,
    error::ErrorKind,
    frame::{CryptoFrame, io::ReceiveFrame},
};
use qconnection::{Error, TlsContext};
use qtls::InstalledKeys;
use qtransport::space::Space;

mod common;
use common::backends;

fn pair(mutual: bool) -> [TlsContext; 2] {
    backends(mutual).map(|tls| TlsContext::new(tls, 256 * 1024).unwrap())
}

async fn flight(from: &TlsContext, to: &TlsContext, expected: Epoch) {
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
    assert!(client.read_server_parameters().now_or_never().is_none());
    flight(&client, &server, Epoch::Initial).await;
    // Neither output nor key consumption is required to retrieve ClientHello.
    assert!(server.read_server_parameters().now_or_never().is_none());
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
    flight(&server, &client, Epoch::Initial).await;
    assert!(matches!(
        client.read_keys().await.unwrap(),
        InstalledKeys::Handshake(_)
    ));
    assert!(client.read_server_parameters().now_or_never().is_none());
    flight(&server, &client, Epoch::Handshake).await;
    assert!(client.read_client_hello().now_or_never().is_none());
    client.read_server_parameters().await.unwrap();
    assert!(matches!(
        client.read_keys().await.unwrap(),
        InstalledKeys::OneRtt(_)
    ));
    assert_eq!(
        client.finished().await.unwrap().remote.unwrap().name(),
        "localhost"
    );
    flight(&client, &server, Epoch::Handshake).await;
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
    assert!(server.write_msg(Epoch::Handshake, &[1]).is_err());
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
async fn retiring_initial_reader_leaves_other_tls_input_alive() {
    let [client, server] = pair(false);
    let space = Space::new(Epoch::Initial, Default::default(), ());
    let crypto = &space.crypto;
    let (paths, closed) = common::paths(qbase::role::Role::Server);
    closed.register(Arc::new(space.crypto.clone()));
    closed.register(Arc::new(server.clone()));
    let reader = tokio::spawn(qconnection::tls::read_space_to_tls(
        server.clone(),
        &space,
        paths.clone(),
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
    assert!(closed.wait().now_or_never().is_none());
    assert!(matches!(
        server.read_keys().await.unwrap(),
        InstalledKeys::Handshake(_)
    ));
}

#[tokio::test(start_paused = true)]
async fn data_space_delivers_post_handshake_crypto_to_tls() {
    use std::sync::Arc;

    use bytes::Bytes;
    use qbase::{param::ArcParameters, role::Role, sid::handy::DemandConcurrency};
    use qrecovery::streams::DataStreams;
    use qtransport::{ArcReliableFrames, keys::ArcOneRttKeys, space::DataSpace};

    let [client, server] = pair(false);
    flight(&client, &server, Epoch::Initial).await;
    flight(&server, &client, Epoch::Initial).await;
    flight(&server, &client, Epoch::Handshake).await;
    flight(&client, &server, Epoch::Handshake).await;

    for (role, tls) in [(Role::Client, client), (Role::Server, server)] {
        tls.finished().await.unwrap();
        assert!(matches!(
            tls.read_keys().await.unwrap(),
            InstalledKeys::Handshake(_)
        ));
        let keys = ArcOneRttKeys::from(tls.read_keys().await.unwrap());
        let (client, server) = common::parameters();
        let parameters = ArcParameters::new(role, Arc::new(client), Arc::new(server));
        let reliable = ArcReliableFrames::with_capacity(0);
        let streams = DataStreams::new(
            parameters,
            Box::new(DemandConcurrency),
            reliable.clone(),
            None,
        );
        let space = DataSpace::new(Default::default(), keys, streams, reliable);
        let (paths, closed) = common::paths(role);
        closed.register(Arc::new(space.crypto.clone()));
        closed.register(Arc::new(tls.clone()));
        let reader = tokio::spawn(qconnection::tls::read_space_to_tls(
            tls.clone(),
            &space,
            paths.clone(),
        ));

        // TLS KeyUpdate is forbidden in QUIC: the Data input must reach the TLS backend.
        let bytes = Bytes::from_static(&[24, 0, 0, 1, 0]);
        space
            .crypto
            .incoming()
            .recv_frame((
                CryptoFrame::new(0u32.into(), (bytes.len() as u32).into()),
                bytes,
            ))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(4), async {
            let reason = closed.await;
            assert!(matches!(
                reason,
                Error::Quic(error) if matches!(error.kind(), ErrorKind::Crypto(_))
            ));
            reader.await.unwrap();
            assert!(tls.read_msg().await.is_err());
        })
        .await
        .unwrap();
    }
}
