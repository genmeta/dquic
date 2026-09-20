mod common;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    net::{addr::EndpointAddr, route::Pathway},
    time::ArcConnIdle,
    token::{ArcTokenRegistry, handy::NoopTokenRegistry},
};
use qconn::{
    ArcConnPhase, CloseReason, ConnPhase, InitialPhase, Paths, TlsContext, client_growing,
};
use qprotocol::QuicProtocol;
use qtransport::{packet::channel, router::QuicRouter};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
};

fn initial_keys(server: bool) -> qtls::BidirectionalKeys {
    let provider = qtls::default_provider();
    let suite = provider
        .cipher_suites
        .iter()
        .find_map(|s| {
            (s.suite() == tls_backend::CipherSuite::TLS13_AES_128_GCM_SHA256)
                .then(|| s.tls13().unwrap().quic_suite().unwrap())
        })
        .unwrap();
    suite
        .keys(
            b"original",
            if server {
                tls_backend::Side::Server
            } else {
                tls_backend::Side::Client
            },
            tls_backend::quic::Version::V1,
        )
        .into()
}

async fn route_exists(router: &QuicRouter, cid: ConnectionId) -> bool {
    use qbase::{
        net::route::Link,
        packet::{DataHeader, DataPacket, LongHeaderBuilder, Packet, long},
    };
    let link = Link::new(
        "127.0.0.1:30001".parse().unwrap(),
        "127.0.0.1:30002".parse().unwrap(),
    );
    let packet = Packet::Data(DataPacket {
        header: DataHeader::Long(long::DataHeader::Initial(
            LongHeaderBuilder::with_cid(cid, cid).initial(vec![]),
        )),
        bytes: BytesMut::new(),
        offset: 0,
    });
    let incoming = Arc::new(AtomicBool::new(false));
    let observed = incoming.clone();
    router.on_incoming(move |_, _, _| {
        observed.store(true, Ordering::Relaxed);
    });
    router.deliver(packet, link.into(), link);
    !incoming.load(Ordering::Relaxed)
}

#[tokio::test]
async fn dropping_old_client_route_preserves_replacement() {
    let router = Arc::new(QuicRouter::new());
    let cid = ConnectionId::random_gen(8);
    let (first_inbox, _) = channel::new();
    let first = router.insert(cid.into(), first_inbox);
    let (replacement_inbox, _) = channel::new();
    let replacement = router.insert(cid.into(), replacement_inbox);
    drop(first);
    assert!(route_exists(&router, cid).await);
    drop(replacement);
    assert!(!route_exists(&router, cid).await);
}

#[tokio::test(start_paused = true)]
async fn client_waits_for_keys_before_creating_handshake_space() {
    use futures::FutureExt;
    let cid = ConnectionId::random_gen(8);
    let phase = ArcConnPhase::new(InitialPhase::new(
        cid,
        ConnectionId::from_slice(b"original"),
        initial_keys(false),
    ));
    let (endpoint, _) = common::endpoints(false);
    let (parameters, _) = common::parameters();
    let tls = TlsContext::client(&endpoint, "localhost".try_into().unwrap(), &parameters).unwrap();
    let paths = Arc::new(Paths::new(phase.clone()));
    let idle = ArcConnIdle::new(Duration::from_secs(5), Duration::ZERO, Duration::ZERO);
    let (inbox, rcvd_pkt) = channel::new();
    let router = QuicRouter::global();
    let route = router.insert(cid.into(), inbox.clone());
    let ConnPhase::Initial(initial_phase) = phase.get() else {
        unreachable!()
    };
    let cid_registry =
        router.registry_on_issuing_scid(inbox, initial_phase.reliable_frames.clone());
    let growing = client_growing(
        phase.clone(),
        tls.clone(),
        parameters,
        cid_registry,
        rcvd_pkt,
        paths,
        idle,
        ArcTokenRegistry::with_sink("localhost".into(), Arc::new(NoopTokenRegistry)),
        |result| assert!(result.is_err()),
    );
    tokio::pin!(growing);
    assert!(growing.as_mut().now_or_never().is_none());
    let initial_only = matches!(phase.get(), ConnPhase::Initial(_));
    tls.on_error(
        qbase::error::QuicError::with_default_fty(
            qbase::error::ErrorKind::Internal,
            "stop before server hello",
        )
        .into(),
    );
    growing.await;
    assert!(!route_exists(QuicRouter::global(), cid).await);
    drop(route);
    assert!(tls.read_keys().await.is_err());
    assert!(
        initial_only,
        "Handshake space must wait for TLS Handshake keys"
    );
}

#[derive(Clone, Copy)]
enum ClientWait {
    ServerParameters,
    OneRttKeys,
    HandshakeDone,
}

async fn close_at_client_stage(wait: ClientWait) {
    use futures::FutureExt;
    use qbase::{
        frame::{CryptoFrame, io::ReceiveFrame},
        net::route::Link,
        packet::LongHeaderBuilder,
    };
    use qtls::CryptoLevel;
    use qtransport::{
        path::Path,
        send::{Burst, constraints::Constraints, records::ArcSendJournal},
        space::ArcFeedback,
    };

    let [tls, server_tls] =
        common::backends(false).map(|tls| TlsContext::new(tls, 256 * 1024).unwrap());
    let (level, hello) = tls.read_msg().await.unwrap();
    server_tls.write_msg(level, &hello).unwrap();
    let (level, hello) = server_tls.read_msg().await.unwrap();
    assert_eq!(level, CryptoLevel::Initial);
    let (_, flight) = server_tls.read_msg().await.unwrap();
    // EncryptedExtensions is enough to publish parameters, without authenticating the server.
    assert_eq!(flight[0], 8);
    let parameters_end = 4 + u32::from_be_bytes([0, flight[1], flight[2], flight[3]]) as usize;
    let cid = ConnectionId::random_gen(8);
    let phase = ArcConnPhase::new(InitialPhase::new(
        cid,
        ConnectionId::from_slice(b"original"),
        initial_keys(false),
    ));
    let paths = Arc::new(Paths::new(phase.clone()));
    let idle = ArcConnIdle::new(Duration::from_secs(5), Duration::ZERO, Duration::ZERO);
    let link = Link::new(
        "127.0.0.1:30001".parse().unwrap(),
        "127.0.0.1:30002".parse().unwrap(),
    );
    let pathway = Pathway::new(
        EndpointAddr::direct(link.src),
        EndpointAddr::direct(link.dst),
    );
    let path = Arc::new(Path::new(
        pathway,
        ConnectionId::from_slice(b"original"),
        Arc::new(qcongestion::HandshakeStatus::new(false)),
        Duration::from_millis(25),
        idle.timer(),
        std::array::from_fn(|_| Arc::new(ArcFeedback::default()) as Arc<dyn qcongestion::Feedback>),
    ));
    assert!(paths.insert(path.clone()));
    // Register a path without a sender. Growing must never start network output for it.
    let router = Arc::new(QuicRouter::new());
    let (inbox, rcvd_pkt) = channel::new();
    let route = router.insert(cid.into(), inbox.clone());
    let ConnPhase::Initial(initial_phase) = phase.get() else {
        unreachable!()
    };
    let cid_registry =
        router.registry_on_issuing_scid(inbox, initial_phase.reliable_frames.clone());
    let (delivered, mut delivery) = oneshot::channel();
    let (parameters, _) = common::parameters();
    let growing = tokio::spawn(client_growing(
        phase.clone(),
        tls.clone(),
        parameters,
        cid_registry,
        rcvd_pkt,
        paths.clone(),
        idle,
        ArcTokenRegistry::with_sink("localhost".into(), Arc::new(NoopTokenRegistry)),
        move |result| {
            let _ = delivered.send(result);
        },
    ));
    let mut burst = Burst::new(
        Arc::new(QuicProtocol::new()),
        pathway,
        path.cc.clone(),
        path.anti_amplifier.clone(),
        path.send_waker.clone(),
    );
    let hello_len = hello.len();
    let bytes = [hello];
    let mut crypto = (
        CryptoFrame::new(0u32.into(), (hello_len as u32).into()),
        bytes.as_slice(),
    );
    let packet = burst
        .assemble_initial_packet(
            &initial_keys(true).sealing,
            LongHeaderBuilder::with_cid(cid, ConnectionId::from_slice(b"server00")).initial(vec![]),
            &ArcSendJournal::default(),
            &Constraints {
                capacity: 1200,
                congestion: 1200,
                anti_amplification: 1200,
            },
            [&mut crypto],
        )
        .unwrap()
        .unwrap();
    router.receive(BytesMut::from(packet.bytes()), pathway, link, 8);
    let handshake = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let ConnPhase::Connecting(connecting) = phase.get() {
                break connecting.handshake.clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        delivery.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(
        phase
            .get()
            .initial()
            .crypto
            .writer()
            .write(&[])
            .await
            .is_err()
    );
    assert!(matches!(
        handshake.crypto.writer().write(&[]).now_or_never(),
        Some(Ok(0))
    ));

    if !matches!(wait, ClientWait::ServerParameters) {
        handshake
            .crypto
            .incoming()
            .recv_frame((
                CryptoFrame::new(0u32.into(), (parameters_end as u32).into()),
                flight.slice(..parameters_end),
            ))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !matches!(phase.get(), ConnPhase::Handshaking(_)) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let ConnPhase::Handshaking(material) = phase.get() else {
            unreachable!()
        };
        assert!(material.spaces.data.keys.try_get().unwrap().is_none());
        assert!(matches!(
            delivery.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }
    let mut connection = None;
    if matches!(wait, ClientWait::HandshakeDone) {
        handshake
            .crypto
            .incoming()
            .recv_frame((
                CryptoFrame::new(
                    (parameters_end as u32).into(),
                    ((flight.len() - parameters_end) as u32).into(),
                ),
                flight.slice(parameters_end..),
            ))
            .unwrap();
        let (_, remote, connected) = (&mut delivery).await.unwrap().unwrap();
        connection = Some(connected);
        assert_eq!(remote.name(), "localhost");
        assert!(matches!(phase.get(), ConnPhase::Handshaking(_)));
        assert!(matches!(
            handshake.crypto.reader().read(&mut [0; 1]).now_or_never(),
            Some(Err(_))
        ));
        assert!(matches!(
            handshake.crypto.writer().write(&[]).now_or_never(),
            Some(Ok(0))
        ));
    }
    tls.on_error(
        qbase::error::QuicError::with_default_fty(
            qbase::error::ErrorKind::Internal,
            "stop at TLS stage",
        )
        .into(),
    );
    assert!(matches!(growing.await.unwrap(), CloseReason::Internal(_)));
    if !matches!(wait, ClientWait::HandshakeDone) {
        assert!(delivery.await.unwrap().is_err());
    }
    assert!(tls.read_keys().await.is_err());
    assert!(handshake.keys.try_get().is_err());
    assert!(handshake.crypto.writer().write(&[]).await.is_err());
    assert!(paths.snapshot().is_empty());
    assert!(!route_exists(&router, cid).await);
    drop(route);
    drop(connection);
}

#[tokio::test(start_paused = true)]
async fn client_closes_while_waiting_for_server_parameters() {
    close_at_client_stage(ClientWait::ServerParameters).await;
}

#[tokio::test(start_paused = true)]
async fn client_closes_while_waiting_for_one_rtt_keys() {
    close_at_client_stage(ClientWait::OneRttKeys).await;
}

#[tokio::test(start_paused = true)]
async fn client_keeps_finished_until_handshake_done_or_close() {
    close_at_client_stage(ClientWait::HandshakeDone).await;
}
