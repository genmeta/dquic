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
    role::Role,
    token::{ArcTokenRegistry, handy::NoopTokenRegistry},
};
use qconnection::{
    ArcConnPhase, ConnPhase, Error, InitialPhase, Paths, TlsContext, client_growing,
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
    common::use_system_resolver();
    use futures::FutureExt;
    let cid = ConnectionId::random_gen(8);
    let router = QuicRouter::global().clone();
    let (inbox, rcvd_pkt) = channel::new();
    let route = router.insert(cid.into(), inbox.clone());
    let (parameters, _) = common::parameters();
    let reliable_frames = qconnection::ArcReliableFrames::with_capacity(0);
    let cid_registry = qconnection::CidRegistry::new(
        Role::Client,
        ConnectionId::from_slice(b"original"),
        qconnection::ArcLocalCids::new(
            cid,
            router.registry_on_issuing_scid(inbox, reliable_frames.clone()),
        ),
        qbase::cid::ArcRemoteCids::new(
            parameters.get::<u64>(qbase::param::ParameterId::ActiveConnectionIdLimit),
            reliable_frames.clone(),
        ),
    );
    let phase = ArcConnPhase::initial(InitialPhase::new(
        (cid, ConnectionId::from_slice(b"original")),
        initial_keys(false),
        reliable_frames,
        cid_registry,
    ));
    let (endpoint, _) = common::endpoints(false);
    let tls = TlsContext::client(&endpoint, "localhost".try_into().unwrap(), &parameters).unwrap();
    let paths = Paths::new(
        Role::Client,
        phase.clone(),
        Duration::from_secs(5),
        Duration::ZERO,
    );
    let tick = qconnection::recv::tick(paths.clone());
    let growing = client_growing(
        "localhost".into(),
        parameters,
        paths,
        rcvd_pkt,
        tls.clone(),
        ArcTokenRegistry::with_sink("localhost".into(), Arc::new(NoopTokenRegistry)),
        |result| assert!(result.is_err()),
    );
    let growing = async move { tokio::join!(growing, tick).0 };
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
    ServerCidMismatch,
}

async fn close_at_client_stage(wait: ClientWait) {
    common::use_system_resolver();
    use futures::FutureExt;
    use qbase::{
        Epoch,
        frame::{CryptoFrame, io::ReceiveFrame},
        net::route::Link,
        packet::LongHeaderBuilder,
    };
    use qrecovery::journal::ArcSentJournal;

    let [tls, server_tls] =
        common::backends(false).map(|tls| TlsContext::new(tls, 256 * 1024).unwrap());
    let (level, hello) = tls.read_msg().await.unwrap();
    server_tls.write_msg(level, &hello).unwrap();
    let (level, hello) = server_tls.read_msg().await.unwrap();
    assert_eq!(level, Epoch::Initial);
    let (_, flight) = server_tls.read_msg().await.unwrap();
    // EncryptedExtensions is enough to publish parameters, without authenticating the server.
    assert_eq!(flight[0], 8);
    let parameters_end = 4 + u32::from_be_bytes([0, flight[1], flight[2], flight[3]]) as usize;
    let cid = ConnectionId::random_gen(8);
    let router = Arc::new(QuicRouter::new());
    let (inbox, rcvd_pkt) = channel::new();
    let route = router.insert(cid.into(), inbox.clone());
    let (parameters, _) = common::parameters();
    let reliable_frames = qconnection::ArcReliableFrames::with_capacity(0);
    let cid_registry = qconnection::CidRegistry::new(
        Role::Client,
        ConnectionId::from_slice(b"original"),
        qconnection::ArcLocalCids::new(
            cid,
            router.registry_on_issuing_scid(inbox, reliable_frames.clone()),
        ),
        qbase::cid::ArcRemoteCids::new(
            parameters.get::<u64>(qbase::param::ParameterId::ActiveConnectionIdLimit),
            reliable_frames.clone(),
        ),
    );
    let phase = ArcConnPhase::initial(InitialPhase::new(
        (cid, ConnectionId::from_slice(b"original")),
        initial_keys(false),
        reliable_frames,
        cid_registry,
    ));
    let paths = Paths::new(
        Role::Client,
        phase.clone(),
        Duration::from_secs(5),
        Duration::ZERO,
    );
    let socket = Arc::new(qprotocol::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let local = EndpointAddr::direct(socket.local_addr().unwrap());
    QuicProtocol::global().register(local, &socket).unwrap();
    let link = Link::new(
        socket.local_addr().unwrap(),
        "127.0.0.1:30002".parse().unwrap(),
    );
    let pathway = Pathway::new(
        EndpointAddr::direct(link.src),
        EndpointAddr::direct(link.dst),
    );
    paths.add_path(pathway);
    let (delivered, mut delivery) = oneshot::channel();
    let tick = qconnection::recv::tick(paths.clone());
    let growing = client_growing(
        "localhost".into(),
        parameters,
        paths.clone(),
        rcvd_pkt,
        tls.clone(),
        ArcTokenRegistry::with_sink("localhost".into(), Arc::new(NoopTokenRegistry)),
        move |result| {
            let _ = delivered.send(result);
        },
    );
    let growing = tokio::spawn(async move { tokio::join!(growing, tick).0 });
    let hello_len = hello.len();
    let bytes = [hello];
    let mut crypto = (
        CryptoFrame::new(0u32.into(), (hello_len as u32).into()),
        bytes.as_slice(),
    );
    let server_scid = if matches!(wait, ClientWait::ServerCidMismatch) {
        b"wrongcid"
    } else {
        b"server00"
    };
    let packet = common::seal(
        LongHeaderBuilder::with_cid(cid, ConnectionId::from_slice(server_scid)).initial(vec![]),
        &initial_keys(true).sealing,
        &ArcSentJournal::default(),
        [&mut crypto],
    )
    .unwrap();
    router.receive(BytesMut::from(packet.as_ref()), pathway, link, 8);
    let handshake = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let ConnPhase::Handshake(connecting) = phase.get() {
                break connecting.handshake_space.clone();
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
    let initial = match phase.get() {
        ConnPhase::Initial(phase) => phase.initial_space.clone(),
        ConnPhase::Handshake(phase) => phase.initial_space.clone(),
        ConnPhase::Mature(phase) => phase.spaces.initial.clone(),
    };
    assert!(initial.crypto.writer().write(&[]).await.is_err());
    assert!(matches!(
        handshake.crypto.writer().write(&[]).now_or_never(),
        Some(Ok(0))
    ));

    if !matches!(wait, ClientWait::ServerParameters) {
        let end = if matches!(wait, ClientWait::ServerCidMismatch) {
            flight.len()
        } else {
            parameters_end
        };
        handshake
            .crypto
            .incoming()
            .recv_frame((
                CryptoFrame::new(0u32.into(), (end as u32).into()),
                flight.slice(..end),
            ))
            .unwrap();
        if matches!(wait, ClientWait::ServerCidMismatch) {
            let result = tokio::time::timeout(Duration::from_secs(1), delivery)
                .await
                .unwrap()
                .unwrap();
            let error = result
                .err()
                .expect("growing must reject a CID different from the Initial header");
            assert_eq!(error.kind(), qbase::error::ErrorKind::TransportParameter);
            assert!(
                matches!(growing.await.unwrap(), Error::Quic(error)
                if error.kind() == qbase::error::ErrorKind::TransportParameter)
            );
            assert!(matches!(phase.get(), ConnPhase::Handshake(_)));
            assert!(paths.snapshot().is_empty());
            assert!(!route_exists(&router, cid).await);
            QuicProtocol::global().unregister(socket.local_addr().unwrap());
            drop(route);
            return;
        }
        tokio::task::yield_now().await;
        assert!(matches!(phase.get(), ConnPhase::Handshake(_)));
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
        let ConnPhase::Mature(material) = phase.get() else {
            panic!()
        };
        assert!(material.spaces.data.keys.get().is_ok());
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
    assert!(matches!(growing.await.unwrap(), Error::Quic(_)));
    if !matches!(wait, ClientWait::HandshakeDone) {
        assert!(delivery.await.unwrap().is_err());
    }
    assert!(tls.read_keys().await.is_err());
    assert!(handshake.keys.get().is_err());
    assert!(handshake.crypto.writer().write(&[]).await.is_err());
    assert!(paths.snapshot().is_empty());
    assert!(!route_exists(&router, cid).await);
    QuicProtocol::global().unregister(socket.local_addr().unwrap());
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

#[tokio::test(start_paused = true)]
async fn client_rejects_server_parameters_with_a_different_initial_scid() {
    close_at_client_stage(ClientWait::ServerCidMismatch).await;
}
