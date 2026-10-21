use std::{
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::BytesMut;
use futures::FutureExt;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    frame::{Frame, FrameReader, GuaranteedFrame},
    net::{addr::EndpointAddr, route::Pathway},
    packet::{DataHeader, LongHeaderBuilder, Packet as ParsedPacket, PacketReader, long},
    param::ParameterId,
    role::Role,
    time::heartbeat::ArcHeartbeat,
};
use qcongestion::Transport as _;
use qtransport::{keys::ArcKeys, packet::CipherPacket, path::Path, space::HandshakeSpace};
use tokio::io::AsyncWriteExt;

use crate::{
    ConnPhase, MaturePhase, Paths,
    common::initial_keys as keys,
    send::{Burst, BurstPackets, MAX_BURST_PACKETS, sending, task},
};

async fn collect(mut burst: Burst<'_, '_>) -> Result<usize, crate::Error> {
    burst.collect().await
}

#[tokio::test(start_paused = true)]
async fn retired_initial_is_discarded_before_polling_an_expired_pto() {
    let paths = crate::common::initial_paths(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let trackers = paths.resender.clone();
    super::enter_handshake(
        &paths,
        Arc::new(HandshakeSpace::new(
            Default::default(),
            ArcKeys::new(Arc::new(keys(false))),
        )),
    );
    let path = Arc::new(Path::new(
        Pathway::new(
            "127.0.0.1:4400".parse::<EndpointAddr>().unwrap(),
            "127.0.0.1:5500".parse().unwrap(),
        ),
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        trackers.clone(),
        &paths.cids,
    ));
    path.client_handshaking();
    paths.cids.select(&path.cid);
    path.cc
        .on_pkt_sent(Epoch::Initial, 0, true, 1200, true, None);
    paths.on_handshake_sent();
    // Initial remains queued until growing cleans up; retired keys must already stop assembly.
    assert_eq!(paths.spaces.read_guard().offset(), 0);
    tokio::time::advance(Duration::from_secs(10)).await;
    let mut datagrams =
        std::array::from_fn::<_, MAX_BURST_PACKETS, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::new();
    let mut pns: BurstPackets = [[None; 3]; MAX_BURST_PACKETS];
    let mut collect = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut pns);
    assert!(
        collect
            .poll_collect(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Initial), 0);
    // While waiting for HANDSHAKE_DONE, an anti-deadlock probe must use live Handshake keys.
    tokio::time::advance(path.cc.pto_base(Epoch::Handshake)).await;
    path.cc.do_tick().unwrap();
    assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Initial), 0);
    assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Handshake), 1);
    assert!(matches!(
        collect.poll_collect(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(1))
    ));
    assert_eq!(pns_for(collect.packets, Epoch::Handshake).count(), 1);
}

#[tokio::test]
async fn collector_mixes_spaces_and_selected_crypto_advances() {
    let paths = crate::common::initial_paths(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let message = vec![42; 7200];
    crate::common::initial_space(&paths.spaces)
        .crypto
        .writer()
        .write_all(&message)
        .await
        .unwrap();
    let handshake = Arc::new(HandshakeSpace::new(
        Default::default(),
        ArcKeys::new(Arc::new(keys(false))),
    ));
    handshake
        .crypto
        .writer()
        .write_all(b"handshake")
        .await
        .unwrap();
    crate::common::initial_space(&paths.spaces)
        .rcvd_journal
        .on_rcvd_pn(3, true, Duration::from_secs(1));
    handshake
        .rcvd_journal
        .on_rcvd_pn(7, true, Duration::from_secs(1));
    let trackers = paths.resender.clone();
    super::enter_handshake(&paths, handshake);
    let pathway = Pathway::new(
        EndpointAddr::direct("127.0.0.1:31001".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:31002".parse().unwrap()),
    );
    let path = Arc::new(Path::new(
        pathway,
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        trackers.clone(),
        &paths.cids,
    ));
    path.client_handshaking();
    paths.cids.select(&path.cid);

    path.cc.on_pkt_rcvd(Epoch::Initial, 3, true);
    path.cc.on_pkt_rcvd(Epoch::Handshake, 7, true);
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::new();
    let mut pns = [[None; 3]; MAX_BURST_PACKETS];
    let count = collect(Burst::new(
        &paths,
        &path,
        &mut datagrams,
        &mut frames,
        &mut pns,
    ))
    .now_or_never()
    .unwrap()
    .unwrap();
    assert_eq!(count, 7);
    assert!(!pns_for(&pns, Epoch::Initial).next().is_none());
    assert_eq!(pns_for(&pns, Epoch::Handshake).count(), 1);
    for (epoch, largest) in [(Epoch::Initial, 3), (Epoch::Handshake, 7)] {
        assert_eq!(
            pns.iter()
                .filter_map(|slots| slots[epoch].and_then(|meta| meta.ack))
                .collect::<Vec<_>>(),
            [largest],
            "each space sends its ACK only once per burst"
        );
    }
    assert!(frames.is_empty());
    let mut recovered = Vec::new();
    for (index, pn) in pns_for(&pns, Epoch::Initial) {
        let ParsedPacket::Data(parsed) = PacketReader::new(datagrams[index].clone(), 8)
            .next()
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        let DataHeader::Long(long::DataHeader::Initial(header)) = parsed.header else {
            panic!()
        };
        let packet = CipherPacket::new(header, parsed.bytes, parsed.offset)
            .decrypt_long_packet(&keys(true).opening, |_| Ok(pn))
            .unwrap()
            .unwrap();
        for frame in FrameReader::new(
            packet.body(),
            qbase::packet::GetType::get_type(
                &LongHeaderBuilder::with_cid(Default::default(), Default::default())
                    .initial(vec![]),
            ),
        ) {
            if let Frame::Crypto(frame, bytes) = frame.unwrap().0 {
                assert_eq!(frame.offset(), recovered.len() as u64);
                recovered.extend_from_slice(&bytes);
            }
        }
    }
    assert_eq!(recovered, message);
}

#[tokio::test]
async fn only_undecided_client_initial_replays_flighting_crypto() {
    for role in [Role::Client, Role::Server] {
        for handshaking in [false, true] {
            for selected in [u8::MAX, 0, 1, 2] {
                let paths = crate::common::initial_paths(
                    role,
                    ConnectionId::from_slice(b"localcid"),
                    ConnectionId::from_slice(b"original"),
                    keys(role == Role::Server),
                );
                crate::common::initial_space(&paths.spaces)
                    .crypto
                    .writer()
                    .write_all(b"hello")
                    .await
                    .unwrap();
                if handshaking {
                    super::enter_handshake(
                        &paths,
                        Arc::new(HandshakeSpace::new(
                            Default::default(),
                            crate::common::initial_space(&paths.spaces).keys.clone(),
                        )),
                    );
                }
                let path = Arc::new(Path::new(
                    Pathway::new(
                        EndpointAddr::direct("127.0.0.1:35001".parse().unwrap()),
                        EndpointAddr::direct("127.0.0.1:35002".parse().unwrap()),
                    ),
                    paths.handshake.clone(),
                    ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                    paths.resender.clone(),
                    &paths.cids,
                ));
                path.validate();
                let competitor = Path::new(
                    Pathway::new(
                        EndpointAddr::direct("127.0.0.1:35001".parse().unwrap()),
                        EndpointAddr::direct("127.0.0.1:35003".parse().unwrap()),
                    ),
                    paths.handshake.clone(),
                    ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                    paths.resender.clone(),
                    &paths.cids,
                );
                match selected {
                    0 => {
                        paths.cids.select(&competitor.cid);
                    }
                    1 => {
                        paths.cids.select(&path.cid);
                    }
                    2 => {
                        paths.cids.select(&path.cid);
                        paths.cids.attach_remote(qbase::cid::ArcRemoteCids::new(
                            paths.cids.initial_dcid(),
                            2,
                            paths.reliable_frames.clone(),
                        ));
                        paths.handshake.handshake_confirmed();
                        paths.cids.confirm_handshake();
                    }
                    _ => {}
                }
                let mut datagrams = [BytesMut::with_capacity(1200)];
                let mut frames = Vec::new();
                let mut pns = [[None; 3]; MAX_BURST_PACKETS];
                for attempt in 0..2 {
                    let result = collect(Burst::new(
                        &paths,
                        &path,
                        &mut datagrams,
                        &mut frames,
                        &mut pns,
                    ))
                    .now_or_never();
                    let replays = role == Role::Client && !handshaking && selected == u8::MAX;
                    if selected != 0 && (attempt == 0 || replays) {
                        assert!(
                            matches!(result, Some(Ok(1))),
                            "{role:?} {handshaking} {selected} {attempt}"
                        );
                        for slots in &mut pns {
                            slots[Epoch::Initial] = None;
                        }
                    } else {
                        assert!(
                            result.is_none(),
                            "{role:?} {handshaking} {selected} {attempt}"
                        );
                        assert!(pns.iter().flatten().all(Option::is_none));
                    }
                    assert!(frames.is_empty());
                }
                task::cancel_waiters(&paths, &path);
                path.retire();
            }
        }
    }
}

#[tokio::test]
async fn closing_is_collected_before_failed_crypto_and_draining_returns_error() {
    for epoch in [Epoch::Initial, Epoch::Handshake] {
        let paths = crate::common::initial_paths(
            Role::Server,
            ConnectionId::from_slice(b"server00"),
            ConnectionId::from_slice(b"original"),
            keys(true),
        );
        let terminator = paths.terminator.clone();
        let mut space = crate::common::initial_space(&paths.spaces);
        let trackers = paths.resender.clone();
        if epoch == Epoch::Handshake {
            let handshake = Arc::new(HandshakeSpace::new(
                Default::default(),
                ArcKeys::new(Arc::new(keys(true))),
            ));
            super::enter_handshake(&paths, handshake.clone());
            space.retire();
            space = Arc::new(handshake.0.clone());
        }
        let path = Arc::new(Path::new(
            Pathway::new(
                EndpointAddr::direct("127.0.0.1:33001".parse().unwrap()),
                EndpointAddr::direct("127.0.0.1:33002".parse().unwrap()),
            ),
            paths.handshake.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            trackers.clone(),
            &paths.cids,
        ));
        path.validate();
        paths.cids.select(&path.cid);
        let error = QuicError::with_default_fty(ErrorKind::Internal, "TLS failed");
        terminator.close(
            crate::CloseReason::Internal(error.clone()),
            paths.closing_pto(),
        );
        space.crypto.on_error(&error.into());
        let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
        let mut frames = Vec::new();
        let mut pns = [[None; 3]; MAX_BURST_PACKETS];
        let mut collector = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut pns);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            collector.poll_collect(&mut cx),
            Poll::Ready(Ok(1))
        ));
        let pn = pns_for(collector.packets, epoch).next().unwrap().1;
        assert_eq!(space.sent_journal.lock_guard().frames(pn).count(), 0);
        drop(collector);
        let ParsedPacket::Data(packet) = PacketReader::new(datagrams[0].clone(), 8)
            .next()
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        use qbase::packet::GetType;
        let ty = packet.get_type();
        let body = match packet.header {
            DataHeader::Long(long::DataHeader::Initial(header)) => {
                CipherPacket::new(header, packet.bytes, packet.offset)
                    .decrypt_long_packet(&keys(false).opening, |_| Ok(pn))
                    .unwrap()
                    .unwrap()
                    .body()
            }
            DataHeader::Long(long::DataHeader::Handshake(header)) => {
                CipherPacket::new(header, packet.bytes, packet.offset)
                    .decrypt_long_packet(&keys(false).opening, |_| Ok(pn))
                    .unwrap()
                    .unwrap()
                    .body()
            }
            _ => panic!(),
        };
        let decoded = FrameReader::new(body, ty)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            decoded
                .iter()
                .any(|(frame, _)| matches!(frame, Frame::Close(_)))
        );
        assert!(
            decoded
                .iter()
                .all(|(frame, _)| matches!(frame, Frame::Close(_) | Frame::Padding(_)))
        );
        for slots in &mut pns {
            slots[epoch] = None;
        }
        let mut collector = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut pns);
        assert!(collector.poll_collect(&mut cx).is_pending());
        terminator.terminate();
        assert!(matches!(
            collector.poll_collect(&mut cx),
            Poll::Ready(Err(_))
        ));
    }
}

fn server_one_rtt_keys() -> qtls::OneRttKeyMaterial {
    use tls_backend::pki_types::pem::PemObject;
    let provider = Arc::new(qtls::default_provider());
    qtls::RootCerts::set([qtls::CertificateDer::from_pem_slice(include_bytes!(
        "../keychain/localhost/ca.cert"
    ))
    .unwrap()])
    .unwrap();
    let client = qtls::TlsClient::new(qtls::ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        authority: None,
        resumption: qtls::ClientResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap();
    let server = qtls::TlsServer::new(qtls::ServerTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        authority: qtls::LocalAuthority::new(
            &provider,
            Arc::from("localhost"),
            vec![
                qtls::CertificateDer::from_pem_slice(include_bytes!(
                    "../keychain/localhost/server.cert"
                ))
                .unwrap(),
            ],
            qtls::PrivateKeyDer::from_pem_slice(include_bytes!("../keychain/localhost/server.key"))
                .unwrap(),
            include_bytes!("../keychain/localhost/server.ocsp").to_vec(),
        )
        .unwrap(),
        resumption: qtls::ServerResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap();
    let mut client = client
        .start(qtls::ClientStart {
            server_name: "localhost".try_into().unwrap(),
            quic_version: qtls::QuicVersion::V1,
            local_transport_parameters: bytes::Bytes::new(),
        })
        .unwrap();
    let mut server = server
        .start(qtls::QuicVersion::V1, bytes::Bytes::new())
        .unwrap();
    while let Some(event) = client.next_event() {
        if let qtls::TlsEvent::WriteCrypto {
            epoch: level,
            bytes,
        } = event
        {
            server.receive_crypto(level, &bytes).unwrap();
        }
    }
    loop {
        if let qtls::TlsEvent::InstallKeys(qtls::InstalledKeys::OneRtt(keys)) =
            server.next_event().unwrap()
        {
            return keys;
        }
    }
}

pub(super) fn mature_phase(role: Role, defer: Duration) -> (Arc<Paths>, super::MatureFixture) {
    use qbase::param::{ArcParameters, ClientParameters, ServerParameters};
    let paths = crate::common::initial_paths_with_timeouts(
        role,
        ConnectionId::from_slice(b"server00"),
        ConnectionId::from_slice(b"original"),
        keys(true),
        Duration::ZERO,
        defer,
    );
    let mut client = ClientParameters::default();
    client
        .set(
            ParameterId::InitialSourceConnectionId,
            ConnectionId::from_slice(b"client00"),
        )
        .unwrap();
    let parameters = ArcParameters::new(
        Role::Server,
        Arc::new(client),
        Arc::new(ServerParameters::default()),
    );
    let terminator = &paths.terminator;
    let registry = crate::CidRegistry::new(
        crate::common::initial_phase(&paths).local_cids.clone(),
        qbase::cid::ArcRemoteCids::new(
            parameters.remote(ParameterId::InitialSourceConnectionId),
            2,
            paths.reliable_frames.clone(),
        ),
    );
    let handshake = Arc::new(HandshakeSpace::new(
        Default::default(),
        ArcKeys::new(Arc::new(keys(true))),
    ));
    terminator.register(Arc::new(handshake.crypto.clone()));
    let reliable_frames = paths.reliable_frames.clone();
    let streams = crate::DataStreams::new(
        parameters.clone(),
        Box::new(qbase::sid::handy::ConsistentConcurrency::new(
            parameters.local(qbase::param::ParameterId::InitialMaxStreamsBidi),
            parameters.local(qbase::param::ParameterId::InitialMaxStreamsUni),
        )),
        reliable_frames.clone(),
        None,
    );
    terminator.register(Arc::new(streams.clone()));
    let flow = crate::FlowController::new(
        parameters.remote(qbase::param::ParameterId::InitialMaxData),
        parameters.local(qbase::param::ParameterId::InitialMaxData),
        reliable_frames.clone(),
    );
    let data = Arc::new(qtransport::space::DataSpace::new(
        Default::default(),
        qtransport::keys::ArcOneRttKeys::from(server_one_rtt_keys()),
        streams,
        reliable_frames.clone(),
    ));
    terminator.register(Arc::new(data.crypto.clone()));
    let puncher = qtraversal::punch::ArcPuncher::new(
        reliable_frames,
        qtraversal::punch::ProbeEncoder::new(data.clone(), ConnectionId::from_slice(b"client00")),
    );
    let concrete = super::SpaceFixture {
        initial: crate::common::initial_space(&paths.spaces),
        handshake,
        data,
    };
    let mature = Arc::new(MaturePhase {
        flow_ctrl: flow,
        cid_registry: registry,
        parameters,
        puncher,
    });
    (
        paths.clone(),
        super::MatureFixture {
            paths,
            phase: mature,
            spaces: concrete,
        },
    )
}

#[tokio::test]
async fn phase_upgrade_wakes_senders_and_releases_subscriptions() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let (paths, mature) = mature_phase(Role::Server, Duration::ZERO);
    let phase = paths.phase();
    let first = Arc::new(Counter::default());
    let second = Arc::new(Counter::default());
    let a = Waker::from(first.clone());
    let b = Waker::from(second.clone());
    let mut cx = Context::from_waker(&a);
    let ConnPhase::Initial(initial) = phase.poll_phase(&mut cx).clone() else {
        panic!("expected Initial");
    };
    drop(phase.poll_phase(&mut cx));
    drop(phase.poll_phase(&mut Context::from_waker(&b)));
    initial.upgrade_wakers.unregister(&b);
    paths
        .cids
        .update_initial_dcid(ConnectionId::from_slice(b"peer0000"));
    initial.set_dcid(ConnectionId::from_slice(b"peer0000"));
    assert_eq!(
        paths.cids.initial_dcid(),
        ConnectionId::from_slice(b"peer0000")
    );
    assert_eq!(first.0.load(Ordering::Relaxed), 1);
    assert_eq!(second.0.load(Ordering::Relaxed), 0);
    drop(phase.poll_phase(&mut Context::from_waker(&b)));

    let dcid = phase.enter_handshake();
    assert_eq!(dcid, ConnectionId::from_slice(b"peer0000"));
    assert_eq!(paths.spaces.read_guard().len(), 1);
    assert_eq!(paths.resender.read_guard().len(), 1);
    assert_eq!(first.0.load(Ordering::Relaxed), 2);
    assert_eq!(second.0.load(Ordering::Relaxed), 1);
    assert_eq!(
        Arc::strong_count(&first),
        3,
        "Handshake preserves Initial subscriptions"
    );
    assert_eq!(Arc::strong_count(&second), 3);
    assert_eq!(
        Arc::strong_count(&initial),
        1,
        "Handshake must not own InitialPhase"
    );
    drop(initial);

    let ConnPhase::Handshake(handshake) = phase.get() else {
        panic!("expected Handshake");
    };
    assert_eq!(handshake.dcid, dcid);
    handshake.upgrade_wakers.unregister(&b);
    drop(phase.poll_phase(&mut cx));
    drop(phase.poll_phase(&mut cx));
    drop(phase.poll_phase(&mut Context::from_waker(&b)));

    phase.enter_mature(mature.phase.clone());
    assert_eq!(paths.spaces.read_guard().len(), 1);
    assert_eq!(paths.resender.read_guard().len(), 1);
    assert_eq!(first.0.load(Ordering::Relaxed), 3);
    assert_eq!(second.0.load(Ordering::Relaxed), 2);
    assert_eq!(
        Arc::strong_count(&first),
        2,
        "Handshake releases subscriptions"
    );
    assert_eq!(Arc::strong_count(&second), 2);
    assert!(matches!(&*phase.poll_phase(&mut cx), ConnPhase::Mature(_)));
    drop(phase.poll_phase(&mut Context::from_waker(&b)));
    assert_eq!(
        Arc::strong_count(&first),
        2,
        "Mature must not register wakers"
    );
    assert_eq!(Arc::strong_count(&second), 2);
    assert!(matches!(phase.get(), ConnPhase::Mature(_)));
}

#[tokio::test]
async fn phase_upgrades_preserve_cid_cleanup_and_termination() {
    let (paths, mature) = mature_phase(Role::Server, Duration::ZERO);
    let local_cids = crate::common::initial_phase(&paths).local_cids.clone();
    let terminator = paths.terminator.clone();
    let phase = paths.phase();
    super::enter_handshake(&paths, mature.spaces.handshake.clone());
    let ConnPhase::Handshake(handshake) = phase.get() else {
        panic!("expected Handshake");
    };
    super::enter_mature(&paths, &mature);

    local_cids.clear();
    assert!(handshake.local_cids.initial_scid().is_none());
    assert!(mature.cid_registry.local.initial_scid().is_none());
    terminator.terminate();
    let error = terminator.now_or_never().unwrap();
    assert_eq!(paths.terminator.clone().now_or_never(), Some(error));
}

#[tokio::test(start_paused = true)]
async fn existing_path_recovers_new_spaces_after_phase_upgrade() {
    let (paths, mature) = mature_phase(Role::Server, Duration::ZERO);
    let path = Arc::new(Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:34101".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:34102".parse().unwrap()),
        ),
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        paths.resender.clone(),
        &paths.cids,
    ));
    path.validate();
    paths.cids.select(&path.cid);
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::new();
    let mut pns = [[None; 3]; MAX_BURST_PACKETS];

    for epoch in [Epoch::Handshake, Epoch::Data] {
        let (crypto, journal) = if epoch == Epoch::Handshake {
            super::enter_handshake(&paths, mature.spaces.handshake.clone());
            (
                &mature.spaces.handshake.crypto,
                &mature.spaces.handshake.sent_journal,
            )
        } else {
            super::enter_mature(&paths, &mature);
            super::confirm_handshake(&paths);
            (&mature.spaces.data.crypto, &mature.spaces.data.sent_journal)
        };
        let mut sent = Vec::new();
        for _ in 0..4 {
            crypto.writer().write_all(b"crypto").await.unwrap();
            collect(Burst::new(
                &paths,
                &path,
                &mut datagrams,
                &mut frames,
                &mut pns,
            ))
            .now_or_never()
            .unwrap()
            .unwrap();
            assert_eq!(pns_for(&pns, epoch).count(), 1);
            let (index, pn) = pns_for(&pns, epoch).next().unwrap();
            journal.on_sent(pn, true, Duration::from_secs(1), Duration::from_secs(3));
            path.cc
                .on_pkt_sent(epoch, pn, true, datagrams[index].len(), true, None);
            sent.push(pn);
            for entries in &mut pns {
                entries.fill(None);
            }
        }
        // Three later packets prove the first one lost. CC must call the newly attached space.
        let ack = qbase::frame::AckFrame::new(
            sent[3].try_into().unwrap(),
            0u32.into(),
            0u32.into(),
            vec![],
            None,
        );
        path.cc.on_ack_rcvd(epoch, &ack);
        collect(Burst::new(
            &paths,
            &path,
            &mut datagrams,
            &mut frames,
            &mut pns,
        ))
        .now_or_never()
        .expect("loss must make the original CRYPTO range sendable")
        .unwrap();
        assert_eq!(pns_for(&pns, epoch).count(), 1);
        let records = journal.lock_guard();
        assert!(records.frames(pns_for(&pns, epoch).next().unwrap().1).any(|frame| {
            matches!(frame, GuaranteedFrame::Crypto(frame) if frame.offset() == 0 && frame.len() == 6)
        }));
        for entries in &mut pns {
            entries.fill(None);
        }
    }
}
#[tokio::test]
async fn growing_assigns_the_selected_cid_before_releasing_or_creating_other_paths() {
    use qbase::frame::{NewConnectionIdFrame, io::ReceiveFrame};

    let (paths, mature) = mature_phase(Role::Server, Duration::ZERO);
    let remote = &mature.cid_registry.remote;
    let next = ConnectionId::from_slice(b"client01");
    remote
        .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
        .unwrap();
    let make_path = |port| {
        let path = Arc::new(Path::new(
            Pathway::new(
                EndpointAddr::direct(([127, 0, 0, 1], port).into()),
                EndpointAddr::direct("127.0.0.1:34300".parse().unwrap()),
            ),
            paths.handshake.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.resender.clone(),
            &paths.cids,
        ));
        paths
            .entries
            .lock()
            .unwrap()
            .insert(path.pathway, path.clone());
        path
    };
    let other = make_path(34301);
    let selected = make_path(34302);
    paths.select_path(&selected);
    assert!(
        matches!(super::borrow(&selected), Poll::Ready(Some(cid)) if *cid == paths.cids.initial_dcid())
    );
    super::enter_mature(&paths, &mature);
    assert!(
        matches!(super::borrow(&selected), Poll::Ready(Some(cid)) if *cid == mature.peer_cid())
    );
    assert!(super::borrow(&other).is_pending());
    assert_eq!(super::selection(&paths, &other), 0);
    super::confirm_handshake(&paths);
    assert_eq!(super::selection(&paths, &selected), 2);
    assert_eq!(super::selection(&paths, &other), 2);
    assert!(matches!(super::borrow(&other), Poll::Ready(Some(cid)) if *cid == next));
    let added = paths.add_path(Pathway::new(
        EndpointAddr::direct("127.0.0.1:34303".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:34300".parse().unwrap()),
    ));
    assert!(super::borrow(&added).is_pending());
    assert_eq!(super::selection(&paths, &added), 2);
    paths.retire_all();
}

#[tokio::test]
async fn mature_packets_wait_for_and_share_the_path_cid() {
    use qbase::{
        frame::{NewConnectionIdFrame, io::ReceiveFrame},
        packet::GetDcid,
    };

    let (paths, mature) = mature_phase(Role::Server, Duration::ZERO);
    let remote = &mature.cid_registry.remote;
    let initial_cell = remote.apply_dcid();
    super::enter_mature(&paths, &mature);
    let path = Arc::new(Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:34201".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:34202".parse().unwrap()),
        ),
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        paths.resender.clone(),
        &paths.cids,
    ));
    paths.cids.select(&path.cid);
    path.validate();
    // The selected sender waits if the available CID was already consumed.
    assert!(paths.cids.is_selected(&path.cid));
    for crypto in [
        &mature.spaces.initial.crypto,
        &mature.spaces.handshake.crypto,
        &mature.spaces.data.crypto,
    ] {
        crypto.writer().write_all(b"crypto").await.unwrap();
    }
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::new();
    let mut pns = [[None; 3]; MAX_BURST_PACKETS];
    let mut collector = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut pns);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(collector.poll_collect(&mut cx).is_pending());
    let next = ConnectionId::from_slice(b"client01");
    remote
        .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
        .unwrap();
    assert!(matches!(
        collector.poll_collect(&mut cx),
        Poll::Ready(Ok(1))
    ));
    // Keep the CID borrowed while the assembled datagram awaits UDP submission.
    let borrowed = collector.dcid.take().unwrap();
    drop(collector);
    assert!(
        Epoch::EPOCHS
            .into_iter()
            .all(|epoch| pns[0][epoch].is_some())
    );
    let packets = PacketReader::new(datagrams[0].clone(), 8)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(packets.len(), 3);
    for packet in packets {
        let ParsedPacket::Data(packet) = packet else {
            panic!()
        };
        assert_eq!(*packet.header.dcid(), next);
    }
    initial_cell.retire();
    let replacement = ConnectionId::from_slice(b"client02");
    remote
        .recv_frame(NewConnectionIdFrame::new(
            replacement,
            2u32.into(),
            2u32.into(),
        ))
        .unwrap();
    assert_eq!(*borrowed, next);
    let ConnPhase::Mature(current) = paths.phase().get() else {
        panic!("expected Mature");
    };
    assert!(Arc::ptr_eq(&current, &mature.phase));
    drop(borrowed);
    assert!(matches!(super::borrow(&path),
        Poll::Ready(Some(cid)) if *cid == replacement));

    for slots in &mut pns {
        slots.fill(None);
    }
    for crypto in [
        &mature.spaces.initial.crypto,
        &mature.spaces.handshake.crypto,
        &mature.spaces.data.crypto,
    ] {
        crypto.writer().write_all(b"next").await.unwrap();
    }
    collect(Burst::new(
        &paths,
        &path,
        &mut datagrams,
        &mut frames,
        &mut pns,
    ))
    .now_or_never()
    .unwrap()
    .unwrap();
    assert!(
        Epoch::EPOCHS
            .into_iter()
            .all(|epoch| pns[0][epoch].is_some())
    );
    let packets = PacketReader::new(datagrams[0].clone(), 8)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(packets.len(), 3);
    for packet in packets {
        let ParsedPacket::Data(packet) = packet else {
            panic!()
        };
        assert_eq!(*packet.header.dcid(), replacement);
    }
}

#[tokio::test]
async fn mature_server_collects_its_three_spaces_and_one_rtt_close() {
    let (paths, mature) = mature_phase(Role::Server, Duration::ZERO);
    for crypto in [
        &mature.spaces.initial.crypto,
        &mature.spaces.handshake.crypto,
        &mature.spaces.data.crypto,
    ] {
        crypto.writer().write_all(b"crypto").await.unwrap();
    }
    super::enter_mature(&paths, &mature);
    let path = Arc::new(Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:34001".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:34002".parse().unwrap()),
        ),
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        paths.resender.clone(),
        &paths.cids,
    ));
    path.validate();
    paths.cids.select(&path.cid);
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::new();
    let mut pns = [[None; 3]; MAX_BURST_PACKETS];
    assert_eq!(
        collect(Burst::new(
            &paths,
            &path,
            &mut datagrams,
            &mut frames,
            &mut pns
        ))
        .now_or_never()
        .unwrap()
        .unwrap(),
        1
    );
    for epoch in Epoch::EPOCHS {
        assert_eq!(pns_for(&pns, epoch).count(), 1);
    }
    assert_eq!(pns_for(&pns, Epoch::Initial).next().unwrap().0, 0);
    assert_eq!(pns_for(&pns, Epoch::Handshake).next().unwrap().0, 0);
    assert_eq!(pns_for(&pns, Epoch::Data).next().unwrap().0, 0);
    assert!(frames.is_empty());
    // Consume this burst's packet numbers before collecting the next burst.
    for entries in &mut pns {
        entries.fill(None);
    }
    mature
        .spaces
        .initial
        .crypto
        .writer()
        .write_all(b"remaining")
        .await
        .unwrap();
    paths.handshake.handshake_confirmed();
    paths.cids.confirm_handshake();
    assert!(matches!(
        collect(Burst::new(
            &paths,
            &path,
            &mut datagrams,
            &mut frames,
            &mut pns
        ))
        .now_or_never(),
        Some(Ok(1))
    ));
    assert_eq!(pns_for(&pns, Epoch::Initial).count(), 1);
    for slots in &mut pns {
        slots[Epoch::Initial] = None;
    }
    // A path without an available CID must wait before collecting data. Retirement
    // must wake that wait even though the socket has never been polled.
    let waiting_path = Arc::new(Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:34003".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:34002".parse().unwrap()),
        ),
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        paths.resender.clone(),
        &paths.cids,
    ));
    waiting_path.validate();
    mature
        .spaces
        .data
        .crypto
        .writer()
        .write_all(b"next")
        .await
        .unwrap();
    paths
        .entries
        .lock()
        .unwrap()
        .insert(path.pathway, path.clone());
    let sending_task = tokio::spawn(sending(paths.clone(), waiting_path.clone()));
    tokio::task::yield_now().await;
    assert!(!sending_task.is_finished());
    waiting_path.retire();
    tokio::time::timeout(Duration::from_secs(1), sending_task)
        .await
        .unwrap()
        .unwrap();
    mature.spaces.initial.retire();
    mature.spaces.handshake.retire();
    let (_, mut writer) = mature
        .spaces
        .data
        .streams
        .open_uni()
        .await
        .unwrap()
        .unwrap();
    writer.write_all(b"queued before closing").await.unwrap();
    assert!(mature.spaces.data.streams.fresh_bytes() > 0);
    let credit = mature.flow_ctrl.sender.credit(usize::MAX).available();
    assert!(credit > 0);
    let error = QuicError::with_default_fty(ErrorKind::Internal, "connection failed");
    paths.terminator.close(
        crate::CloseReason::Internal(error.clone()),
        paths.closing_pto(),
    );
    mature.spaces.data.crypto.on_error(&error.into());
    // Closing stops the streams; the flow controller remains an ordinary credit ledger.
    assert_eq!(mature.spaces.data.streams.fresh_bytes(), 0);
    assert_eq!(
        mature.flow_ctrl.sender.credit(usize::MAX).available(),
        credit
    );
    assert_eq!(
        collect(Burst::new(
            &paths,
            &path,
            &mut datagrams,
            &mut frames,
            &mut pns
        ))
        .now_or_never()
        .unwrap()
        .unwrap(),
        1
    );
    assert!(pns_for(&pns, Epoch::Initial).next().is_none());
    assert!(pns_for(&pns, Epoch::Handshake).next().is_none());
    let pn = pns_for(&pns, Epoch::Data).next().unwrap().1;
    let journal = mature.spaces.data.sent_journal.lock_guard();
    assert_eq!(journal.frames(pn).count(), 0);
    assert_eq!(
        journal.packet(pn).unwrap().content,
        qbase::packet::PacketContent::NonAckEliciting
    );
    assert!(journal.packet(pn).unwrap().size > 0);
}

#[tokio::test(start_paused = true)]
async fn heartbeat_wakes_the_collector_and_supplies_ping_in_each_space() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use qbase::packet::PacketContent;

    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    for epoch in Epoch::EPOCHS {
        let (paths, mature) = mature_phase(Role::Server, Duration::from_secs(60));
        if epoch == Epoch::Handshake {
            super::enter_handshake(&paths, mature.spaces.handshake.clone());
            mature.spaces.initial.retire();
        } else if epoch == Epoch::Data {
            super::enter_mature(&paths, &mature);
        }
        let path = Arc::new(Path::new(
            Pathway::new(
                "127.0.0.1:30001".parse::<EndpointAddr>().unwrap(),
                "127.0.0.1:30002".parse().unwrap(),
            ),
            paths.handshake.clone(),
            ArcHeartbeat::new(Duration::from_secs(60), Duration::ZERO),
            paths.resender.clone(),
            &paths.cids,
        ));
        path.validate();
        paths.cids.select(&path.cid);
        path.heartbeat
            .on_rcvd_at(PacketContent::EffectivePayload, tokio::time::Instant::now())
            .unwrap();

        if epoch == Epoch::Data {
            super::confirm_handshake(&paths);
        }
        let mut datagrams = [BytesMut::with_capacity(1200)];
        let mut frames = Vec::new();
        let mut pns = [[None; 3]; MAX_BURST_PACKETS];
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let mut collector = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut pns);
        if epoch == Epoch::Data {
            // Consume the CID advertisement queued by the fixture before testing idleness.
            assert!(matches!(
                collector.poll_collect(&mut cx),
                Poll::Ready(Ok(1))
            ));
            for slots in &mut *collector.packets {
                if let Some(meta) = slots[Epoch::Data].take() {
                    mature.spaces.data.on_sent(
                        meta.pn,
                        meta.in_flight,
                        Duration::from_secs(1),
                        Duration::from_secs(3),
                    );
                }
            }
            // Finish the simulated submission before collecting another batch.
            collector.cancel();
            assert!(collector.dcid.is_none());
        }
        assert!(collector.poll_collect(&mut cx).is_pending());
        tokio::task::yield_now().await;
        let before = counter.0.load(Ordering::Relaxed);
        tokio::time::advance(Duration::from_secs(20)).await;
        tokio::task::yield_now().await;
        assert!(counter.0.load(Ordering::Relaxed) > before);
        let result = collector.poll_collect(&mut cx);
        assert!(
            matches!(result, Poll::Ready(Ok(1))),
            "{epoch:?}: {result:?}"
        );
        drop(collector);
        assert_eq!(pns_for(&pns, epoch).count(), 1);
        let pn = pns_for(&pns, epoch).next().unwrap().1;
        assert_eq!(
            paths
                .spaces
                .read_guard()
                .get(epoch as u64)
                .unwrap()
                .sent_journal()
                .lock_guard()
                .packet(pn)
                .unwrap()
                .content,
            PacketContent::JustPing
        );
        path.retire();
    }
}

#[tokio::test]
async fn trackers_follow_space_creation_and_retirement_in_epoch_order() {
    for role in [Role::Client, Role::Server] {
        for retire_before_handshake in [false, true] {
            let (paths, mature) = mature_phase(role, Duration::ZERO);
            let selected = Path::new(
                Pathway::new(
                    EndpointAddr::direct("127.0.0.1:35201".parse().unwrap()),
                    EndpointAddr::direct("127.0.0.1:35202".parse().unwrap()),
                ),
                paths.handshake.clone(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.resender.clone(),
                &paths.cids,
            );
            paths.cids.select(&selected.cid);
            let trackers = paths.resender.clone();
            let epochs = || {
                trackers
                    .read_guard()
                    .enumerate()
                    .map(|(epoch, _)| epoch)
                    .collect::<Vec<_>>()
            };
            let retire_initial = || {
                if role == Role::Client {
                    paths.on_handshake_sent();
                } else {
                    paths.on_handshake_received();
                }
                super::retire_spaces(&paths, Epoch::Handshake);
            };
            assert_eq!(epochs(), [0]);
            if retire_before_handshake {
                retire_initial();
                retire_initial();
                assert!(epochs().is_empty());
                assert!(mature.spaces.initial.keys.get().is_err());
            }
            super::enter_handshake(&paths, mature.spaces.handshake.clone());
            if retire_before_handshake {
                assert_eq!(epochs(), [1]);
            } else {
                assert_eq!(epochs(), [0, 1]);
            }
            retire_initial();
            retire_initial();
            assert_eq!(epochs(), [1]);
            assert!(mature.spaces.initial.keys.get().is_err());
            assert!(mature.spaces.handshake.keys.get().is_ok());

            super::enter_mature(&paths, &mature);
            assert_eq!(epochs(), [1, 2]);
            retire_initial();
            assert_eq!(epochs(), [1, 2]);
            super::confirm_handshake(&paths);
            super::confirm_handshake(&paths);
            assert_eq!(epochs(), [2]);
            assert!(mature.spaces.handshake.keys.get().is_err());
            assert!(mature.spaces.data.keys.get().is_ok());
        }
    }
}

fn pns_for(pns: &BurstPackets, epoch: Epoch) -> impl Iterator<Item = (usize, u64)> + '_ {
    pns.iter()
        .enumerate()
        .filter_map(move |(index, slots)| slots[epoch].map(|meta| (index, meta.pn)))
}

#[tokio::test(start_paused = true)]
async fn path_validation_respects_small_amplification_credit() {
    use qbase::frame::{PathChallengeFrame, io::ReceiveFrame};

    for received in [0, 128, 399, 400] {
        for reply in [false, true] {
            let (paths, mature) = mature_phase(Role::Server, Duration::ZERO);
            super::enter_mature(&paths, &mature);
            let path = Arc::new(Path::new(
                Pathway::new(
                    EndpointAddr::direct("127.0.0.1:35101".parse().unwrap()),
                    EndpointAddr::direct("127.0.0.1:35102".parse().unwrap()),
                ),
                paths.handshake.clone(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.resender.clone(),
                &paths.cids,
            ));
            paths.cids.select(&path.cid);
            paths.handshake.handshake_confirmed();
            paths.cids.confirm_handshake();
            path.on_datagram_received(received);
            let challenge = PathChallengeFrame::from_slice(&[7; 8]);
            if reply {
                path.recv_frame(challenge).unwrap();
            } else {
                path.set_challenge(challenge);
            }
            let credit = path.amplification_credit();
            let mut datagrams = [BytesMut::with_capacity(1200)];
            let mut frames = Vec::new();
            let mut pns: BurstPackets = [[None; 3]; MAX_BURST_PACKETS];
            let mut collector = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut pns);
            let result = collector.poll_collect(&mut Context::from_waker(Waker::noop()));
            drop(collector);
            if received == 0 {
                assert!(result.is_pending());
                assert!(pns_for(&pns, Epoch::Data).next().is_none());
            } else {
                assert!(
                    matches!(result, Poll::Ready(Ok(1))),
                    "received={received}, reply={reply}, result={result:?}"
                );
                let size = datagrams[0].len();
                assert!(size <= credit, "validation exceeded amplification credit");
                if credit < 1200 {
                    assert!(size < 1200);
                } else {
                    assert_eq!(size, 1200);
                }
                let journal = mature.spaces.data.sent_journal.lock_guard();
                assert!(
                    journal
                        .packet(pns[0][Epoch::Data].unwrap().pn)
                        .unwrap()
                        .in_flight
                );
                assert!(
                    if reply {
                        path.response().is_none()
                    } else {
                        path.challenge().is_none()
                    },
                    "validation frame was not encoded"
                );
            }
            assert!(!path.is_validated());
            path.retire();
            paths.terminator.terminate();
        }
    }
}

#[tokio::test]
async fn burst_commits_the_udp_prefix_and_recovers_only_the_failed_suffix() {
    use qprotocol::{QuicProtocol, UdpSocket};

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let local = EndpointAddr::direct(socket.local_addr().unwrap());
    QuicProtocol::global().register(local, &socket).unwrap();
    let paths = crate::common::initial_paths(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let space = crate::common::initial_space(&paths.spaces);
    space
        .crypto
        .writer()
        .write_all(&vec![42; 2400])
        .await
        .unwrap();
    let path = Arc::new(Path::new(
        Pathway::new(local, EndpointAddr::direct(peer.local_addr().unwrap())),
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        paths.resender.clone(),
        &paths.cids,
    ));
    path.client_handshaking();
    paths.cids.select(&path.cid);

    let mut datagrams = std::array::from_fn::<_, MAX_BURST_PACKETS, _>(|_| BytesMut::new());
    let mut frames = Vec::new();
    let mut pns = [[None; 3]; MAX_BURST_PACKETS];
    let mut burst = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut pns);
    let count = burst.collect().await.unwrap();
    assert!(count > 1);
    let pending = *burst.packets;
    let first = pending[0][Epoch::Initial].unwrap().pn;
    let suffix = pending[1][Epoch::Initial].unwrap().pn;
    let offset = space
        .sent_journal
        .lock_guard()
        .frames(suffix)
        .find_map(|frame| {
            if let GuaranteedFrame::Crypto(frame) = frame {
                Some(frame.offset())
            } else {
                None
            }
        })
        .unwrap();
    // The kernel accepts the first datagram, then rejects the oversized second datagram.
    burst.datagrams[1].resize(65536, 0);
    let error = burst.submit(count).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NoViablePath);
    assert!(burst.packets[0].iter().all(Option::is_none));
    assert_eq!(
        burst.packets[1].map(|packet| packet.map(|meta| (
            meta.pn,
            meta.pktlen,
            meta.content,
            meta.in_flight,
            meta.ack
        ))),
        pending[1].map(|packet| packet.map(|meta| (
            meta.pn,
            meta.pktlen,
            meta.content,
            meta.in_flight,
            meta.ack
        ))),
    );
    burst.cancel();
    assert!(burst.packets.iter().flatten().all(Option::is_none));
    {
        let journal = space.sent_journal.lock_guard();
        assert!(journal.packet(first).is_some());
        for slots in &pending[1..count] {
            assert!(journal.packet(slots[Epoch::Initial].unwrap().pn).is_none());
        }
    }
    let count = burst.collect().await.unwrap();
    let retransmit = burst.packets[0][Epoch::Initial].unwrap().pn;
    assert!(
        space
            .sent_journal
            .lock_guard()
            .frames(retransmit)
            .any(|frame| {
                matches!(frame, GuaranteedFrame::Crypto(frame) if frame.offset() == offset)
            })
    );
    burst.submit(count).await.unwrap();
    assert!(burst.packets.iter().flatten().all(Option::is_none));
    task::cancel_waiters(&paths, &path);
    QuicProtocol::global().unregister(socket.local_addr().unwrap());
}

#[tokio::test(start_paused = true)]
async fn space_and_path_account_each_packet_and_start_timers_at_submission() {
    use qprotocol::{QuicProtocol, UdpSocket};
    use tokio::time::Instant;

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let local = EndpointAddr::direct(socket.local_addr().unwrap());
    QuicProtocol::global().register(local, &socket).unwrap();
    let paths = crate::common::initial_paths(
        Role::Server,
        ConnectionId::from_slice(b"server00"),
        ConnectionId::from_slice(b"original"),
        keys(true),
    );
    let initial = crate::common::initial_space(&paths.spaces);
    let handshake = Arc::new(HandshakeSpace::new(
        Default::default(),
        initial.keys.clone(),
    ));
    initial.crypto.writer().write_all(b"initial").await.unwrap();
    handshake
        .crypto
        .writer()
        .write_all(b"handshake")
        .await
        .unwrap();
    super::enter_handshake(&paths, handshake.clone());
    let path = Arc::new(Path::new(
        Pathway::new(local, EndpointAddr::direct(peer.local_addr().unwrap())),
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        paths.resender.clone(),
        &paths.cids,
    ));
    path.on_datagram_received(1200);
    paths.cids.select(&path.cid);
    let mut datagrams = [BytesMut::with_capacity(1200)];
    let mut frames = Vec::new();
    let mut pns = [[None; 3]; MAX_BURST_PACKETS];
    let mut burst = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut pns);
    assert_eq!(burst.collect().await.unwrap(), 1);
    assert!(burst.packets[0][Epoch::Initial].is_some());
    assert!(burst.packets[0][Epoch::Handshake].is_some());
    let journals = [&initial.sent_journal, &handshake.sent_journal];
    tokio::time::advance(Duration::from_secs(10)).await;
    for journal in journals {
        journal.on_tick(Instant::now(), |_| panic!("unsubmitted packet timed out"));
    }
    assert_eq!(path.amplification_credit(), 3600);
    let delays =
        [Epoch::Initial, Epoch::Handshake].map(|epoch| path.cc.retransmit_and_expire_time(epoch).0);
    burst.submit(1).await.unwrap();
    let submitted_at = Instant::now();
    assert!(burst.packets[0].iter().all(Option::is_none));
    assert_eq!(path.amplification_credit(), 2400);
    burst.cancel();
    for (journal, delay) in journals.into_iter().zip(delays) {
        journal.on_tick(submitted_at + delay - Duration::from_nanos(1), |_| {
            panic!("timer started before submission")
        });
        let mut recovered = 0;
        journal.on_tick(submitted_at + delay, |_| recovered += 1);
        assert_eq!(
            recovered, 1,
            "each space starts its submitted packet's journal timer"
        );
    }
    task::cancel_waiters(&paths, &path);
    QuicProtocol::global().unregister(socket.local_addr().unwrap());
}

#[tokio::test]
async fn retired_cid_keeps_sender_pending_until_a_replacement_arrives() {
    use qbase::frame::{NewConnectionIdFrame, io::ReceiveFrame};

    let (paths, mature) = mature_phase(Role::Server, Duration::ZERO);
    let make_path = |port| {
        let path = Arc::new(Path::new(
            Pathway::new(
                EndpointAddr::direct("127.0.0.1:35501".parse().unwrap()),
                EndpointAddr::direct(([127, 0, 0, 1], port).into()),
            ),
            paths.handshake.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.resender.clone(),
            &paths.cids,
        ));
        path.validate();
        path
    };
    let selected = make_path(35502);
    let other = make_path(35503);
    paths.cids.select(&selected.cid);
    super::enter_mature(&paths, &mature);
    super::confirm_handshake(&paths);
    let remote = &mature.cid_registry.remote;
    let old = ConnectionId::from_slice(b"client01");
    remote
        .recv_frame(NewConnectionIdFrame::new(old, 1u32.into(), 0u32.into()))
        .unwrap();
    assert!(matches!(super::borrow(&other), Poll::Ready(Some(cid)) if *cid == old));
    // The selected path gets the sole replacement. The other path stays alive.
    remote
        .recv_frame(NewConnectionIdFrame::new(
            ConnectionId::from_slice(b"client02"),
            2u32.into(),
            2u32.into(),
        ))
        .unwrap();
    mature
        .spaces
        .data
        .crypto
        .writer()
        .write_all(b"waiting for a CID")
        .await
        .unwrap();
    let mut datagrams = [BytesMut::new()];
    let mut frames = Vec::new();
    let mut packets = [[None; 3]; MAX_BURST_PACKETS];
    let mut burst = Burst::new(&paths, &other, &mut datagrams, &mut frames, &mut packets);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(burst.poll_collect(&mut cx).is_pending());
    assert!(burst.packets.iter().flatten().all(Option::is_none));
    assert!(burst.dcid.is_none());
    assert!(other.is_validated());
    let replacement = ConnectionId::from_slice(b"client03");
    remote
        .recv_frame(NewConnectionIdFrame::new(
            replacement,
            3u32.into(),
            2u32.into(),
        ))
        .unwrap();
    assert!(matches!(burst.poll_collect(&mut cx), Poll::Ready(Ok(n)) if n > 0));
    assert_eq!(**burst.dcid.as_ref().unwrap(), replacement);
    burst.cancel();
    other.retire();
    assert!(
        matches!(burst.poll_collect(&mut cx), Poll::Ready(Err(error))
        if error.kind() == ErrorKind::NoViablePath && error.to_string().contains("path CID binding retired"))
    );
}
