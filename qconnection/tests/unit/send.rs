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
    Paths,
    common::initial_keys as keys,
    send::{Burst, BurstPackets, MAX_BURST_PACKETS, sending, task},
};

async fn collect(mut burst: Burst<'_, '_>) -> Result<usize, crate::Error> {
    burst.collect().await
}

#[tokio::test(start_paused = true)]
async fn inactive_paths_keep_acks_and_heartbeats_without_consuming_payload() {
    use qbase::{
        frame::{MaxDataFrame, PathChallengeFrame, io::SendFrame},
        packet::PacketContent,
    };

    for epoch in Epoch::EPOCHS {
        let (paths, data) = data_spaces(Role::Server, Duration::from_secs(60));
        super::install_data(&paths, &data);
        let path = crate::common::registered_path(
            &paths,
            Path::new(
                crate::common::path_fixtures::pathway(34601),
                paths.progress.facts(),
                ArcHeartbeat::new(Duration::from_secs(60), Duration::ZERO),
                paths.loss_resender.clone(),
                paths.cid_registry.remote.apply_dcid(),
            ),
        );
        path.validation.enter_validated().unwrap();
        path.disable();
        let space = paths.spaces.read_guard().get(epoch as u64).unwrap().clone();
        for crypto in [
            &data.spaces.initial.crypto,
            &data.spaces.handshake.crypto,
            &data.spaces.data.crypto,
        ] {
            crypto.writer().write_all(b"queued crypto").await.unwrap();
        }
        let (_, mut writer) = data.spaces.data.streams.open_uni().await.unwrap().unwrap();
        writer.write_all(b"queued stream").await.unwrap();
        data.spaces
            .data
            .reliable_frames
            .send_frame([qbase::frame::StreamCtlFrame::from(MaxDataFrame::new(
                1234u32.into(),
            ))]);
        path.validation.revalidate().unwrap();
        path.validation.on_received(1000);
        path.validation
            .challenge(PathChallengeFrame::from_slice(&[7; 8]))
            .unwrap();
        for pn in [41, 42] {
            space
                .rcvd_journal()
                .on_rcvd_pn(pn, true, Duration::from_secs(1));
            path.cc.on_pkt_rcvd(epoch, pn, true);
        }
        let mut datagrams = [BytesMut::new()];
        let mut frames = Vec::new();
        let mut packets = [[None; 3]; MAX_BURST_PACKETS];
        let mut burst = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut packets);
        let mut cx = Context::from_waker(Waker::noop());
        let result = burst.poll_collect(&mut cx);
        assert!(
            matches!(result, Poll::Ready(Ok(1))),
            "{epoch:?}: {result:?}"
        );
        let meta = burst.packets[0][epoch].unwrap();
        assert_eq!(meta.ack, Some(42));
        assert_eq!(meta.content, PacketContent::NonAckEliciting);
        assert!(
            space
                .sent_journal()
                .lock_guard()
                .frames(meta.pn)
                .next()
                .is_none()
        );
        assert_eq!(
            data.spaces.data.streams.fresh_bytes(),
            b"queued stream".len()
        );
        burst.packets[0][epoch] = None;
        space.on_sent(
            meta.pn,
            false,
            Duration::from_secs(1),
            Duration::from_secs(3),
        );
        path.cc
            .on_pkt_sent(epoch, meta.pn, false, meta.pktlen, false, Some(42));
        burst.cancel();
        path.heartbeat
            .on_rcvd_at(PacketContent::EffectivePayload, tokio::time::Instant::now())
            .unwrap();
        tokio::time::advance(Duration::from_secs(20)).await;
        path.cc.do_tick().unwrap();
        assert!(matches!(burst.poll_collect(&mut cx), Poll::Ready(Ok(1))));
        for meta in burst.packets.iter().flatten().flatten() {
            assert_ne!(meta.content, PacketContent::EffectivePayload);
        }
        assert!(
            burst
                .packets
                .iter()
                .flatten()
                .flatten()
                .any(|meta| meta.content == PacketContent::JustPing)
        );
        burst.cancel();
        path.enable();
        assert!(matches!(burst.poll_collect(&mut cx), Poll::Ready(Ok(1))));
        assert!(
            burst
                .packets
                .iter()
                .flatten()
                .flatten()
                .any(|meta| meta.content == PacketContent::EffectivePayload)
        );
        assert!(data.spaces.data.streams.fresh_bytes() < b"queued stream".len());
        burst.cancel();
        path.disable();
        paths.terminator.close(
            crate::CloseReason::Internal(QuicError::with_default_fty(
                ErrorKind::Internal,
                "closed",
            )),
            paths.closing_pto(),
        );
        assert!(matches!(burst.poll_collect(&mut cx), Poll::Ready(Ok(1))));
        assert!(
            burst
                .packets
                .iter()
                .flatten()
                .flatten()
                .all(|meta| meta.content == PacketContent::NonAckEliciting)
        );
        burst.cancel();
        task::cancel_waiters(&paths, &path);
        paths.retire_all();
    }
}

#[tokio::test(start_paused = true)]
async fn deactivation_cancels_unsubmitted_payload_and_keeps_it_for_reactivation() {
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
        .write_all(b"queued crypto")
        .await
        .unwrap();
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            crate::common::path_fixtures::pathway(34601),
            paths.progress.facts(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.loss_resender.clone(),
            paths.cid_registry.remote.apply_dcid(),
        ),
    );
    path.validation.exempt().unwrap();
    let mut datagrams = [BytesMut::new()];
    let mut frames = Vec::new();
    let mut packets = [[None; 3]; MAX_BURST_PACKETS];
    let mut burst = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut packets);
    let count = burst.collect().await.unwrap();
    let pn = burst.packets[0][Epoch::Initial].unwrap().pn;
    path.disable();
    // No socket is registered: successful cancellation must avoid UDP submission.
    burst.submit(count).await.unwrap();
    assert!(burst.packets.iter().flatten().all(Option::is_none));
    assert!(space.sent_journal.lock_guard().packet(pn).is_none());
    assert!(
        burst
            .poll_collect(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    path.enable();
    assert!(matches!(
        burst.poll_collect(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(1))
    ));
    let pn = burst.packets[0][Epoch::Initial].unwrap().pn;
    assert!(space.sent_journal.lock_guard().frames(pn).any(|frame| {
        matches!(frame, GuaranteedFrame::Crypto(frame) if frame.offset() == 0 && frame.len() == b"queued crypto".len() as u64)
    }));
    burst.cancel();
    task::cancel_waiters(&paths, &path);
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn retired_initial_is_discarded_before_polling_an_expired_pto() {
    let paths = crate::common::initial_paths(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let trackers = paths.loss_resender.clone();
    super::install_handshake(
        &paths,
        Arc::new(HandshakeSpace::new(
            Default::default(),
            ArcKeys::new(Arc::new(keys(false))),
            paths.progress.facts(),
        )),
    );
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            Pathway::new(
                "127.0.0.1:4400".parse::<EndpointAddr>().unwrap(),
                "127.0.0.1:5500".parse().unwrap(),
            ),
            paths.progress.facts(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            trackers.clone(),
            paths.cid_registry.remote.apply_dcid(),
        ),
    );
    path.validation.exempt().unwrap();
    paths.progress.on_path_selected(&paths, &path);
    path.cc
        .on_pkt_sent(Epoch::Initial, 0, true, 1200, true, None);
    tokio::time::advance(Duration::from_secs(10)).await;
    paths.progress.on_handshake_sent();
    assert_eq!(paths.spaces.read_guard().offset(), Epoch::Handshake as u64);
    assert_eq!(trackers.read_guard().offset(), Epoch::Handshake as u64);
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
    let paths = crate::common::initial_paths_with_timeouts(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
        Duration::ZERO,
        Duration::ZERO,
        crate::common::handshake_facts(Role::Client, false),
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
        paths.progress.facts(),
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
    let trackers = paths.loss_resender.clone();
    super::install_handshake(&paths, handshake);
    let pathway = Pathway::new(
        EndpointAddr::direct("127.0.0.1:31001".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:31002".parse().unwrap()),
    );
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            pathway,
            paths.progress.facts(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            trackers.clone(),
            paths.cid_registry.remote.apply_dcid(),
        ),
    );
    path.validation.exempt().unwrap();
    paths.progress.on_path_selected(&paths, &path);

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
async fn crypto_replays_until_ack_or_path_selection() {
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
                    super::install_handshake(
                        &paths,
                        Arc::new(HandshakeSpace::new(
                            Default::default(),
                            crate::common::initial_space(&paths.spaces).keys.clone(),
                            paths.progress.facts(),
                        )),
                    );
                }
                let path = crate::common::registered_path(
                    &paths,
                    Path::new(
                        Pathway::new(
                            EndpointAddr::direct("127.0.0.1:35001".parse().unwrap()),
                            EndpointAddr::direct("127.0.0.1:35002".parse().unwrap()),
                        ),
                        paths.progress.facts(),
                        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                        paths.loss_resender.clone(),
                        paths.cid_registry.remote.apply_dcid(),
                    ),
                );
                path.validation.enter_validated().unwrap();
                let competitor = crate::common::registered_path(
                    &paths,
                    Path::new(
                        Pathway::new(
                            EndpointAddr::direct("127.0.0.1:35001".parse().unwrap()),
                            EndpointAddr::direct("127.0.0.1:35003".parse().unwrap()),
                        ),
                        paths.progress.facts(),
                        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                        paths.loss_resender.clone(),
                        paths.cid_registry.remote.apply_dcid(),
                    ),
                );
                {
                    let mut entries = paths.entries.lock().unwrap();
                    entries.insert(path.pathway, path.clone());
                    entries.insert(competitor.pathway, competitor.clone());
                }
                if selected != u8::MAX {
                    paths.progress.on_initial_received(crate::common::cid_value(
                        &paths.cid_registry.remote.apply_dcid(),
                    ));
                }
                match selected {
                    0 => {
                        paths.progress.on_path_selected(&paths, &competitor);
                    }
                    1 => {
                        paths.progress.on_path_selected(&paths, &path);
                    }
                    2 => {
                        paths.progress.on_path_selected(&paths, &path);
                        paths.progress.facts().on_handshake_done();
                        paths.progress.on_initial_received(crate::common::cid_value(
                            &paths.cid_registry.remote.apply_dcid(),
                        ));
                        paths.cid_registry.remote.upgrade();
                        for path in paths.entries.lock().unwrap().values() {
                            path.dcid.upgrade();
                        }
                    }
                    _ => {}
                }
                let mut datagrams = [BytesMut::with_capacity(1200)];
                let mut frames = Vec::new();
                let mut pns = [[None; 3]; MAX_BURST_PACKETS];
                for attempt in 0..4 {
                    let result = collect(Burst::new(
                        &paths,
                        &path,
                        &mut datagrams,
                        &mut frames,
                        &mut pns,
                    ))
                    .now_or_never();
                    if (selected == u8::MAX && attempt < 3)
                        || (matches!(selected, 1 | 2) && attempt == 0)
                    {
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
                    if selected != 0 && attempt == 1 {
                        crate::common::initial_space(&paths.spaces)
                            .crypto
                            .outgoing()
                            .on_data_acked(&qbase::frame::CryptoFrame::new(
                                0u32.into(),
                                1u32.into(),
                            ));
                    }
                    assert!(frames.is_empty());
                }
                task::cancel_waiters(&paths, &path);
                paths.retire_all();
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
        let trackers = paths.loss_resender.clone();
        if epoch == Epoch::Handshake {
            let handshake = Arc::new(HandshakeSpace::new(
                Default::default(),
                ArcKeys::new(Arc::new(keys(true))),
                paths.progress.facts(),
            ));
            super::install_handshake(&paths, handshake.clone());
            space.retire();
            space = Arc::new(handshake.0.clone());
        }
        let path = crate::common::registered_path(
            &paths,
            Path::new(
                Pathway::new(
                    EndpointAddr::direct("127.0.0.1:33001".parse().unwrap()),
                    EndpointAddr::direct("127.0.0.1:33002".parse().unwrap()),
                ),
                paths.progress.facts(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                trackers.clone(),
                paths.cid_registry.remote.apply_dcid(),
            ),
        );
        path.validation.enter_validated().unwrap();
        paths.progress.on_path_selected(&paths, &path);
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

pub(super) fn data_spaces(role: Role, defer: Duration) -> (Arc<Paths>, super::DataFixture) {
    use qbase::param::{ArcParameters, ClientParameters, ServerParameters};
    let facts = crate::common::handshake_facts(role, false);
    let paths = crate::common::initial_paths_with_timeouts(
        role,
        ConnectionId::from_slice(b"server00"),
        ConnectionId::from_slice(if role == Role::Server {
            b"client00"
        } else {
            b"original"
        }),
        keys(true),
        Duration::ZERO,
        defer,
        facts.clone(),
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
    paths
        .cid_registry
        .remote
        .set_limit(parameters.local(ParameterId::ActiveConnectionIdLimit));
    paths
        .progress
        .on_initial_received(parameters.remote(ParameterId::InitialSourceConnectionId));
    let handshake = Arc::new(HandshakeSpace::new(
        Default::default(),
        ArcKeys::new(Arc::new(keys(true))),
        facts.clone(),
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
        Default::default(),
    );
    terminator.register(Arc::new(streams.clone()));
    let data = Arc::new(qtransport::space::DataSpace::new(
        Default::default(),
        qtransport::keys::ArcOneRttKeys::from(server_one_rtt_keys()),
        streams,
        reliable_frames.clone(),
        parameters.local::<u64>(qbase::param::ParameterId::AckDelayExponent) as u32,
        parameters.remote::<u64>(qbase::param::ParameterId::AckDelayExponent) as u32,
        facts,
    ));
    terminator.register(Arc::new(data.crypto.clone()));
    let concrete = super::SpaceFixture {
        initial: crate::common::initial_space(&paths.spaces),
        handshake,
        data,
    };
    (
        paths.clone(),
        super::DataFixture {
            paths,
            parameters,
            spaces: concrete,
        },
    )
}

#[tokio::test]
async fn space_installation_preserves_cid_cleanup_and_termination() {
    let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
    let cid_registry = paths.cid_registry.clone();
    let scid = cid_registry.local.initial_scid();
    let dcid = cid_registry.remote.apply_dcid();
    assert!(scid.is_some());
    let terminator = paths.terminator.clone();
    super::install_handshake(&paths, mature.spaces.handshake.clone());
    assert_eq!(paths.cid_registry.local.initial_scid(), scid);
    assert_eq!(crate::common::cid_value(&dcid), mature.peer_cid());
    super::install_data(&paths, &mature);
    assert_eq!(paths.cid_registry.local.initial_scid(), scid);
    assert_eq!(
        crate::common::cid_value(&paths.cid_registry.remote.apply_dcid()),
        mature.peer_cid()
    );

    cid_registry.local.clear();
    assert!(paths.cid_registry.local.initial_scid().is_none());
    terminator.terminate();
    let error = terminator.now_or_never().unwrap();
    assert_eq!(paths.terminator.clone().now_or_never(), Some(error));
}

#[tokio::test]
async fn publishing_prequeued_spaces_does_not_wake_paths_and_activation_resumes_sending() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    for epoch in [Epoch::Handshake, Epoch::Data] {
        let (paths, data) = data_spaces(Role::Server, Duration::ZERO);
        if epoch == Epoch::Data {
            assert!(
                paths
                    .progress
                    .install_handshake(data.spaces.handshake.clone())
            );
        }
        let path = crate::common::registered_path(
            &paths,
            Path::new(
                crate::common::path_fixtures::pathway(34501),
                paths.progress.facts(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.loss_resender.clone(),
                paths.cid_registry.remote.apply_dcid(),
            ),
        );
        let other = crate::common::registered_path(
            &paths,
            Path::new(
                crate::common::path_fixtures::pathway(34502),
                paths.progress.facts(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.loss_resender.clone(),
                paths.cid_registry.remote.apply_dcid(),
            ),
        );
        path.validation.enter_validated().unwrap();
        paths.progress.on_path_selected(&paths, &path);
        path.disable();
        let counter = Arc::new(Counter::default());
        let other_counter = Arc::new(Counter::default());
        let waker = Waker::from(counter.clone());
        other.send_waker.register(&Waker::from(other_counter.clone()));
        let mut cx = Context::from_waker(&waker);
        let mut datagrams = [BytesMut::new()];
        let mut frames = Vec::new();
        let mut packets = [[None; 3]; MAX_BURST_PACKETS];
        let mut burst = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut packets);
        assert!(burst.poll_collect(&mut cx).is_pending());
        let before = counter.0.load(Ordering::Relaxed);
        if epoch == Epoch::Handshake {
            data.spaces
                .handshake
                .crypto
                .writer()
                .write_all(b"handshake")
                .await
                .unwrap();
        } else {
            data.spaces
                .data
                .crypto
                .writer()
                .write_all(b"data")
                .await
                .unwrap();
        }
        assert_eq!(counter.0.load(Ordering::Relaxed), before);
        assert!(burst.poll_collect(&mut cx).is_pending());
        if epoch == Epoch::Handshake {
            assert!(
                paths
                    .progress
                    .install_handshake(data.spaces.handshake.clone())
            );
        } else {
            paths.progress.install_data(data.spaces.data.clone());
        }
        assert_eq!(counter.0.load(Ordering::Relaxed), before);
        assert_eq!(other_counter.0.load(Ordering::Relaxed), 0);
        path.enable();
        assert!(counter.0.load(Ordering::Relaxed) > before);
        assert_eq!(other_counter.0.load(Ordering::Relaxed), 0);
        assert!(matches!(burst.poll_collect(&mut cx), Poll::Ready(Ok(n)) if n > 0));
        assert!(burst.packets[0][epoch].is_some());
        burst.cancel();
        paths.retire_all();
    }
}

#[tokio::test(start_paused = true)]
async fn existing_path_recovers_newly_installed_spaces() {
    let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            Pathway::new(
                EndpointAddr::direct("127.0.0.1:34101".parse().unwrap()),
                EndpointAddr::direct("127.0.0.1:34102".parse().unwrap()),
            ),
            paths.progress.facts(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.loss_resender.clone(),
            paths.cid_registry.remote.apply_dcid(),
        ),
    );
    path.validation.enter_validated().unwrap();
    paths.progress.on_path_selected(&paths, &path);
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::new();
    let mut pns = [[None; 3]; MAX_BURST_PACKETS];

    for epoch in [Epoch::Handshake, Epoch::Data] {
        let (crypto, journal) = if epoch == Epoch::Handshake {
            super::install_handshake(&paths, mature.spaces.handshake.clone());
            (
                &mature.spaces.handshake.crypto,
                &mature.spaces.handshake.sent_journal,
            )
        } else {
            super::install_data(&paths, &mature);
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

    let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
    let remote = &paths.cid_registry.remote;
    let next = ConnectionId::from_slice(b"client01");
    remote
        .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
        .unwrap();
    let make_path = |port| {
        let path = crate::common::registered_path(
            &paths,
            Path::new(
                Pathway::new(
                    EndpointAddr::direct(([127, 0, 0, 1], port).into()),
                    EndpointAddr::direct("127.0.0.1:34300".parse().unwrap()),
                ),
                paths.progress.facts(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.loss_resender.clone(),
                paths.cid_registry.remote.apply_dcid(),
            ),
        );
        paths
            .entries
            .lock()
            .unwrap()
            .insert(path.pathway, path.clone());
        path
    };
    let other = make_path(34301);
    let selected = make_path(34302);
    paths.progress.on_path_selected(&paths, &selected);
    assert!(matches!(super::borrow(&selected), Poll::Ready(Some(cid)) if cid == mature.peer_cid()));
    super::install_data(&paths, &mature);
    assert!(matches!(super::borrow(&selected), Poll::Ready(Some(cid)) if cid == mature.peer_cid()));
    assert!(super::borrow(&other).is_pending());
    assert_eq!(super::selection(&paths, &other), 0);
    super::confirm_handshake(&paths);
    assert_eq!(super::selection(&paths, &selected), 2);
    assert_eq!(super::selection(&paths, &other), 2);
    assert!(matches!(super::borrow(&other), Poll::Ready(Some(cid)) if cid == next));
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

    let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
    let remote = &paths.cid_registry.remote;
    let initial_cell = remote.apply_dcid();
    initial_cell.upgrade();
    super::install_data(&paths, &mature);
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            Pathway::new(
                EndpointAddr::direct("127.0.0.1:34201".parse().unwrap()),
                EndpointAddr::direct("127.0.0.1:34202".parse().unwrap()),
            ),
            paths.progress.facts(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.loss_resender.clone(),
            paths.cid_registry.remote.apply_dcid(),
        ),
    );
    paths.progress.on_path_selected(&paths, &path);
    path.validation.enter_validated().unwrap();
    // The selected sender waits if the available CID was already consumed.
    assert!(!paths.progress.facts().is_handshake_done() && path.dcid.is_allocated());
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
    assert_eq!(borrowed, next);
    path.dcid.refresh();
    assert!(matches!(super::borrow(&path),
        Poll::Ready(Some(cid)) if cid == replacement));

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
    let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
    for crypto in [
        &mature.spaces.initial.crypto,
        &mature.spaces.handshake.crypto,
        &mature.spaces.data.crypto,
    ] {
        crypto.writer().write_all(b"crypto").await.unwrap();
    }
    super::install_data(&paths, &mature);
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            Pathway::new(
                EndpointAddr::direct("127.0.0.1:34001".parse().unwrap()),
                EndpointAddr::direct("127.0.0.1:34002".parse().unwrap()),
            ),
            paths.progress.facts(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.loss_resender.clone(),
            paths.cid_registry.remote.apply_dcid(),
        ),
    );
    path.validation.enter_validated().unwrap();
    paths.progress.on_path_selected(&paths, &path);
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
    paths.progress.facts().on_handshake_done();
    paths.cid_registry.remote.upgrade();
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
    let waiting_path = crate::common::registered_path(
        &paths,
        Path::new(
            Pathway::new(
                EndpointAddr::direct("127.0.0.1:34003".parse().unwrap()),
                EndpointAddr::direct("127.0.0.1:34002".parse().unwrap()),
            ),
            paths.progress.facts(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.loss_resender.clone(),
            paths.cid_registry.remote.apply_dcid(),
        ),
    );
    waiting_path.validation.enter_validated().unwrap();
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
    waiting_path.close();
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
    let error = QuicError::with_default_fty(ErrorKind::Internal, "connection failed");
    paths.terminator.close(
        crate::CloseReason::Internal(error.clone()),
        paths.closing_pto(),
    );
    mature.spaces.data.crypto.on_error(&error.into());
    // Closing removes queued stream output; only the close response remains sendable.
    assert_eq!(mature.spaces.data.streams.fresh_bytes(), 0);
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
        let (paths, mature) = data_spaces(Role::Server, Duration::from_secs(60));
        if epoch == Epoch::Handshake {
            super::install_handshake(&paths, mature.spaces.handshake.clone());
            mature.spaces.initial.retire();
        } else if epoch == Epoch::Data {
            super::install_data(&paths, &mature);
        }
        let path = crate::common::registered_path(
            &paths,
            Path::new(
                Pathway::new(
                    "127.0.0.1:30001".parse::<EndpointAddr>().unwrap(),
                    "127.0.0.1:30002".parse().unwrap(),
                ),
                paths.progress.facts(),
                ArcHeartbeat::new(Duration::from_secs(60), Duration::ZERO),
                paths.loss_resender.clone(),
                paths.cid_registry.remote.apply_dcid(),
            ),
        );
        path.validation.enter_validated().unwrap();
        paths.progress.on_path_selected(&paths, &path);
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
        path.close();
    }
}

#[tokio::test]
async fn trackers_follow_space_creation_and_retirement_in_epoch_order() {
    for role in [Role::Client, Role::Server] {
        for retire_before_handshake in [false, true] {
            let (paths, mature) = data_spaces(role, Duration::ZERO);
            let selected = crate::common::registered_path(
                &paths,
                Path::new(
                    Pathway::new(
                        EndpointAddr::direct("127.0.0.1:35201".parse().unwrap()),
                        EndpointAddr::direct("127.0.0.1:35202".parse().unwrap()),
                    ),
                    paths.progress.facts(),
                    ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                    paths.loss_resender.clone(),
                    paths.cid_registry.remote.apply_dcid(),
                ),
            );
            paths.progress.on_path_selected(&paths, &selected);
            let trackers = paths.loss_resender.clone();
            let epochs = || {
                trackers
                    .read_guard()
                    .enumerate()
                    .map(|(epoch, _)| epoch)
                    .collect::<Vec<_>>()
            };
            let retire_initial = || {
                if role == Role::Client {
                    paths.progress.on_handshake_sent();
                } else {
                    paths.progress.on_handshake_received();
                }
            };
            assert_eq!(epochs(), [0]);
            if retire_before_handshake {
                retire_initial();
                retire_initial();
                assert!(epochs().is_empty());
                assert!(mature.spaces.initial.keys.get().is_err());
            }
            super::install_handshake(&paths, mature.spaces.handshake.clone());
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

            super::install_data(&paths, &mature);
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
async fn amplification_unblocks_pto_when_its_probe_fits() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    for (epoch, validated) in Epoch::EPOCHS
        .into_iter()
        .flat_map(|epoch| [(epoch, false), (epoch, true)])
    {
        let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
        match epoch {
            Epoch::Initial => {}
            Epoch::Handshake => super::install_handshake(&paths, mature.spaces.handshake.clone()),
            Epoch::Data => super::install_data(&paths, &mature),
        }
        let path = crate::common::registered_path(
            &paths,
            Path::new(
                Pathway::new(
                    EndpointAddr::direct("127.0.0.1:35101".parse().unwrap()),
                    EndpointAddr::direct("127.0.0.1:35102".parse().unwrap()),
                ),
                paths.progress.facts(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.loss_resender.clone(),
                paths.cid_registry.remote.apply_dcid(),
            ),
        );
        paths.progress.on_path_selected(&paths, &path);
        if epoch == Epoch::Data {
            super::confirm_handshake(&paths);
            // Withdraw the handshake path's address validation for this credit test.
            path.validation.revalidate().unwrap();
        }
        path.validation.on_received(400);
        path.validation.on_sent(1200);
        path.cc.on_pkt_sent(epoch, 0, true, 1200, true, None);
        let base = path.cc.get_pto(epoch);
        let mut datagrams = [BytesMut::with_capacity(1200)];
        let mut frames = Vec::new();
        let mut pns: BurstPackets = [[None; 3]; MAX_BURST_PACKETS];
        let mut burst = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut pns);
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(burst.poll_collect(&mut cx).is_pending());
        tokio::time::advance(base * 2).await;
        assert!(burst.poll_collect(&mut cx).is_pending());
        assert_eq!(path.cc.get_pto(epoch), base);

        // Positive credit can still be too small even for a PING packet.
        let before = counter.0.load(Ordering::Relaxed);
        path.validation.on_received(1);
        path.send_waker.wake_all();
        assert!(counter.0.load(Ordering::Relaxed) > before);
        assert!(burst.poll_collect(&mut cx).is_pending());
        assert_eq!(path.cc.need_send_ack_eliciting(epoch), 0);
        assert_eq!(path.cc.get_pto(epoch), base);

        // Handshake and 1-RTT probes fit well below 1200 bytes.
        let before = counter.0.load(Ordering::Relaxed);
        if validated {
            path.validation.enter_validated().unwrap();
        } else {
            path.validation.on_received(20);
        }
        path.send_waker.wake_all();
        assert!(counter.0.load(Ordering::Relaxed) > before);
        if epoch == Epoch::Initial && !validated {
            assert!(burst.poll_collect(&mut cx).is_pending());
            assert_eq!(path.cc.need_send_ack_eliciting(epoch), 0);
            path.validation.on_received(379);
        }
        assert!(
            matches!(burst.poll_collect(&mut cx), Poll::Ready(Ok(1))),
            "{epoch:?} PTO did not resume when its probe fitted"
        );
        let meta = burst.packets[0][epoch].unwrap();
        assert!(meta.content.is_ack_eliciting());
        assert_eq!(path.cc.need_send_ack_eliciting(epoch), 1);
        assert!(path.cc.get_pto(epoch) > base);
        if epoch == Epoch::Initial {
            assert_eq!(burst.datagrams[0].len(), 1200);
        } else if !validated {
            assert!(burst.datagrams[0].len() <= 63);
        }
        burst.cancel();
        task::cancel_waiters(&paths, &path);
        path.close();
        paths.terminator.terminate();
    }
}

#[tokio::test(start_paused = true)]
async fn ack_only_submission_blocks_pto_when_amplification_credit_cannot_fit_a_probe() {
    use qprotocol::{QuicProtocol, UdpSocket};

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    QuicProtocol::global()
        .register(EndpointAddr::direct(socket.local_addr().unwrap()), &socket)
        .unwrap();
    let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
    super::install_handshake(&paths, mature.spaces.handshake.clone());
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            Pathway::new(
                EndpointAddr::direct(socket.local_addr().unwrap()),
                EndpointAddr::direct(peer.local_addr().unwrap()),
            ),
            paths.progress.facts(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.loss_resender.clone(),
            paths.cid_registry.remote.apply_dcid(),
        ),
    );
    paths.progress.on_path_selected(&paths, &path);
    path.validation.on_received(20);
    path.cc
        .on_pkt_sent(Epoch::Handshake, 0, true, 1200, true, None);
    mature
        .spaces
        .handshake
        .rcvd_journal
        .on_rcvd_pn(42, true, path.cc.pto_base(Epoch::Handshake));
    path.cc.on_pkt_rcvd(Epoch::Handshake, 42, true);
    let base = path.cc.get_pto(Epoch::Handshake);
    let mut datagrams = [BytesMut::with_capacity(1200)];
    let mut frames = Vec::new();
    let mut pns: BurstPackets = [[None; 3]; MAX_BURST_PACKETS];
    let mut burst = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut pns);
    assert!(matches!(
        burst.poll_collect(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(1))
    ));
    let meta = burst.packets[0][Epoch::Handshake].unwrap();
    assert!(!meta.content.is_ack_eliciting());
    assert!(!meta.in_flight);
    assert!(meta.ack.is_some());
    burst.submit(1).await.unwrap();
    assert!(crate::common::path_credit(&path) > 0);
    tokio::time::advance(base * 2).await;
    // No subsequent budget poll: submission must already have told CC it is blocked.
    path.cc.do_tick().unwrap();
    assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Handshake), 0);
    assert_eq!(path.cc.get_pto(Epoch::Handshake), base);
    path.validation.enter_validated().unwrap();
    assert!(matches!(
        burst.poll_collect(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(1))
    ));
    assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Handshake), 1);
    burst.cancel();
    task::cancel_waiters(&paths, &path);
    path.close();
    paths.terminator.terminate();
    QuicProtocol::global().unregister(socket.local_addr().unwrap());
}

#[tokio::test(start_paused = true)]
async fn path_validation_respects_small_amplification_credit() {
    use qbase::frame::{PathChallengeFrame, io::ReceiveFrame};

    for received in [0, 128, 399, 400] {
        for reply in [false, true] {
            let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
            super::install_data(&paths, &mature);
            let path = crate::common::registered_path(
                &paths,
                Path::new(
                    Pathway::new(
                        EndpointAddr::direct("127.0.0.1:35101".parse().unwrap()),
                        EndpointAddr::direct("127.0.0.1:35102".parse().unwrap()),
                    ),
                    paths.progress.facts(),
                    ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                    paths.loss_resender.clone(),
                    paths.cid_registry.remote.apply_dcid(),
                ),
            );
            paths.progress.on_path_selected(&paths, &path);
            paths.progress.facts().on_handshake_done();
            path.validation.on_received(received);
            let challenge = PathChallengeFrame::from_slice(&[7; 8]);
            if reply {
                path.validation.recv_frame(challenge).unwrap();
            } else {
                path.validation.challenge(challenge).unwrap();
            }
            let credit = crate::common::path_credit(&path);
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
                    super::take_validation_frames(&path).is_empty(),
                    "validation frame was not encoded"
                );
            }
            assert!(!path.validation.is_validated());
            path.close();
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
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            Pathway::new(local, EndpointAddr::direct(peer.local_addr().unwrap())),
            paths.progress.facts(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.loss_resender.clone(),
            paths.cid_registry.remote.apply_dcid(),
        ),
    );
    path.validation.exempt().unwrap();
    paths.progress.on_initial_received(crate::common::cid_value(
        &paths.cid_registry.remote.apply_dcid(),
    ));
    paths.progress.on_path_selected(&paths, &path);

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
async fn retired_path_rejects_a_collected_burst_before_udp_submission() {
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
    space.crypto.writer().write_all(b"pending").await.unwrap();
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            Pathway::new(local, EndpointAddr::direct(peer.local_addr().unwrap())),
            paths.progress.facts(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.loss_resender.clone(),
            paths.cid_registry.remote.apply_dcid(),
        ),
    );
    path.validation.exempt().unwrap();
    paths.progress.on_initial_received(crate::common::cid_value(
        &paths.cid_registry.remote.apply_dcid(),
    ));
    paths.progress.on_path_selected(&paths, &path);
    let mut datagrams = [BytesMut::with_capacity(1200)];
    let mut frames = Vec::new();
    let mut packets = [[None; 3]; MAX_BURST_PACKETS];
    let mut burst = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut packets);
    let count = burst.collect().await.unwrap();
    let pn = burst.packets[0][Epoch::Initial].unwrap().pn;
    path.close();

    let error = burst.submit(count).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NoViablePath);
    assert!(matches!(error, crate::Error::Quic(error) if error.reason() == "Cancelled"));
    assert!(burst.packets[0][Epoch::Initial].is_some());
    burst.cancel();
    assert!(space.sent_journal.lock_guard().packet(pn).is_none());
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
        paths.progress.facts(),
    ));
    initial.crypto.writer().write_all(b"initial").await.unwrap();
    handshake
        .crypto
        .writer()
        .write_all(b"handshake")
        .await
        .unwrap();
    super::install_handshake(&paths, handshake.clone());
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            Pathway::new(local, EndpointAddr::direct(peer.local_addr().unwrap())),
            paths.progress.facts(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.loss_resender.clone(),
            paths.cid_registry.remote.apply_dcid(),
        ),
    );
    path.validation.on_received(1200);
    paths.progress.on_path_selected(&paths, &path);
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
    assert_eq!(crate::common::path_credit(&path), 3600);
    let delays =
        [Epoch::Initial, Epoch::Handshake].map(|epoch| path.cc.retransmit_and_expire_time(epoch).0);
    burst.submit(1).await.unwrap();
    let submitted_at = Instant::now();
    assert!(burst.packets[0].iter().all(Option::is_none));
    assert_eq!(crate::common::path_credit(&path), 2400);
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
async fn sender_transmits_with_the_old_cid_until_its_replacement_arrives() {
    use qbase::{
        frame::{NewConnectionIdFrame, io::ReceiveFrame},
        net::route::Line,
        packet::GetDcid,
    };
    use qprotocol::{QuicProtocol, UdpSocket};

    async fn received_dcid(peer: &UdpSocket) -> ConnectionId {
        let mut received = [BytesMut::zeroed(1500)];
        let mut lines = [Line::default()];
        tokio::time::timeout(
            Duration::from_secs(1),
            peer.receive(&mut received, &mut lines),
        )
        .await
        .unwrap()
        .unwrap();
        received[0].truncate(lines[0].seg_size as usize);
        let ParsedPacket::Data(packet) = PacketReader::new(received[0].clone(), 8)
            .next()
            .unwrap()
            .unwrap()
        else {
            panic!("expected an encrypted Data packet");
        };
        *packet.header.dcid()
    }

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let local = EndpointAddr::direct(socket.local_addr().unwrap());
    QuicProtocol::global().register(local, &socket).unwrap();
    let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
    let make_path = |port| {
        let path = crate::common::registered_path(
            &paths,
            Path::new(
                Pathway::new(local, EndpointAddr::direct(([127, 0, 0, 1], port).into())),
                paths.progress.facts(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.loss_resender.clone(),
                paths.cid_registry.remote.apply_dcid(),
            ),
        );
        path.validation.enter_validated().unwrap();
        path
    };
    let selected = make_path(9);
    let other = make_path(peer.local_addr().unwrap().port());
    paths.progress.on_path_selected(&paths, &selected);
    super::install_data(&paths, &mature);
    super::confirm_handshake(&paths);
    let remote = &paths.cid_registry.remote;
    let old = ConnectionId::from_slice(b"client01");
    remote
        .recv_frame(NewConnectionIdFrame::new(old, 1u32.into(), 0u32.into()))
        .unwrap();
    assert!(matches!(super::borrow(&other), Poll::Ready(Some(cid)) if cid == old));
    // Only the selected path gets CID 2. This path must keep sending with CID 1.
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
        .write_all(b"old CID still sends")
        .await
        .unwrap();
    let mut datagrams = [BytesMut::new()];
    let mut frames = Vec::new();
    let mut packets = [[None; 3]; MAX_BURST_PACKETS];
    let mut burst = Burst::new(&paths, &other, &mut datagrams, &mut frames, &mut packets);
    let count = burst
        .collect()
        .now_or_never()
        .expect("missing replacement must not suspend this sender")
        .unwrap();
    assert_eq!(burst.dcid, Some(old));
    burst.submit(count).await.unwrap();
    assert_eq!(received_dcid(&peer).await, old);
    assert!(other.validation.is_validated());

    let replacement = ConnectionId::from_slice(b"client03");
    remote
        .recv_frame(NewConnectionIdFrame::new(
            replacement,
            3u32.into(),
            2u32.into(),
        ))
        .unwrap();
    mature
        .spaces
        .data
        .crypto
        .writer()
        .write_all(b"replacement CID sends")
        .await
        .unwrap();
    let count = burst.collect().now_or_never().unwrap().unwrap();
    assert_eq!(burst.dcid, Some(replacement));
    burst.submit(count).await.unwrap();
    assert_eq!(received_dcid(&peer).await, replacement);
    burst.cancel();
    other.close();
    assert!(
        matches!(burst.poll_collect(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(error))
        if error.kind() == ErrorKind::NoViablePath && error.to_string().contains("path CID binding retired"))
    );
    paths.retire_all();
    QuicProtocol::global().unregister(socket.local_addr().unwrap());
}
