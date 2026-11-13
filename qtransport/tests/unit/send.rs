use std::{
    future::Future,
    io,
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
    packet::{DataHeader, LongHeaderBuilder, Packet as ParsedPacket, PacketReader, assemble::Metadata, long},
    param::ParameterId,
    role::Role,
    time::heartbeat::ArcHeartbeat,
};
use qcongestion::Transport as _;
use qtransport::{keys::ArcKeys, packet::CipherPacket, path::Path, space::HandshakeSpace};
use tokio::io::AsyncWriteExt;

use crate::{
    Paths,
    common::{self, initial_keys as keys, opening::PacketOpen as _, packet_metadata},
    path::Datagram,
};

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
                paths.cid_registry.remote.apply_dcid(),
                crate::common::path_fixtures::pathway(34601),
                paths.progress.facts(),
                paths.spaces.clone(),
                paths.resenders.clone(),
                ArcHeartbeat::new(Duration::from_secs(60), Duration::ZERO),
                paths.terminator.clone(),
                paths.progress.clone(),
            ),
        );
        path.validation.grant().unwrap();
        path.disable();
        let space = paths.spaces.get(epoch).unwrap();
        for crypto in [&data.spaces.initial.crypto, &data.spaces.handshake.crypto, &data.spaces.data.crypto] {
            crypto.writer().write_all(b"queued crypto").await.unwrap();
        }
        let (_, mut writer) = data.spaces.data.streams.open_uni().await.unwrap().unwrap();
        writer.write_all(b"queued stream").await.unwrap();
        data.spaces.data.reliable_frames.send_frame([qbase::frame::StreamCtlFrame::from(MaxDataFrame::new(1234u32.into()))]);
        crate::common::revalidate(&path);
        path.validation.on_received(1000);
        path.validation.challenge(PathChallengeFrame::from_slice(&[7; 8])).unwrap();
        for pn in [41, 42] {
            space.rcvd_journal().on_rcvd_pn(pn, true, Duration::from_secs(1));
            path.cc.on_pkt_rcvd(epoch, pn, true);
        }
        let mut datagrams = [Datagram::default()];
        let mut frames = Vec::new();
        let mut cx = Context::from_waker(Waker::noop());
        let result = poll_collect(&path, &mut datagrams, &mut frames, &mut cx);
        assert!(matches!(result, Poll::Ready(Ok(1))), "{epoch:?}: {result:?}");
        let meta = datagram_metadata(&datagrams[0], epoch).unwrap();
        assert_eq!(meta.ack, Some(42));
        assert_eq!(meta.content, PacketContent::NonAckEliciting);
        assert!(space.sent_journal().lock_guard().frames(meta.pn).next().is_none());
        assert_eq!(data.spaces.data.streams.fresh_bytes(), b"queued stream".len());
        datagrams[0].packets.retain(|meta| meta.epoch() != epoch);
        space.on_sent(meta.pn, false, Duration::from_secs(1), Duration::from_secs(3));
        path.cc.on_pkt_sent(epoch, meta.pn, false, meta.pktlen, false, Some(42));
        path.refresh(&mut datagrams, &mut frames);
        path.heartbeat.on_rcvd_at(PacketContent::EffectivePayload, tokio::time::Instant::now()).unwrap();
        tokio::time::advance(Duration::from_secs(20)).await;
        path.cc.do_tick().unwrap();
        assert!(matches!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx), Poll::Ready(Ok(1))));
        for meta in metadata(&datagrams) {
            assert_ne!(meta.content, PacketContent::EffectivePayload);
        }
        assert!(metadata(&datagrams).any(|meta| meta.content == PacketContent::JustPing));
        path.refresh(&mut datagrams, &mut frames);
        path.enable();
        assert!(matches!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx), Poll::Ready(Ok(1))));
        assert!(metadata(&datagrams).any(|meta| meta.content == PacketContent::EffectivePayload));
        assert!(data.spaces.data.streams.fresh_bytes() < b"queued stream".len());
        path.refresh(&mut datagrams, &mut frames);
        path.disable();
        paths
            .terminator
            .close(crate::CloseReason::Internal(QuicError::with_default_fty(ErrorKind::Internal, "closed")), paths.closing_pto());
        assert!(matches!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx), Poll::Ready(Ok(1))));
        assert!(metadata(&datagrams).all(|meta| meta.content == PacketContent::NonAckEliciting));
        path.refresh(&mut datagrams, &mut frames);
        paths.del_path(&path);
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
    space.crypto.writer().write_all(b"queued crypto").await.unwrap();
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            paths.cid_registry.remote.apply_dcid(),
            crate::common::path_fixtures::pathway(34601),
            paths.progress.facts(),
            paths.spaces.clone(),
            paths.resenders.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    path.validation.exempt().unwrap();
    let mut datagrams = [Datagram::default()];
    let mut frames = Vec::new();
    let (count, _) = path.collect(&mut datagrams, &mut frames).await.unwrap();
    let pn = datagram_metadata(&datagrams[0], Epoch::Initial).unwrap().pn;
    path.disable();
    // No socket is registered: successful cancellation must avoid UDP submission.
    path.send(&mut datagrams[..count], &paths.idle_timer()).await.unwrap();
    path.refresh(&mut datagrams, &mut frames);
    assert!(datagrams.iter().all(|datagram| datagram.packets.is_empty()));
    assert!(space.sent_journal.lock_guard().packet(pn).is_none());
    assert!(poll_collect(&path, &mut datagrams, &mut frames, &mut Context::from_waker(Waker::noop())).is_pending());
    path.enable();
    assert!(matches!(poll_collect(&path, &mut datagrams, &mut frames, &mut Context::from_waker(Waker::noop())), Poll::Ready(Ok(1))));
    let pn = datagram_metadata(&datagrams[0], Epoch::Initial).unwrap().pn;
    assert!(space.sent_journal.lock_guard().frames(pn).any(|frame| {
        matches!(frame, GuaranteedFrame::Crypto(frame) if frame.offset() == 0 && frame.len() == b"queued crypto".len() as u64)
    }));
    path.refresh(&mut datagrams, &mut frames);
    paths.del_path(&path);
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
    let trackers = paths.resenders.clone();
    super::install_handshake(
        &paths,
        Arc::new(HandshakeSpace::new(Default::default(), ArcKeys::new(Arc::new(keys(false))), paths.progress.facts())),
    );
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            paths.cid_registry.remote.apply_dcid(),
            Pathway::new("127.0.0.1:4400".parse::<EndpointAddr>().unwrap(), "127.0.0.1:5500".parse().unwrap()),
            paths.progress.facts(),
            paths.spaces.clone(),
            trackers.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    path.validation.exempt().unwrap();
    paths.progress.on_path_selected(&paths, &path);
    path.cc.on_pkt_sent(Epoch::Initial, 0, true, 1200, true, None);
    tokio::time::advance(Duration::from_secs(10)).await;
    paths.progress.on_handshake_sent();
    assert_eq!(crate::common::space_epochs(&paths.spaces)[0], Epoch::Handshake);
    assert_eq!(trackers.read_guard().offset(), Epoch::Handshake as u64);
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| Datagram::default());
    let mut frames = Vec::new();
    assert!(poll_collect(&path, &mut datagrams, &mut frames, &mut Context::from_waker(Waker::noop())).is_pending());
    assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Initial), 0);
    // While waiting for HANDSHAKE_DONE, an anti-deadlock probe must use live Handshake keys.
    tokio::time::advance(path.cc.pto_base(Epoch::Handshake)).await;
    path.cc.do_tick().unwrap();
    assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Initial), 0);
    assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Handshake), 1);
    assert!(matches!(poll_collect(&path, &mut datagrams, &mut frames, &mut Context::from_waker(Waker::noop())), Poll::Ready(Ok(1))));
    assert_eq!(pns_for(&datagrams, Epoch::Handshake).count(), 1);
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
    crate::common::initial_space(&paths.spaces).crypto.writer().write_all(&message).await.unwrap();
    let handshake = Arc::new(HandshakeSpace::new(Default::default(), ArcKeys::new(Arc::new(keys(false))), paths.progress.facts()));
    handshake.crypto.writer().write_all(b"handshake").await.unwrap();
    crate::common::initial_space(&paths.spaces).rcvd_journal.on_rcvd_pn(3, true, Duration::from_secs(1));
    handshake.rcvd_journal.on_rcvd_pn(7, true, Duration::from_secs(1));
    let trackers = paths.resenders.clone();
    super::install_handshake(&paths, handshake);
    let pathway =
        Pathway::new(EndpointAddr::direct("127.0.0.1:31001".parse().unwrap()), EndpointAddr::direct("127.0.0.1:31002".parse().unwrap()));
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            paths.cid_registry.remote.apply_dcid(),
            pathway,
            paths.progress.facts(),
            paths.spaces.clone(),
            trackers.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    path.validation.exempt().unwrap();
    paths.progress.on_path_selected(&paths, &path);

    path.cc.on_pkt_rcvd(Epoch::Initial, 3, true);
    path.cc.on_pkt_rcvd(Epoch::Handshake, 7, true);
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| Datagram::default());
    let mut frames = Vec::new();
    let (count, _) = path.collect(&mut datagrams, &mut frames).now_or_never().unwrap().unwrap();
    assert_eq!(count, 7);
    assert!(!pns_for(&datagrams, Epoch::Initial).next().is_none());
    assert_eq!(pns_for(&datagrams, Epoch::Handshake).count(), 1);
    for (epoch, largest) in [(Epoch::Initial, 3), (Epoch::Handshake, 7)] {
        assert_eq!(
            datagrams.iter().filter_map(|slots| datagram_metadata(slots, epoch).and_then(|meta| meta.ack)).collect::<Vec<_>>(),
            [largest],
            "each space sends its ACK only once per collection"
        );
    }
    assert!(frames.is_empty());
    let mut recovered = Vec::new();
    for (index, pn) in pns_for(&datagrams, Epoch::Initial) {
        let ParsedPacket::Data(parsed) = PacketReader::new(datagrams[index].bytes.clone(), 8).next().unwrap().unwrap() else {
            panic!()
        };
        let DataHeader::Long(long::DataHeader::Initial(header)) = parsed.header else {
            panic!()
        };
        let packet = CipherPacket::new(header, parsed.bytes, parsed.offset).open_long(&keys(true).opening, |_| Ok(pn)).unwrap().unwrap();
        for frame in FrameReader::new(
            packet.body(),
            qbase::packet::GetType::get_type(&LongHeaderBuilder::with_cid(Default::default(), Default::default()).initial(vec![])),
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
                crate::common::initial_space(&paths.spaces).crypto.writer().write_all(b"hello").await.unwrap();
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
                        paths.cid_registry.remote.apply_dcid(),
                        Pathway::new(
                            EndpointAddr::direct("127.0.0.1:35001".parse().unwrap()),
                            EndpointAddr::direct("127.0.0.1:35002".parse().unwrap()),
                        ),
                        paths.progress.facts(),
                        paths.spaces.clone(),
                        paths.resenders.clone(),
                        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                        paths.terminator.clone(),
                        paths.progress.clone(),
                    ),
                );
                path.validation.grant().unwrap();
                let competitor = crate::common::registered_path(
                    &paths,
                    Path::new(
                        paths.cid_registry.remote.apply_dcid(),
                        Pathway::new(
                            EndpointAddr::direct("127.0.0.1:35001".parse().unwrap()),
                            EndpointAddr::direct("127.0.0.1:35003".parse().unwrap()),
                        ),
                        paths.progress.facts(),
                        paths.spaces.clone(),
                        paths.resenders.clone(),
                        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                        paths.terminator.clone(),
                        paths.progress.clone(),
                    ),
                );
                {
                    let mut entries = paths.entries.lock().unwrap();
                    entries.insert(path.pathway, path.clone());
                    entries.insert(competitor.pathway, competitor.clone());
                }
                if selected != u8::MAX {
                    paths.progress.on_initial_received(crate::common::cid_value(&paths.cid_registry.remote.apply_dcid()));
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
                        paths.progress.on_initial_received(crate::common::cid_value(&paths.cid_registry.remote.apply_dcid()));
                        paths.cid_registry.remote.upgrade();
                        for path in paths.entries.lock().unwrap().values() {
                            path.dcid.upgrade();
                        }
                    }
                    _ => {}
                }
                let mut datagrams = [Datagram::default()];
                let mut frames = Vec::new();
                for attempt in 0..4 {
                    let result = path.collect(&mut datagrams, &mut frames).now_or_never();
                    if (selected == u8::MAX && attempt < 3) || (matches!(selected, 1 | 2) && attempt == 0) {
                        assert!(matches!(result, Some(Ok((1, _)))), "{role:?} {handshaking} {selected} {attempt}");
                        for slots in &mut datagrams {
                            slots.packets.retain(|meta| meta.epoch() != Epoch::Initial);
                        }
                    } else {
                        assert!(result.is_none(), "{role:?} {handshaking} {selected} {attempt}");
                        assert!(datagrams.iter().all(|datagram| datagram.packets.is_empty()));
                    }
                    if selected != 0 && attempt == 1 {
                        crate::common::initial_space(&paths.spaces)
                            .crypto
                            .outgoing()
                            .on_data_acked(&qbase::frame::CryptoFrame::new(0u32.into(), 1u32.into()));
                    }
                    assert!(frames.is_empty());
                }
                paths.del_path(&path);
                paths.retire_all();
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn closing_is_collected_before_failed_crypto_and_termination_leaves_no_data() {
    for epoch in [Epoch::Initial, Epoch::Handshake] {
        let paths = crate::common::initial_paths(
            Role::Server,
            ConnectionId::from_slice(b"server00"),
            ConnectionId::from_slice(b"original"),
            keys(true),
        );
        let terminator = paths.terminator.clone();
        let mut space = crate::common::initial_space(&paths.spaces);
        let trackers = paths.resenders.clone();
        if epoch == Epoch::Handshake {
            let handshake = Arc::new(HandshakeSpace::new(Default::default(), ArcKeys::new(Arc::new(keys(true))), paths.progress.facts()));
            super::install_handshake(&paths, handshake.clone());
            space.retire();
            space = Arc::new(handshake.0.clone());
        }
        let path = crate::common::registered_path(
            &paths,
            Path::new(
                paths.cid_registry.remote.apply_dcid(),
                Pathway::new(
                    EndpointAddr::direct("127.0.0.1:33001".parse().unwrap()),
                    EndpointAddr::direct("127.0.0.1:33002".parse().unwrap()),
                ),
                paths.progress.facts(),
                paths.spaces.clone(),
                trackers.clone(),
                ArcHeartbeat::new(Duration::from_secs(60), Duration::ZERO),
                paths.terminator.clone(),
                paths.progress.clone(),
            ),
        );
        path.validation.grant().unwrap();
        paths.progress.on_path_selected(&paths, &path);
        path.heartbeat.on_rcvd_at(qbase::packet::PacketContent::EffectivePayload, tokio::time::Instant::now()).unwrap();
        tokio::time::advance(Duration::from_secs(20)).await;
        let error = QuicError::with_default_fty(ErrorKind::Internal, "TLS failed");
        path.disable();
        terminator.close(crate::CloseReason::Internal(error.clone()), paths.closing_pto());
        space.crypto.on_error(&error.into());
        let mut datagrams = std::array::from_fn::<_, 8, _>(|_| Datagram::default());
        let mut frames = Vec::new();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx), Poll::Ready(Ok(1))));
        let pn = pns_for(&datagrams, epoch).next().unwrap().1;
        assert_eq!(space.sent_journal.lock_guard().frames(pn).count(), 0);
        let ParsedPacket::Data(packet) = PacketReader::new(datagrams[0].bytes.clone(), 8).next().unwrap().unwrap() else {
            panic!()
        };
        use qbase::packet::GetType;
        let ty = packet.get_type();
        let body = match packet.header {
            DataHeader::Long(long::DataHeader::Initial(header)) => {
                CipherPacket::new(header, packet.bytes, packet.offset).open_long(&keys(false).opening, |_| Ok(pn)).unwrap().unwrap().body()
            }
            DataHeader::Long(long::DataHeader::Handshake(header)) => {
                CipherPacket::new(header, packet.bytes, packet.offset).open_long(&keys(false).opening, |_| Ok(pn)).unwrap().unwrap().body()
            }
            _ => panic!(),
        };
        let decoded = FrameReader::new(body, ty).collect::<Result<Vec<_>, _>>().unwrap();
        assert!(decoded.iter().any(|(frame, _)| matches!(frame, Frame::Close(_))));
        assert!(decoded.iter().all(|(frame, _)| matches!(frame, Frame::Close(_) | Frame::Padding(_))));
        for slots in &mut datagrams {
            slots.packets.retain(|meta| meta.epoch() != epoch);
        }
        assert!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx).is_pending());
        terminator.terminate();
        assert!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx).is_pending());
        assert!(datagrams.iter().all(|datagram| datagram.packets.is_empty()));
        assert!(frames.is_empty());
    }
}

fn server_one_rtt_keys() -> qtls::OneRttKeyMaterial {
    use tls_backend::pki_types::pem::PemObject;
    let provider = Arc::new(qtls::default_provider());
    qtls::RootCerts::set([
        qtls::CertificateDer::from_pem_slice(include_bytes!("../../../qconnection/tests/keychain/localhost/ca.cert")).unwrap()
    ])
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
                qtls::CertificateDer::from_pem_slice(include_bytes!("../../../qconnection/tests/keychain/localhost/server.cert")).unwrap(),
            ],
            qtls::PrivateKeyDer::from_pem_slice(include_bytes!("../../../qconnection/tests/keychain/localhost/server.key")).unwrap(),
            include_bytes!("../../../qconnection/tests/keychain/localhost/server.ocsp").to_vec(),
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
    let mut server = server.start(qtls::QuicVersion::V1, bytes::Bytes::new()).unwrap();
    while let Some(event) = client.next_event() {
        if let qtls::TlsEvent::WriteCrypto { epoch: level, bytes } = event {
            server.receive_crypto(level, &bytes).unwrap();
        }
    }
    loop {
        if let qtls::TlsEvent::InstallKeys(qtls::InstalledKeys::OneRtt(keys)) = server.next_event().unwrap() {
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
    client.set(ParameterId::InitialSourceConnectionId, ConnectionId::from_slice(b"client00")).unwrap();
    let parameters = ArcParameters::new(Role::Server, Arc::new(client), Arc::new(ServerParameters::default()));
    let terminator = &paths.terminator;
    paths.cid_registry.remote.set_limit(parameters.local(ParameterId::ActiveConnectionIdLimit));
    paths.progress.on_initial_received(parameters.remote(ParameterId::InitialSourceConnectionId));
    let handshake = Arc::new(HandshakeSpace::new(Default::default(), ArcKeys::new(Arc::new(keys(true))), facts.clone()));
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
        facts,
    ));
    terminator.register(Arc::new(data.crypto.clone()));
    let concrete = super::SpaceFixture { initial: crate::common::initial_space(&paths.spaces), handshake, data };
    (paths.clone(), super::DataFixture { paths, parameters, spaces: concrete })
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
    assert_eq!(crate::common::cid_value(&paths.cid_registry.remote.apply_dcid()), mature.peer_cid());

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
            assert!(paths.progress.install_handshake(data.spaces.handshake.clone()));
        }
        let path = crate::common::registered_path(
            &paths,
            Path::new(
                paths.cid_registry.remote.apply_dcid(),
                crate::common::path_fixtures::pathway(34501),
                paths.progress.facts(),
                paths.spaces.clone(),
                paths.resenders.clone(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.terminator.clone(),
                paths.progress.clone(),
            ),
        );
        let other = crate::common::registered_path(
            &paths,
            Path::new(
                paths.cid_registry.remote.apply_dcid(),
                crate::common::path_fixtures::pathway(34502),
                paths.progress.facts(),
                paths.spaces.clone(),
                paths.resenders.clone(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.terminator.clone(),
                paths.progress.clone(),
            ),
        );
        path.validation.grant().unwrap();
        paths.progress.on_path_selected(&paths, &path);
        path.disable();
        let counter = Arc::new(Counter::default());
        let other_counter = Arc::new(Counter::default());
        let waker = Waker::from(counter.clone());
        other.send_waker.register(&Waker::from(other_counter.clone()));
        other.send_waker.refresh(false);
        let mut cx = Context::from_waker(&waker);
        let mut datagrams = [Datagram::default()];
        let mut frames = Vec::new();
        assert!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx).is_pending());
        let before = counter.0.load(Ordering::Relaxed);
        if epoch == Epoch::Handshake {
            data.spaces.handshake.crypto.writer().write_all(b"handshake").await.unwrap();
        } else {
            data.spaces.data.crypto.writer().write_all(b"data").await.unwrap();
        }
        assert_eq!(counter.0.load(Ordering::Relaxed), before);
        assert!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx).is_pending());
        if epoch == Epoch::Handshake {
            assert!(paths.progress.install_handshake(data.spaces.handshake.clone()));
        } else {
            paths.progress.install_data(data.spaces.data.clone());
        }
        assert_eq!(counter.0.load(Ordering::Relaxed), before);
        assert_eq!(other_counter.0.load(Ordering::Relaxed), 0);
        path.enable();
        assert!(counter.0.load(Ordering::Relaxed) > before);
        assert_eq!(other_counter.0.load(Ordering::Relaxed), 0);
        assert!(matches!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx), Poll::Ready(Ok(n)) if n > 0));
        assert!(datagram_metadata(&datagrams[0], epoch).is_some());
        path.refresh(&mut datagrams, &mut frames);
        paths.retire_all();
    }
}

#[tokio::test(start_paused = true)]
async fn existing_path_recovers_newly_installed_spaces() {
    let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            paths.cid_registry.remote.apply_dcid(),
            Pathway::new(
                EndpointAddr::direct("127.0.0.1:34101".parse().unwrap()),
                EndpointAddr::direct("127.0.0.1:34102".parse().unwrap()),
            ),
            paths.progress.facts(),
            paths.spaces.clone(),
            paths.resenders.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    path.validation.grant().unwrap();
    paths.progress.on_path_selected(&paths, &path);
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| Datagram::default());
    let mut frames = Vec::new();

    for epoch in [Epoch::Handshake, Epoch::Data] {
        let (crypto, journal) = if epoch == Epoch::Handshake {
            super::install_handshake(&paths, mature.spaces.handshake.clone());
            (&mature.spaces.handshake.crypto, &mature.spaces.handshake.sent_journal)
        } else {
            super::install_data(&paths, &mature);
            super::confirm_handshake(&paths);
            (&mature.spaces.data.crypto, &mature.spaces.data.sent_journal)
        };
        let mut sent = Vec::new();
        for _ in 0..4 {
            crypto.writer().write_all(b"crypto").await.unwrap();
            path.collect(&mut datagrams, &mut frames).now_or_never().unwrap().unwrap();
            assert_eq!(pns_for(&datagrams, epoch).count(), 1);
            let (index, pn) = pns_for(&datagrams, epoch).next().unwrap();
            journal.on_sent(pn, true, Duration::from_secs(1), Duration::from_secs(3));
            path.cc.on_pkt_sent(epoch, pn, true, datagrams[index].bytes.len(), true, None);
            sent.push(pn);
            for entries in &mut datagrams {
                entries.packets.clear();
            }
        }
        // Three later packets prove the first one lost. CC must call the newly attached space.
        let ack = qbase::frame::AckFrame::new(sent[3].try_into().unwrap(), 0u32.into(), 0u32.into(), vec![], None);
        path.cc.on_ack_rcvd(epoch, &ack);
        path.collect(&mut datagrams, &mut frames).now_or_never().expect("loss must make the original CRYPTO range sendable").unwrap();
        assert_eq!(pns_for(&datagrams, epoch).count(), 1);
        let records = journal.lock_guard();
        assert!(
            records
                .frames(pns_for(&datagrams, epoch).next().unwrap().1)
                .any(|frame| { matches!(frame, GuaranteedFrame::Crypto(frame) if frame.offset() == 0 && frame.len() == 6) })
        );
        for entries in &mut datagrams {
            entries.packets.clear();
        }
    }
}
#[tokio::test]
async fn growing_assigns_the_selected_cid_before_releasing_or_creating_other_paths() {
    use qbase::frame::{NewConnectionIdFrame, io::ReceiveFrame};

    let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
    let remote = &paths.cid_registry.remote;
    let next = ConnectionId::from_slice(b"client01");
    remote.recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into())).unwrap();
    let make_path = |port| {
        let path = crate::common::registered_path(
            &paths,
            Path::new(
                paths.cid_registry.remote.apply_dcid(),
                Pathway::new(EndpointAddr::direct(([127, 0, 0, 1], port).into()), EndpointAddr::direct("127.0.0.1:34300".parse().unwrap())),
                paths.progress.facts(),
                paths.spaces.clone(),
                paths.resenders.clone(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.terminator.clone(),
                paths.progress.clone(),
            ),
        );
        paths.entries.lock().unwrap().insert(path.pathway, path.clone());
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
            paths.cid_registry.remote.apply_dcid(),
            Pathway::new(
                EndpointAddr::direct("127.0.0.1:34201".parse().unwrap()),
                EndpointAddr::direct("127.0.0.1:34202".parse().unwrap()),
            ),
            paths.progress.facts(),
            paths.spaces.clone(),
            paths.resenders.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    paths.progress.on_path_selected(&paths, &path);
    path.validation.grant().unwrap();
    // The selected sender waits if the available CID was already consumed.
    assert!(!paths.progress.facts().is_handshake_done() && path.dcid.is_allocated());
    for crypto in [&mature.spaces.initial.crypto, &mature.spaces.handshake.crypto, &mature.spaces.data.crypto] {
        crypto.writer().write_all(b"crypto").await.unwrap();
    }
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| Datagram::default());
    let mut frames = Vec::new();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx).is_pending());
    let next = ConnectionId::from_slice(b"client01");
    remote.recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into())).unwrap();
    let (count, borrowed) = path.collect(&mut datagrams, &mut frames).now_or_never().unwrap().unwrap();
    assert_eq!(count, 1);
    // Keep the CID borrowed while the assembled datagram awaits UDP submission.
    assert!(Epoch::EPOCHS.into_iter().all(|epoch| datagram_metadata(&datagrams[0], epoch).is_some()));
    let packets = PacketReader::new(datagrams[0].bytes.clone(), 8).collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(packets.len(), 3);
    for packet in packets {
        let ParsedPacket::Data(packet) = packet else {
            panic!()
        };
        assert_eq!(*packet.header.dcid(), next);
    }
    initial_cell.retire();
    let replacement = ConnectionId::from_slice(b"client02");
    remote.recv_frame(NewConnectionIdFrame::new(replacement, 2u32.into(), 2u32.into())).unwrap();
    assert_eq!(borrowed, next);
    path.dcid.refresh();
    assert!(matches!(super::borrow(&path),
        Poll::Ready(Some(cid)) if cid == replacement));

    for slots in &mut datagrams {
        slots.packets.clear();
    }
    for crypto in [&mature.spaces.initial.crypto, &mature.spaces.handshake.crypto, &mature.spaces.data.crypto] {
        crypto.writer().write_all(b"next").await.unwrap();
    }
    path.collect(&mut datagrams, &mut frames).now_or_never().unwrap().unwrap();
    assert!(Epoch::EPOCHS.into_iter().all(|epoch| datagram_metadata(&datagrams[0], epoch).is_some()));
    let packets = PacketReader::new(datagrams[0].bytes.clone(), 8).collect::<Result<Vec<_>, _>>().unwrap();
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
    for crypto in [&mature.spaces.initial.crypto, &mature.spaces.handshake.crypto, &mature.spaces.data.crypto] {
        crypto.writer().write_all(b"crypto").await.unwrap();
    }
    super::install_data(&paths, &mature);
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            paths.cid_registry.remote.apply_dcid(),
            Pathway::new(
                EndpointAddr::direct("127.0.0.1:34001".parse().unwrap()),
                EndpointAddr::direct("127.0.0.1:34002".parse().unwrap()),
            ),
            paths.progress.facts(),
            paths.spaces.clone(),
            paths.resenders.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    path.validation.grant().unwrap();
    paths.progress.on_path_selected(&paths, &path);
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| Datagram::default());
    let mut frames = Vec::new();
    assert_eq!(path.collect(&mut datagrams, &mut frames).now_or_never().unwrap().unwrap().0, 1);
    for epoch in Epoch::EPOCHS {
        assert_eq!(pns_for(&datagrams, epoch).count(), 1);
    }
    assert_eq!(pns_for(&datagrams, Epoch::Initial).next().unwrap().0, 0);
    assert_eq!(pns_for(&datagrams, Epoch::Handshake).next().unwrap().0, 0);
    assert_eq!(pns_for(&datagrams, Epoch::Data).next().unwrap().0, 0);
    assert!(frames.is_empty());
    // Consume these datagrams' packet numbers before collecting the next datagrams.
    for entries in &mut datagrams {
        entries.packets.clear();
    }
    mature.spaces.initial.crypto.writer().write_all(b"remaining").await.unwrap();
    paths.progress.facts().on_handshake_done();
    paths.cid_registry.remote.upgrade();
    assert!(matches!(path.collect(&mut datagrams, &mut frames).now_or_never(), Some(Ok((1, _)))));
    assert_eq!(pns_for(&datagrams, Epoch::Initial).count(), 1);
    for slots in &mut datagrams {
        slots.packets.retain(|meta| meta.epoch() != Epoch::Initial);
    }
    // A path without an available CID must wait before collecting data. Retirement
    // must wake that wait even though the socket has never been polled.
    let waiting_path = crate::common::registered_path(
        &paths,
        Path::new(
            paths.cid_registry.remote.apply_dcid(),
            Pathway::new(
                EndpointAddr::direct("127.0.0.1:34003".parse().unwrap()),
                EndpointAddr::direct("127.0.0.1:34002".parse().unwrap()),
            ),
            paths.progress.facts(),
            paths.spaces.clone(),
            paths.resenders.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    waiting_path.validation.grant().unwrap();
    mature.spaces.data.crypto.writer().write_all(b"next").await.unwrap();
    paths.entries.lock().unwrap().insert(path.pathway, path.clone());
    let sending_task = tokio::spawn({
        let paths = paths.clone();
        let path = waiting_path.clone();
        async move { paths.send_via(&path).await }
    });
    tokio::task::yield_now().await;
    assert!(!sending_task.is_finished());
    waiting_path.close();
    let error = tokio::time::timeout(Duration::from_secs(1), sending_task).await.unwrap().unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    paths.del_path(&waiting_path);
    mature.spaces.initial.retire();
    mature.spaces.handshake.retire();
    let (_, mut writer) = mature.spaces.data.streams.open_uni().await.unwrap().unwrap();
    writer.write_all(b"queued before closing").await.unwrap();
    assert!(mature.spaces.data.streams.fresh_bytes() > 0);
    let error = QuicError::with_default_fty(ErrorKind::Internal, "connection failed");
    paths.terminator.close(crate::CloseReason::Internal(error.clone()), paths.closing_pto());
    mature.spaces.data.crypto.on_error(&error.into());
    // Closing removes queued stream output; only the close response remains sendable.
    assert_eq!(mature.spaces.data.streams.fresh_bytes(), 0);
    assert_eq!(path.collect(&mut datagrams, &mut frames).now_or_never().unwrap().unwrap().0, 1);
    assert!(pns_for(&datagrams, Epoch::Initial).next().is_none());
    assert!(pns_for(&datagrams, Epoch::Handshake).next().is_none());
    let pn = pns_for(&datagrams, Epoch::Data).next().unwrap().1;
    let journal = mature.spaces.data.sent_journal.lock_guard();
    assert_eq!(journal.frames(pn).count(), 0);
    assert_eq!(journal.packet(pn).unwrap().content, qbase::packet::PacketContent::NonAckEliciting);
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
                paths.cid_registry.remote.apply_dcid(),
                Pathway::new("127.0.0.1:30001".parse::<EndpointAddr>().unwrap(), "127.0.0.1:30002".parse().unwrap()),
                paths.progress.facts(),
                paths.spaces.clone(),
                paths.resenders.clone(),
                ArcHeartbeat::new(Duration::from_secs(60), Duration::ZERO),
                paths.terminator.clone(),
                paths.progress.clone(),
            ),
        );
        path.validation.grant().unwrap();
        paths.progress.on_path_selected(&paths, &path);
        path.heartbeat.on_rcvd_at(PacketContent::EffectivePayload, tokio::time::Instant::now()).unwrap();

        if epoch == Epoch::Data {
            super::confirm_handshake(&paths);
        }
        let mut datagrams = [Datagram::default()];
        let mut frames = Vec::new();
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        if epoch == Epoch::Data {
            // Consume the CID advertisement queued by the fixture before testing idleness.
            assert!(matches!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx), Poll::Ready(Ok(1))));
            for slots in &mut datagrams {
                if let Some(meta) = datagram_metadata(slots, Epoch::Data) {
                    slots.packets.retain(|meta| meta.epoch() != Epoch::Data);
                    mature.spaces.data.on_sent(meta.pn, meta.in_flight, Duration::from_secs(1), Duration::from_secs(3));
                }
            }
            // Finish the simulated submission before collecting another batch.
            path.refresh(&mut datagrams, &mut frames);
        }
        assert!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx).is_pending());
        tokio::task::yield_now().await;
        let before = counter.0.load(Ordering::Relaxed);
        tokio::time::advance(Duration::from_secs(20)).await;
        tokio::task::yield_now().await;
        assert!(counter.0.load(Ordering::Relaxed) > before);
        let result = poll_collect(&path, &mut datagrams, &mut frames, &mut cx);
        assert!(matches!(result, Poll::Ready(Ok(1))), "{epoch:?}: {result:?}");
        assert_eq!(pns_for(&datagrams, epoch).count(), 1);
        let pn = pns_for(&datagrams, epoch).next().unwrap().1;
        assert_eq!(paths.spaces.get(epoch).unwrap().sent_journal().lock_guard().packet(pn).unwrap().content, PacketContent::JustPing);
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
                    paths.cid_registry.remote.apply_dcid(),
                    Pathway::new(
                        EndpointAddr::direct("127.0.0.1:35201".parse().unwrap()),
                        EndpointAddr::direct("127.0.0.1:35202".parse().unwrap()),
                    ),
                    paths.progress.facts(),
                    paths.spaces.clone(),
                    paths.resenders.clone(),
                    ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                    paths.terminator.clone(),
                    paths.progress.clone(),
                ),
            );
            paths.progress.on_path_selected(&paths, &selected);
            let trackers = paths.resenders.clone();
            let epochs = || trackers.read_guard().enumerate().map(|(epoch, _)| epoch).collect::<Vec<_>>();
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
            assert!(mature.spaces.data.keys.sealing_keys().is_ok());
        }
    }
}

pub(super) fn datagram_metadata(datagram: &Datagram, epoch: Epoch) -> Option<Metadata> {
    datagram.packets.iter().find(|meta| meta.epoch() == epoch).copied()
}

pub(super) fn poll_collect(
    path: &Path,
    datagrams: &mut [Datagram],
    frames: &mut Vec<GuaranteedFrame>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<usize>> {
    std::pin::pin!(path.collect(datagrams, frames)).poll(cx).map(|result| result.map(|(count, _)| count))
}

fn metadata(datagrams: &[Datagram]) -> impl Iterator<Item = &Metadata> {
    datagrams.iter().flat_map(|datagram| &datagram.packets)
}

fn pns_for(datagrams: &[Datagram], epoch: Epoch) -> impl Iterator<Item = (usize, u64)> + '_ {
    datagrams.iter().enumerate().filter_map(move |(index, datagram)| datagram_metadata(datagram, epoch).map(|meta| (index, meta.pn)))
}

#[tokio::test(start_paused = true)]
async fn amplification_rearms_pto_when_credit_returns() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    for (epoch, validated) in Epoch::EPOCHS.into_iter().flat_map(|epoch| [(epoch, false), (epoch, true)]) {
        let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
        match epoch {
            Epoch::Initial => {}
            Epoch::Handshake => super::install_handshake(&paths, mature.spaces.handshake.clone()),
            Epoch::Data => super::install_data(&paths, &mature),
        }
        let path = crate::common::registered_path(
            &paths,
            Path::new(
                paths.cid_registry.remote.apply_dcid(),
                Pathway::new(
                    EndpointAddr::direct("127.0.0.1:35101".parse().unwrap()),
                    EndpointAddr::direct("127.0.0.1:35102".parse().unwrap()),
                ),
                paths.progress.facts(),
                paths.spaces.clone(),
                paths.resenders.clone(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.terminator.clone(),
                paths.progress.clone(),
            ),
        );
        paths.progress.on_path_selected(&paths, &path);
        if epoch == Epoch::Data {
            super::confirm_handshake(&paths);
            // Withdraw the handshake path's address validation for this credit test.
            crate::common::revalidate(&path);
        }
        path.validation.on_received(400);
        path.validation.on_sent(1200);
        let quota = path.cc.send_quota();
        path.cc.on_pkt_sent(epoch, 0, true, quota, true, None);
        assert_eq!(path.cc.send_quota(), 0);
        if epoch == Epoch::Data {
            let (_, mut writer) = mature.spaces.data.streams.open_uni().await.unwrap().unwrap();
            writer.write_all(&[7; 4000]).await.unwrap();
        }
        let base = path.cc.get_pto(epoch);
        let mut datagrams = std::array::from_fn::<_, 8, _>(|_| Datagram::default());
        let mut frames = Vec::new();
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx).is_pending());
        tokio::time::advance(base).await;
        assert!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx).is_pending());
        assert_eq!(path.cc.get_pto(epoch), base);

        // Credit below the sending threshold neither wakes the sender nor rearms PTO.
        let before = counter.0.load(Ordering::Relaxed);
        path.validation.on_received(1);
        assert_eq!(counter.0.load(Ordering::Relaxed), before);
        assert!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx).is_pending());
        assert_eq!(path.cc.need_send_ack_eliciting(epoch), 0);
        assert_eq!(path.cc.get_pto(epoch), base);

        // Handshake and 1-RTT probes fit well below 1200 bytes.
        let before = counter.0.load(Ordering::Relaxed);
        if validated {
            path.validation.grant().unwrap();
        } else {
            path.validation.on_received(42);
        }
        assert!(counter.0.load(Ordering::Relaxed) > before);
        if epoch == Epoch::Initial && !validated {
            assert!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx).is_pending());
            assert_eq!(path.cc.need_send_ack_eliciting(epoch), 1);
            path.validation.on_received(357);
        }
        assert!(
            matches!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx), Poll::Ready(Ok(1))),
            "{epoch:?} PTO did not resume when its probe fitted"
        );
        let meta = datagram_metadata(&datagrams[0], epoch).unwrap();
        assert!(meta.content.is_ack_eliciting());
        assert_eq!(path.cc.need_send_ack_eliciting(epoch), 1);
        assert!(path.cc.get_pto(epoch) > base);
        if epoch == Epoch::Initial {
            assert_eq!(datagrams[0].bytes.len(), 1200);
        } else if !validated {
            assert!(datagrams[0].bytes.len() <= 129);
        }
        path.refresh(&mut datagrams, &mut frames);
        paths.del_path(&path);
        path.close();
        paths.terminator.terminate();
    }
}

#[tokio::test(start_paused = true)]
async fn ack_only_submission_leaves_credit_below_threshold_and_blocks_pto_without_another_collect() {
    use qprotocol::{QuicProtocol, UdpSocket};

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    QuicProtocol::global().register(EndpointAddr::direct(socket.local_addr().unwrap()), &socket).unwrap();
    let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
    super::install_handshake(&paths, mature.spaces.handshake.clone());
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            paths.cid_registry.remote.apply_dcid(),
            Pathway::new(EndpointAddr::direct(socket.local_addr().unwrap()), EndpointAddr::direct(peer.local_addr().unwrap())),
            paths.progress.facts(),
            paths.spaces.clone(),
            paths.resenders.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    paths.progress.on_path_selected(&paths, &path);
    path.validation.on_received(43);
    path.cc.on_pkt_sent(Epoch::Handshake, 0, true, 1200, true, None);
    mature.spaces.handshake.rcvd_journal.on_rcvd_pn(42, true, path.cc.pto_base(Epoch::Handshake));
    path.cc.on_pkt_rcvd(Epoch::Handshake, 42, true);
    let base = path.cc.get_pto(Epoch::Handshake);
    let mut datagrams = [Datagram::default()];
    let mut frames = Vec::new();
    let (count, _) = path.collect(&mut datagrams, &mut frames).now_or_never().unwrap().unwrap();
    assert_eq!(count, 1);
    let meta = datagram_metadata(&datagrams[0], Epoch::Handshake).unwrap();
    assert!(!meta.content.is_ack_eliciting());
    assert!(!meta.in_flight);
    assert!(meta.ack.is_some());
    path.send(&mut datagrams[..1], &paths.idle_timer()).await.unwrap();
    assert!((1..96).contains(&crate::common::path_credit(&path).unwrap()));
    tokio::time::advance(base * 2).await;
    // No subsequent budget poll: submission must already have told CC it is blocked.
    path.cc.do_tick().unwrap();
    assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Handshake), 0);
    assert_eq!(path.cc.get_pto(Epoch::Handshake), base);
    path.validation.grant().unwrap();
    assert!(matches!(poll_collect(&path, &mut datagrams, &mut frames, &mut Context::from_waker(Waker::noop())), Poll::Ready(Ok(1))));
    assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Handshake), 1);
    path.refresh(&mut datagrams, &mut frames);
    paths.del_path(&path);
    path.close();
    paths.terminator.terminate();
    QuicProtocol::global().unregister(socket.local_addr().unwrap());
}

#[tokio::test(start_paused = true)]
async fn path_validation_respects_small_amplification_credit() {
    use qbase::frame::{PathChallengeFrame, io::ReceiveFrame};

    for received in [0, 31, 32, 128, 399, 400] {
        for reply in [false, true] {
            let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
            super::install_data(&paths, &mature);
            let path = crate::common::registered_path(
                &paths,
                Path::new(
                    paths.cid_registry.remote.apply_dcid(),
                    Pathway::new(
                        EndpointAddr::direct("127.0.0.1:35101".parse().unwrap()),
                        EndpointAddr::direct("127.0.0.1:35102".parse().unwrap()),
                    ),
                    paths.progress.facts(),
                    paths.spaces.clone(),
                    paths.resenders.clone(),
                    ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                    paths.terminator.clone(),
                    paths.progress.clone(),
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
            let credit = crate::common::path_credit(&path).unwrap();
            let mut datagrams = [Datagram::default()];
            let mut frames = Vec::new();
            let result = poll_collect(&path, &mut datagrams, &mut frames, &mut Context::from_waker(Waker::noop()));
            if credit < 96 {
                assert!(result.is_pending());
                assert!(pns_for(&datagrams, Epoch::Data).next().is_none());
            } else {
                assert!(matches!(result, Poll::Ready(Ok(1))), "received={received}, reply={reply}, result={result:?}");
                let size = datagrams[0].bytes.len();
                assert!(size <= credit, "validation exceeded amplification credit");
                if credit < 1200 {
                    assert!(size < 1200);
                } else {
                    assert_eq!(size, 1200);
                }
                let journal = mature.spaces.data.sent_journal.lock_guard();
                assert!(journal.packet(datagram_metadata(&datagrams[0], Epoch::Data).unwrap().pn).unwrap().in_flight);
                assert!(super::take_validation_frames(&path).is_empty(), "validation frame was not encoded");
            }
            assert!(!path.validation.is_validated());
            path.close();
            paths.terminator.terminate();
        }
    }
}

#[tokio::test]
async fn idle_and_amplification_blocked_collectors_wait_without_periodic_wakes() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    for blocked in [false, true] {
        let paths = crate::common::initial_paths(
            Role::Server,
            ConnectionId::from_slice(b"server00"),
            ConnectionId::from_slice(b"original"),
            keys(true),
        );
        let path = crate::common::registered_path(
            &paths,
            Path::new(
                paths.cid_registry.remote.apply_dcid(),
                crate::common::path_fixtures::pathway(34601),
                paths.progress.facts(),
                paths.spaces.clone(),
                paths.resenders.clone(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.terminator.clone(),
                paths.progress.clone(),
            ),
        );
        if blocked {
            path.cc.on_pkt_sent(Epoch::Initial, 0, true, 12000, true, None);
        } else {
            path.validation.exempt().unwrap();
        }
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut datagrams = [Datagram::default()];
        let mut frames = Vec::new();
        assert!(poll_collect(&path, &mut datagrams, &mut frames, &mut Context::from_waker(&waker)).is_pending());
        counter.0.store(0, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(counter.0.load(Ordering::Relaxed), 0, "blocked={blocked}");
        if blocked {
            path.validation.on_received(400);
            assert!(counter.0.load(Ordering::Relaxed) > 0);
        }
        path.refresh(&mut datagrams, &mut frames);
        path.send_waker.register(&waker);
        path.send_waker.refresh(false);
        paths.del_path(&path);
        path.close();
        paths.terminator.terminate();
    }
}

#[tokio::test]
async fn sending_uses_its_budget_across_multiple_collections() {
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
    space.crypto.writer().write_all(&[42; 24000]).await.unwrap();
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            paths.cid_registry.remote.apply_dcid(),
            Pathway::new(local, EndpointAddr::direct(peer.local_addr().unwrap())),
            paths.progress.facts(),
            paths.spaces.clone(),
            paths.resenders.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    path.validation.exempt().unwrap();
    let quota = path.cc.send_quota();
    let mut sender = std::pin::pin!(paths.send_via(&path));
    // The first poll can wait for UDP writability before submitting anything.
    tokio::time::timeout(
        Duration::from_secs(1),
        std::future::poll_fn(|cx| {
            assert!(sender.as_mut().poll(cx).is_pending());
            if quota - path.cc.send_quota() > 8 * 1200 {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .unwrap();
    let (next, _) = space.next_pn();
    let sent = {
        let journal = space.sent_journal.lock_guard();
        (0..next).filter(|&pn| journal.packet(pn).is_some()).count()
    };
    assert!(sent > 8, "sending stopped after {sent} datagrams");
    paths.terminator.terminate();
    sender.await.unwrap();
    paths.del_path(&path);
    assert!(paths.entries.lock().unwrap().is_empty());
    QuicProtocol::global().unregister(socket.local_addr().unwrap());
}

#[tokio::test]
async fn termination_discards_collected_packets_after_space_retirement() {
    let paths = crate::common::initial_paths(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let space = crate::common::initial_space(&paths.spaces);
    space.crypto.writer().write_all(b"pending crypto").await.unwrap();
    let owner = Arc::downgrade(&paths.spaces.get(Epoch::Initial).unwrap());
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            paths.cid_registry.remote.apply_dcid(),
            crate::common::path_fixtures::pathway(34601),
            paths.progress.facts(),
            paths.spaces.clone(),
            paths.resenders.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    path.validation.exempt().unwrap();
    let quota = path.cc.send_quota();
    let mut datagrams = [Datagram::default()];
    let mut frames = Vec::new();
    let (count, _) = path.collect(&mut datagrams, &mut frames).await.unwrap();
    let pn = datagram_metadata(&datagrams[0], Epoch::Initial).unwrap().pn;
    paths.progress.on_handshake_sent();
    assert!(paths.spaces.get(Epoch::Initial).is_none());
    assert!(owner.upgrade().is_none(), "collected packets must not retain retired spaces");
    paths.terminator.terminate();
    let idle_timer = paths.idle_timer();
    tokio::select! {
        biased;
        _ = paths.terminator.clone() => {},
        _ = path.send(&mut datagrams[..count], &idle_timer) => panic!("terminated task must skip submission"),
    }
    path.refresh(&mut datagrams, &mut frames);
    path.refresh(&mut datagrams, &mut frames);
    assert!(datagrams[0].bytes.is_empty());
    assert!(datagrams[0].packets.is_empty());
    assert!(frames.is_empty());
    assert!(space.sent_journal.lock_guard().packet(pn).is_some(), "refresh must skip the retired journal");
    assert_eq!(path.cc.send_quota(), quota);
    paths.del_path(&path);
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn collection_bounds_each_datagram_and_charges_envelopes_once() {
    use qprotocol::QuicProtocol;

    for mediate in [false, true] {
        for amplification_limited in [false, true] {
            let (paths, mature) = data_spaces(Role::Server, Duration::ZERO);
            super::install_data(&paths, &mature);
            let local = EndpointAddr::direct("127.0.0.1:35501".parse().unwrap());
            let remote = if mediate {
                EndpointAddr::mediate("127.0.0.1:35502".parse().unwrap(), "127.0.0.1:35503".parse().unwrap())
            } else {
                EndpointAddr::direct("127.0.0.1:35502".parse().unwrap())
            };
            let path = crate::common::registered_path(
                &paths,
                Path::new(
                    paths.cid_registry.remote.apply_dcid(),
                    Pathway::new(local, remote),
                    paths.progress.facts(),
                    paths.spaces.clone(),
                    paths.resenders.clone(),
                    ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                    paths.terminator.clone(),
                    paths.progress.clone(),
                ),
            );
            paths.progress.on_path_selected(&paths, &path);
            let overhead = QuicProtocol::datagram_overhead(path.pathway);
            crate::common::spaces::take_reliable(&mature);
            let budget = (1500 + 2 * overhead).div_ceil(3) * 3;
            if amplification_limited {
                path.validation.on_received(budget / 3);
            } else {
                path.validation.exempt().unwrap();
                let used = path.cc.send_quota() - budget;
                path.cc.on_pkt_sent(Epoch::Data, 999, true, used, true, None);
                assert_eq!(path.cc.send_quota(), budget);
            }
            let mut datagrams = std::array::from_fn::<_, 8, _>(|_| Datagram::default());
            let mut frames = Vec::new();
            let mut cx = Context::from_waker(Waker::noop());
            let result = poll_collect(&path, &mut datagrams, &mut frames, &mut cx);
            assert!(result.is_pending(), "{result:?}");
            assert!(datagrams.iter().all(|datagram| datagram.packets.is_empty()));
            let (_, mut writer) = mature.spaces.data.streams.open_uni().await.unwrap().unwrap();
            writer.write_all(&[7; 4000]).await.unwrap();
            assert!(matches!(poll_collect(&path, &mut datagrams, &mut frames, &mut cx), Poll::Ready(Ok(2))));
            assert_eq!(datagrams[0].bytes.len(), 1200);
            assert_eq!(datagrams[1].bytes.len(), budget - 2 * overhead - 1200);
            let charged: usize = datagrams[..2].iter().map(|datagram| datagram.bytes.len() + overhead).sum();
            assert_eq!(charged, budget);
            assert!(metadata(&datagrams[..2]).all(|meta| meta.in_flight));
            path.refresh(&mut datagrams, &mut frames);
            paths.del_path(&path);
            path.close();
            paths.terminator.terminate();
        }
    }
}

#[tokio::test(start_paused = true)]
async fn deleting_a_path_recovers_its_unacknowledged_data_for_another_path() {
    use qbase::frame::io::ReceiveFrame as _;
    use qtransport::space::Transmit as _;

    let (paths, data) = data_spaces(Role::Server, Duration::ZERO);
    let make_path = |port| {
        common::registered_path(
            &paths,
            Path::new(
                paths.cid_registry.remote.apply_dcid(),
                common::path_fixtures::pathway(port),
                paths.progress.facts(),
                paths.spaces.clone(),
                paths.resenders.clone(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.terminator.clone(),
                paths.progress.clone(),
            ),
        )
    };
    let failed = make_path(38011);
    let live = make_path(38012);
    paths.progress.on_path_selected(&paths, &failed);
    super::install_data(&paths, &data);
    super::confirm_handshake(&paths);
    paths
        .cid_registry
        .remote
        .recv_frame(qbase::frame::NewConnectionIdFrame::new(ConnectionId::from_slice(b"client01"), 1u32.into(), 0u32.into()))
        .unwrap();
    live.validation.grant().unwrap();
    common::spaces::take_reliable(&data);
    data.spaces.data.crypto.writer().write_all(b"recover on another path").await.unwrap();
    let mut datagrams = [Datagram::default()];
    let mut frames = Vec::new();
    failed.collect(&mut datagrams, &mut frames).await.unwrap();
    let meta = datagram_metadata(&datagrams[0], Epoch::Data).unwrap();
    data.spaces.data.on_sent(meta.pn, meta.in_flight, Duration::from_secs(1), Duration::from_secs(3));
    failed.cc.on_pkt_sent(Epoch::Data, meta.pn, meta.content.is_ack_eliciting(), meta.pktlen, meta.in_flight, meta.ack);
    // These packets have been submitted: refresh must not recover them.
    datagrams[0].packets.clear();
    failed.refresh(&mut datagrams, &mut frames);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(poll_collect(&live, &mut datagrams, &mut frames, &mut cx).is_pending());
    assert!(paths.del_path(&failed));
    assert!(matches!(poll_collect(&live, &mut datagrams, &mut frames, &mut cx), Poll::Ready(Ok(1))));
    let retransmit = datagram_metadata(&datagrams[0], Epoch::Data).unwrap();
    assert_ne!(retransmit.pn, meta.pn);
    assert!(
        data.spaces
            .data
            .sent_journal
            .lock_guard()
            .frames(retransmit.pn)
            .any(|frame| { matches!(frame, GuaranteedFrame::Crypto(frame) if frame.offset() == 0 && frame.len() == 23) })
    );
    live.refresh(&mut datagrams, &mut frames);
    paths.del_path(&live);
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn collection_reports_unanswered_probes_as_an_io_timeout() {
    let paths = crate::common::initial_paths(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            paths.cid_registry.remote.apply_dcid(),
            Pathway::new(
                EndpointAddr::direct("127.0.0.1:38001".parse().unwrap()),
                EndpointAddr::direct("127.0.0.1:38002".parse().unwrap()),
            ),
            paths.progress.facts(),
            paths.spaces.clone(),
            paths.resenders.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    path.validation.exempt().unwrap();
    let sent_at = tokio::time::Instant::now();
    path.cc.on_pkt_sent(Epoch::Initial, 0, true, 1200, true, None);
    for _ in 0..6 {
        let deadline = sent_at + path.cc.get_pto(Epoch::Initial);
        tokio::time::advance(deadline.saturating_duration_since(tokio::time::Instant::now())).await;
        path.cc.do_tick().unwrap();
    }
    let deadline = sent_at + path.cc.get_pto(Epoch::Initial);
    tokio::time::advance(deadline.saturating_duration_since(tokio::time::Instant::now())).await;
    let mut datagrams = [Datagram::default()];
    let mut frames = Vec::new();
    let error = path.collect(&mut datagrams, &mut frames).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(paths.terminator.clone().now_or_never().is_none(), "a path error is not itself a connection error");
    paths.del_path(&path);
    paths.retire_all();
}

#[tokio::test]
async fn sending_commits_the_udp_prefix_and_recovers_only_the_failed_suffix() {
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
    space.crypto.writer().write_all(&vec![42; 2400]).await.unwrap();
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            paths.cid_registry.remote.apply_dcid(),
            Pathway::new(local, EndpointAddr::direct(peer.local_addr().unwrap())),
            paths.progress.facts(),
            paths.spaces.clone(),
            paths.resenders.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    path.validation.exempt().unwrap();
    paths.progress.on_initial_received(crate::common::cid_value(&paths.cid_registry.remote.apply_dcid()));
    paths.progress.on_path_selected(&paths, &path);

    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| Datagram::default());
    let mut frames = Vec::new();
    let (count, _) = path.collect(&mut datagrams, &mut frames).await.unwrap();
    assert!(count > 1);
    let pending: Vec<_> = datagrams.iter().map(|datagram| datagram.packets.clone()).collect();
    let first = packet_metadata(&pending[0], Epoch::Initial).unwrap().pn;
    let suffix = packet_metadata(&pending[1], Epoch::Initial).unwrap().pn;
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
    datagrams[1].bytes.resize(65536, 0);
    let error = path.send(&mut datagrams[..count], &paths.idle_timer()).await.unwrap_err();
    assert!(error.raw_os_error().is_some(), "preserve the socket's original OS error");
    assert!(datagrams[0].packets.is_empty());
    assert_eq!(
        datagrams[1].packets.iter().map(|meta| (meta.pn, meta.pktlen, meta.content, meta.in_flight, meta.ack)).collect::<Vec<_>>(),
        pending[1].iter().map(|meta| (meta.pn, meta.pktlen, meta.content, meta.in_flight, meta.ack)).collect::<Vec<_>>(),
    );
    path.refresh(&mut datagrams, &mut frames);
    assert!(datagrams.iter().all(|datagram| datagram.packets.is_empty()));
    {
        let journal = space.sent_journal.lock_guard();
        assert!(journal.packet(first).is_some());
        for slots in &pending[1..count] {
            assert!(journal.packet(packet_metadata(slots, Epoch::Initial).unwrap().pn).is_none());
        }
    }
    let (count, _) = path.collect(&mut datagrams, &mut frames).await.unwrap();
    let retransmit = datagram_metadata(&datagrams[0], Epoch::Initial).unwrap().pn;
    assert!(
        space
            .sent_journal
            .lock_guard()
            .frames(retransmit)
            .any(|frame| { matches!(frame, GuaranteedFrame::Crypto(frame) if frame.offset() == offset) })
    );
    path.send(&mut datagrams[..count], &paths.idle_timer()).await.unwrap();
    assert!(datagrams.iter().all(|datagram| datagram.packets.is_empty()));
    paths.del_path(&path);
    QuicProtocol::global().unregister(socket.local_addr().unwrap());
}

#[tokio::test(start_paused = true)]
async fn retired_path_rejects_collected_datagrams_before_udp_submission() {
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
            paths.cid_registry.remote.apply_dcid(),
            Pathway::new(local, EndpointAddr::direct(peer.local_addr().unwrap())),
            paths.progress.facts(),
            paths.spaces.clone(),
            paths.resenders.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    path.validation.exempt().unwrap();
    paths.progress.on_initial_received(crate::common::cid_value(&paths.cid_registry.remote.apply_dcid()));
    paths.progress.on_path_selected(&paths, &path);
    let mut datagrams = [Datagram::default()];
    let mut frames = Vec::new();
    let (count, _) = path.collect(&mut datagrams, &mut frames).await.unwrap();
    let pn = datagram_metadata(&datagrams[0], Epoch::Initial).unwrap().pn;
    path.close();

    let error = path.send(&mut datagrams[..count], &paths.idle_timer()).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert!(datagram_metadata(&datagrams[0], Epoch::Initial).is_some());
    path.refresh(&mut datagrams, &mut frames);
    assert!(space.sent_journal.lock_guard().packet(pn).is_none());
    paths.del_path(&path);
    QuicProtocol::global().unregister(socket.local_addr().unwrap());
}

#[tokio::test(start_paused = true)]
async fn submission_skips_retired_initial_and_accounts_live_handshake_and_path() {
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
    let handshake = Arc::new(HandshakeSpace::new(Default::default(), ArcKeys::new(Arc::new(keys(true))), paths.progress.facts()));
    initial.crypto.writer().write_all(b"initial").await.unwrap();
    handshake.crypto.writer().write_all(b"handshake").await.unwrap();
    super::install_handshake(&paths, handshake.clone());
    let path = crate::common::registered_path(
        &paths,
        Path::new(
            paths.cid_registry.remote.apply_dcid(),
            Pathway::new(local, EndpointAddr::direct(peer.local_addr().unwrap())),
            paths.progress.facts(),
            paths.spaces.clone(),
            paths.resenders.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    path.validation.on_received(1200);
    paths.progress.on_path_selected(&paths, &path);
    let mut datagrams = [Datagram::default()];
    let mut frames = Vec::new();
    let (count, _) = path.collect(&mut datagrams, &mut frames).await.unwrap();
    assert_eq!(count, 1);
    assert!(datagram_metadata(&datagrams[0], Epoch::Initial).is_some());
    assert!(datagram_metadata(&datagrams[0], Epoch::Handshake).is_some());
    paths.progress.on_handshake_received();
    assert!(paths.spaces.get(Epoch::Initial).is_none());
    let journals = [&initial.sent_journal, &handshake.sent_journal];
    tokio::time::advance(Duration::from_secs(10)).await;
    for journal in journals {
        journal.on_tick(Instant::now(), |_| panic!("unsubmitted packet timed out"));
    }
    assert_eq!(crate::common::path_credit(&path), Some(3600));
    let delays = [Epoch::Initial, Epoch::Handshake].map(|epoch| path.cc.retransmit_and_expire_time(epoch).0);
    path.send(&mut datagrams[..1], &paths.idle_timer()).await.unwrap();
    let submitted_at = Instant::now();
    assert!(datagrams[0].packets.is_empty());
    assert_eq!(crate::common::path_credit(&path), Some(2400));
    path.refresh(&mut datagrams, &mut frames);
    for ((journal, delay), expected) in journals.into_iter().zip(delays).zip([0, 1]) {
        journal.on_tick(submitted_at + delay - Duration::from_nanos(1), |_| panic!("timer started before submission"));
        let mut recovered = 0;
        journal.on_tick(submitted_at + delay, |_| recovered += 1);
        assert_eq!(recovered, expected, "only the live space starts its journal timer");
    }
    paths.del_path(&path);
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
        tokio::time::timeout(Duration::from_secs(1), peer.receive(&mut received, &mut lines)).await.unwrap().unwrap();
        received[0].truncate(lines[0].seg_size as usize);
        let ParsedPacket::Data(packet) = PacketReader::new(received[0].clone(), 8).next().unwrap().unwrap() else {
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
                paths.cid_registry.remote.apply_dcid(),
                Pathway::new(local, EndpointAddr::direct(([127, 0, 0, 1], port).into())),
                paths.progress.facts(),
                paths.spaces.clone(),
                paths.resenders.clone(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.terminator.clone(),
                paths.progress.clone(),
            ),
        );
        path.validation.grant().unwrap();
        path
    };
    let selected = make_path(9);
    let other = make_path(peer.local_addr().unwrap().port());
    paths.progress.on_path_selected(&paths, &selected);
    super::install_data(&paths, &mature);
    super::confirm_handshake(&paths);
    let remote = &paths.cid_registry.remote;
    let old = ConnectionId::from_slice(b"client01");
    remote.recv_frame(NewConnectionIdFrame::new(old, 1u32.into(), 0u32.into())).unwrap();
    assert!(matches!(super::borrow(&other), Poll::Ready(Some(cid)) if cid == old));
    // Only the selected path gets CID 2. This path must keep sending with CID 1.
    remote.recv_frame(NewConnectionIdFrame::new(ConnectionId::from_slice(b"client02"), 2u32.into(), 2u32.into())).unwrap();
    mature.spaces.data.crypto.writer().write_all(b"old CID still sends").await.unwrap();
    let mut datagrams = [Datagram::default()];
    let mut frames = Vec::new();
    let (count, dcid) =
        other.collect(&mut datagrams, &mut frames).now_or_never().expect("missing replacement must not suspend this sender").unwrap();
    assert_eq!(dcid, old);
    other.send(&mut datagrams[..count], &paths.idle_timer()).await.unwrap();
    assert_eq!(received_dcid(&peer).await, old);
    assert!(other.validation.is_validated());
    other.refresh(&mut datagrams, &mut frames);

    let replacement = ConnectionId::from_slice(b"client03");
    remote.recv_frame(NewConnectionIdFrame::new(replacement, 3u32.into(), 2u32.into())).unwrap();
    mature.spaces.data.crypto.writer().write_all(b"replacement CID sends").await.unwrap();
    let (count, dcid) = other.collect(&mut datagrams, &mut frames).now_or_never().unwrap().unwrap();
    assert_eq!(dcid, replacement);
    other.send(&mut datagrams[..count], &paths.idle_timer()).await.unwrap();
    assert_eq!(received_dcid(&peer).await, replacement);
    other.refresh(&mut datagrams, &mut frames);
    other.close();
    assert!(matches!(poll_collect(&other, &mut datagrams, &mut frames, &mut Context::from_waker(Waker::noop())), Poll::Ready(Err(error))
        if error.kind() == io::ErrorKind::BrokenPipe));
    paths.retire_all();
    QuicProtocol::global().unregister(socket.local_addr().unwrap());
}

#[tokio::test]
async fn blocked_ack_does_not_wake_itself_and_cancelled_collect_keeps_subscription() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let paths =
        common::initial_paths(Role::Server, ConnectionId::from_slice(b"serverid"), ConnectionId::from_slice(b"original"), keys(true));
    let path = paths.add_path(Pathway::new(
        EndpointAddr::direct("127.0.0.1:31001".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:31002".parse().unwrap()),
    ));
    path.cc.on_pkt_rcvd(Epoch::Initial, 0, true);
    let initial = common::initial_space(&paths.spaces);
    initial.rcvd_journal.on_rcvd_pn(0, true, Duration::from_secs(1));
    let mut datagrams = [Datagram::default()];
    let mut frames = Vec::new();
    let count = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(std::pin::pin!(path.collect(&mut datagrams, &mut frames)).poll(&mut cx).is_pending());
    assert_eq!(count.0.load(Ordering::Relaxed), 0, "waiting for credit must not continuously wake this task");
    initial.crypto.writer().write_all(b"hello").await.unwrap();
    path.validation.on_received(1200);
    path.close();
    assert!(count.0.load(Ordering::Relaxed) > 0);
    paths.terminator.terminate();
    common::wait_for_sender_exit(&path).await;
    assert_eq!(Arc::strong_count(&count), 2, "task exit releases subscriptions");
}

#[tokio::test]
async fn deleting_a_removed_path_unregisters_its_late_waiters_and_preserves_its_replacement() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use qbase::{
        frame::{HandshakeDoneFrame, io::SendFrame},
        packet::{GetType, OneRttHeader, Package, PacketBuffer},
    };

    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let paths =
        common::initial_paths(Role::Client, ConnectionId::from_slice(b"clientid"), ConnectionId::from_slice(b"original"), keys(false));
    let make_path = || {
        common::registered_path(
            &paths,
            Path::new(
                paths.cid_registry.remote.apply_dcid(),
                common::path_fixtures::pathway(38021),
                paths.progress.facts(),
                paths.spaces.clone(),
                paths.resenders.clone(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                paths.terminator.clone(),
                paths.progress.clone(),
            ),
        )
    };
    let previous = make_path();
    previous.validation.exempt().unwrap();
    let old = Arc::new(Counter(AtomicUsize::new(0)));
    let old_waker = Waker::from(old.clone());
    let mut sender = std::pin::pin!(paths.send_via(&previous));
    assert!(sender.as_mut().poll(&mut Context::from_waker(&old_waker)).is_pending());
    assert!(paths.del_path(&previous));
    let replacement = make_path();
    let initial = common::initial_space(&paths.spaces);
    let live = Arc::new(Counter(AtomicUsize::new(0)));
    let live_waker = Waker::from(live.clone());
    let subscribe = |waker: &Waker| {
        let mut storage = [0; 128];
        let mut bytes = &mut storage[..];
        let mut frames = Vec::new();
        let packet_type = OneRttHeader::new(Default::default(), Default::default()).get_type();
        let mut buffer = PacketBuffer::new(&mut bytes, 128, &mut frames, packet_type, 0, 0);
        let mut cx = Context::from_waker(waker);
        assert!(initial.crypto.outgoing().poll_dump(&mut cx, &mut buffer).is_pending());
        // Consume the initial CID announcements before subscribing to an empty queue.
        let _ = paths.reliable_frames.clone().poll_dump(&mut cx, &mut buffer);
        assert!(paths.reliable_frames.clone().poll_dump(&mut cx, &mut buffer).is_pending());
    };
    // Model subscriptions left by a poll already in progress when the old path was removed.
    subscribe(&Waker::from(previous.send_waker.clone()));
    replacement.send_waker.register(&live_waker);
    replacement.send_waker.refresh(false);
    subscribe(&Waker::from(replacement.send_waker.clone()));
    assert!(
        matches!(sender.as_mut().poll(&mut Context::from_waker(&old_waker)), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
    );
    assert!(!paths.del_path(&previous));
    let old_before = old.0.load(Ordering::Relaxed);
    let live_before = live.0.load(Ordering::Relaxed);
    initial.crypto.writer().write_all(b"wake the live path").await.unwrap();
    paths.reliable_frames.send_frame([HandshakeDoneFrame]);
    assert_eq!(old.0.load(Ordering::Relaxed), old_before);
    assert!(live.0.load(Ordering::Relaxed) > live_before);
    assert!(Arc::ptr_eq(paths.entries.lock().unwrap().get(&replacement.pathway).unwrap(), &replacement));
    assert!(!replacement.validation.is_cancelled());
    paths.retire_all();
}

#[tokio::test]
async fn cancelled_collect_keeps_subscriptions_until_path_task_exits() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let paths =
        common::initial_paths(Role::Client, ConnectionId::from_slice(b"clientid"), ConnectionId::from_slice(b"original"), keys(false));
    let make_path = |port| {
        paths.add_path(Pathway::new(
            EndpointAddr::direct(([127, 0, 0, 1], port).into()),
            EndpointAddr::direct("127.0.0.1:32002".parse().unwrap()),
        ))
    };
    let first = make_path(32001);
    let second = make_path(32003);
    let mut first_bytes = [Datagram::default()];
    let mut second_bytes = [Datagram::default()];
    let mut first_frames = Vec::new();
    let mut second_frames = Vec::new();
    let a = Arc::new(Counter(AtomicUsize::new(0)));
    let b = Arc::new(Counter(AtomicUsize::new(0)));
    let wa = Waker::from(a.clone());
    let wb = Waker::from(b.clone());
    assert!(std::pin::pin!(first.collect(&mut first_bytes, &mut first_frames)).poll(&mut Context::from_waker(&wa)).is_pending());
    assert!(std::pin::pin!(second.collect(&mut second_bytes, &mut second_frames)).poll(&mut Context::from_waker(&wb)).is_pending());
    let initial = common::initial_space(&paths.spaces);
    initial.crypto.writer().write_all(b"hello").await.unwrap();
    assert!(a.0.load(Ordering::Relaxed) > 0);
    assert!(b.0.load(Ordering::Relaxed) > 0);
    // Keep the second task credit-blocked while the first task retires.
    crate::common::revalidate(&second);
    first.close();
    common::wait_for_sender_exit(&first).await;
    let first_before = a.0.load(Ordering::Relaxed);
    second.validation.on_received(1200);
    second.wake_sender();
    assert!(matches!(
        std::pin::pin!(second.collect(&mut second_bytes, &mut second_frames)).poll(&mut Context::from_waker(&wb)),
        Poll::Ready(Ok((1, _)))
    ));
    // Finish the simulated send and acknowledge CRYPTO to end automatic handshake replay.
    initial.crypto.outgoing().on_data_acked(&qbase::frame::CryptoFrame::new(0u32.into(), 5u32.into()));
    for datagram in &mut second_bytes {
        datagram.packets.clear();
    }
    second.refresh(&mut second_bytes, &mut second_frames);
    assert!(std::pin::pin!(second.collect(&mut second_bytes, &mut second_frames)).poll(&mut Context::from_waker(&wb)).is_pending());
    let before = b.0.load(Ordering::Relaxed);
    initial.crypto.writer().write_all(b"again").await.unwrap();
    assert_eq!(a.0.load(Ordering::Relaxed), first_before);
    assert!(b.0.load(Ordering::Relaxed) > before);
    second.close();
    paths.terminator.terminate();
    common::wait_for_sender_exit(&second).await;
    // Terminating the last path also notifies connection-close waiters.
    let first_before = a.0.load(Ordering::Relaxed);
    let before = b.0.load(Ordering::Relaxed);
    first.close();
    second.close();
    assert_eq!(a.0.load(Ordering::Relaxed), first_before);
    assert_eq!(b.0.load(Ordering::Relaxed), before);
}

#[tokio::test]
async fn collected_datagrams_cancel_on_deactivation_and_complete_when_cid_source_changes() {
    use qbase::{
        frame::{NewConnectionIdFrame, io::ReceiveFrame},
        net::route::{Line, Link},
        packet::GetDcid,
    };
    use qprotocol::{QuicProtocol, UdpSocket};

    for change in 0..3 {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let local = EndpointAddr::direct(socket.local_addr().unwrap());
        QuicProtocol::global().register(local, &socket).unwrap();
        let paths =
            common::initial_paths(Role::Client, ConnectionId::from_slice(b"client00"), ConnectionId::from_slice(b"original"), keys(false));
        let first = paths.add_path(Pathway::new(local, EndpointAddr::direct(peer.local_addr().unwrap())));
        let second = paths.add_path(Pathway::new(local, EndpointAddr::direct("127.0.0.1:9".parse().unwrap())));
        if change == 2 {
            paths.progress.on_initial_received(crate::common::cid_value(&paths.cid_registry.remote.apply_dcid()));
            paths.progress.on_path_selected(&paths, &first);
        }
        let initial = common::initial_space(&paths.spaces);
        initial.crypto.writer().write_all(b"client hello").await.unwrap();
        let mut datagrams = std::array::from_fn::<_, 8, _>(|_| Datagram::default());
        let mut frames = Vec::new();
        let (count, _) = first.collect(&mut datagrams, &mut frames).now_or_never().unwrap().unwrap();
        match change {
            0 => {
                paths.progress.on_initial_received(crate::common::cid_value(&paths.cid_registry.remote.apply_dcid()));
                paths.progress.on_path_selected(&paths, &second);
            }
            1 => {
                paths.progress.on_initial_received(ConnectionId::from_slice(b"server00"));
            }
            _ => {
                paths
                    .cid_registry
                    .remote
                    .recv_frame(NewConnectionIdFrame::new(ConnectionId::from_slice(b"server00"), 1u32.into(), 1u32.into()))
                    .unwrap();
            }
        }
        // Verify the CID on the wire after the policy changes and submission completes.
        first.send(&mut datagrams[..count], &paths.idle_timer()).await.unwrap();
        if change == 0 {
            first.refresh(&mut datagrams, &mut frames);
        } else {
            first.dcid.refresh();
        }
        assert!(datagrams.iter().all(|datagram| datagram.packets.is_empty()));
        let mut received = [BytesMut::zeroed(1500)];
        let mut lines = [Line::new(Link::new(local.addr(), peer.local_addr().unwrap()), 64, None, 1500)];
        if change == 0 {
            assert!(!first.is_active());
            assert!(peer.receive(&mut received, &mut lines).now_or_never().is_none());
            common::retire_all(&paths);
            common::wait_for_sender_exit(&first).await;
            common::wait_for_sender_exit(&second).await;
            QuicProtocol::global().unregister(socket.local_addr().unwrap());
            continue;
        }
        tokio::time::timeout(Duration::from_secs(1), peer.receive(&mut received, &mut lines)).await.unwrap().unwrap();
        received[0].truncate(lines[0].seg_size as usize);
        let ParsedPacket::Data(packet) = PacketReader::new(received[0].clone(), 8).next().unwrap().unwrap() else {
            panic!("expected Initial packet");
        };
        assert_eq!(*packet.header.dcid(), ConnectionId::from_slice(b"original"));
        {
            let journal = initial.sent_journal.lock_guard();
            assert!(count > 0);
            for bytes in &datagrams[..count] {
                let ParsedPacket::Data(packet) = PacketReader::new(bytes.bytes.clone(), 8).next().unwrap().unwrap() else {
                    panic!("expected Initial packet");
                };
                let DataHeader::Long(long::DataHeader::Initial(header)) = packet.header else {
                    panic!("expected Initial header");
                };
                let opened = CipherPacket::new(header, packet.bytes, packet.offset)
                    .open_long(&keys(true).opening, |pn| Ok(pn.decode(0)))
                    .unwrap()
                    .unwrap();
                assert!(journal.packet(opened.pn()).unwrap().size > 0);
            }
        }
        assert_eq!(
            first.dcid.poll_borrow(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(ConnectionId::from_slice(b"server00")))
        );
        first.dcid.refresh();
        common::retire_all(&paths);
        common::wait_for_sender_exit(&first).await;
        common::wait_for_sender_exit(&second).await;
        QuicProtocol::global().unregister(socket.local_addr().unwrap());
    }
}
