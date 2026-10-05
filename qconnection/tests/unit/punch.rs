use std::{sync::Arc, time::Duration};

use bytes::BytesMut;
use futures::FutureExt;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::ErrorKind,
    frame::{
        AddAddressFrame, ConnectionCloseFrame, Frame, FrameReader, HandshakeDoneFrame, PingFrame,
        PunchDoneFrame, PunchHelloFrame, PunchMeNowFrame, RemoveAddressFrame,
    },
    net::{
        NatType,
        addr::EndpointAddr,
        route::{Line, Link, Pathway},
    },
    packet::{DataHeader, OneRttHeader, Packet, PacketNumber, PacketReader},
    role::Role,
    time::heartbeat::ArcHeartbeat,
    token::{ArcTokenRegistry, handy::NoopTokenRegistry},
};
use qtransport::{keys::ArcKeys, path::Path, space::HandshakeSpace};
use qtraversal::punch::{ProbeEncoder, PunchPacketEncoder};

use crate::{
    ArcConnPhase, ArcHandshake, ArcParameters, MaturePhase, Paths, Scopes, common,
    recv::receive_1rtt_pkt_and_deliver_frames,
};

pub(super) fn pair() -> [Arc<super::MatureFixture>; 2] {
    let [mut client, mut server] = common::backends(false);
    let mut material = [None, None];
    while material.iter().any(Option::is_none) {
        while let Some(event) = client.next_event() {
            match event {
                qtls::TlsEvent::WriteCrypto {
                    epoch: level,
                    bytes,
                } => {
                    server.receive_crypto(level, &bytes).unwrap();
                }
                qtls::TlsEvent::InstallKeys(qtls::InstalledKeys::OneRtt(keys)) => {
                    material[0] = Some(keys);
                }
                _ => {}
            }
        }
        while let Some(event) = server.next_event() {
            match event {
                qtls::TlsEvent::WriteCrypto {
                    epoch: level,
                    bytes,
                } => {
                    client.receive_crypto(level, &bytes).unwrap();
                }
                qtls::TlsEvent::InstallKeys(qtls::InstalledKeys::OneRtt(keys)) => {
                    material[1] = Some(keys);
                }
                _ => {}
            }
        }
    }
    let (client_params, server_params) = common::parameters();
    [Role::Client, Role::Server]
        .into_iter()
        .zip(material)
        .map(|(role, keys)| {
            let parameters = ArcParameters::new(
                role,
                Arc::new(client_params.clone()),
                Arc::new(server_params.clone()),
            );
            let scid = parameters.local(qbase::param::ParameterId::InitialSourceConnectionId);
            let peer = parameters.remote(qbase::param::ParameterId::InitialSourceConnectionId);
            let initial = crate::common::initial_phase(
                role,
                scid,
                ConnectionId::from_slice(b"original"),
                common::initial_keys(role == Role::Server),
            );
            let registry = initial.cid_registry.clone();
            let handshake = Arc::new(HandshakeSpace::new(
                Default::default(),
                ArcKeys::new(Arc::new(common::initial_keys(role == Role::Server))),
            ));
            let reliable_frames = initial.reliable_frames.clone();
            let streams = crate::DataStreams::new(
                parameters.clone(),
                Box::new(qbase::sid::handy::ConsistentConcurrency::new(
                    parameters.local(qbase::param::ParameterId::InitialMaxStreamsBidi),
                    parameters.local(qbase::param::ParameterId::InitialMaxStreamsUni),
                )),
                reliable_frames.clone(),
                None,
            );
            let flow = crate::FlowController::new(
                parameters.remote(qbase::param::ParameterId::InitialMaxData),
                parameters.local(qbase::param::ParameterId::InitialMaxData),
                reliable_frames.clone(),
            );
            let data = Arc::new(qtransport::space::DataSpace::new(
                Default::default(),
                keys.unwrap().into(),
                streams,
                reliable_frames.clone(),
            ));
            let puncher = qtraversal::punch::ArcPuncher::new(
                reliable_frames,
                qtraversal::punch::ProbeEncoder::new(data.clone(), peer),
            );
            let concrete = super::SpaceFixture {
                initial: crate::common::initial_space(&initial.spaces),
                handshake,
                data,
            };
            let phase = Arc::new(MaturePhase {
                spaces: initial.spaces.clone(),
                scid: initial.scid,
                flow_ctrl: flow,
                cid_registry: registry,
                dcid: peer,
                parameters,
                puncher,
                resender: initial.resender.clone(),
                terminator: initial.terminator.clone(),
            });
            let phase = Arc::new(super::MatureFixture {
                phase,
                spaces: concrete,
            });
            // CID registration can queue NEW_CONNECTION_ID before any punch input.
            take_reliable(&phase);
            phase
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| unreachable!())
}

fn encoder(phase: &super::MatureFixture) -> ProbeEncoder {
    ProbeEncoder::new(phase.spaces.data.clone(), phase.dcid)
}

fn encode_frame(
    phase: &super::MatureFixture,
    mut frame: impl for<'b> qbase::packet::Package<&'b mut BytesMut>,
) -> BytesMut {
    encode_frames(phase, [&mut frame])
}

fn encode_frames<const N: usize>(
    phase: &super::MatureFixture,
    frames: [&mut dyn for<'b> qbase::packet::Package<&'b mut BytesMut>; N],
) -> BytesMut {
    use qbase::packet::{Constraints, assemble::Assemble};

    let space = &phase.spaces.data;
    let keys = space.keys.get().unwrap();
    let (pn, key) = keys
        .reserve(|_| space.next_pn().map_err(Into::into))
        .unwrap();
    let mut bytes = BytesMut::with_capacity(1200);
    let packet = crate::send::Packet::new(
        OneRttHeader::new(Default::default(), phase.dcid),
        pn,
        &mut bytes,
    )
    .unwrap();
    let mut limits = Constraints {
        flow_ctrl: usize::MAX,
        send_quota: 1200,
        credit: 1200,
        max_size: 1200,
        ..Default::default()
    };
    let mut sending = crate::send::Envelope {
        packet,
        keys: &key,
        limits: &mut limits,
    };
    assert!(matches!(
        sending.assemble(
            &mut std::task::Context::from_waker(std::task::Waker::noop()),
            frames.map(|frame| frame as &mut dyn qbase::packet::Package<&mut BytesMut>),
            &mut Vec::new(),
        ),
        std::task::Poll::Ready(Ok(n)) if n > 0
    ));
    sending.seal().unwrap();
    bytes
}

fn empty_paths(phase: &super::MatureFixture) -> Arc<Paths> {
    let role = phase.parameters.role();
    let snapshot = ArcConnPhase::initial(crate::common::initial_phase(
        role,
        phase.scid,
        ConnectionId::from_slice(b"original"),
        common::initial_keys(role == Role::Server),
    ));
    let paths = Paths::new(role, snapshot, Duration::ZERO, Duration::ZERO);
    let terminator = paths.phase().terminator();
    terminator.register(Arc::new(phase.spaces.data.crypto.clone()));
    terminator.register(Arc::new(phase.spaces.data.streams.clone()));
    terminator.register(Arc::new(phase.flow_ctrl.clone()));
    paths
}

async fn receive(
    phase: &Arc<super::MatureFixture>,
    packets: Vec<BytesMut>,
    pathway: Pathway,
    link: Link,
) {
    let paths = empty_paths(phase);
    // Preinstall a path without a sender so responses stay inspectable in the queue.
    let crate::ConnPhase::Initial(initial) = paths.phase().get() else {
        panic!("expected Initial");
    };
    let path = Arc::new(Path::new(
        pathway,
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        initial.resender.clone(),
    ));
    paths.entries.lock().unwrap().insert(pathway, path);
    receive_on_paths(phase, &paths, packets, pathway, link, Scopes::ALL).await;
    for path in paths.snapshot() {
        paths.remove(&path);
    }
}

async fn receive_on_paths(
    phase: &Arc<super::MatureFixture>,
    paths: &Arc<Paths>,
    packets: Vec<BytesMut>,
    pathway: Pathway,
    link: Link,
    scopes: Scopes,
) -> ArcHandshake {
    let (tx, rx) = tokio::sync::mpsc::channel(packets.len());
    for bytes in packets {
        let Packet::Data(packet) = PacketReader::new(bytes, 8).next().unwrap().unwrap() else {
            panic!("expected Data packet");
        };
        let DataHeader::Short(header) = packet.header else {
            panic!("expected 1-RTT packet");
        };
        tx.try_send((
            qtransport::packet::CipherPacket::new(header, packet.bytes, packet.offset),
            pathway,
            link,
        ))
        .unwrap();
    }
    drop(tx);
    let closed = paths.phase().terminator();
    let notification = crate::common::observe_close(&closed);
    let tokens = ArcTokenRegistry::with_sink("localhost".into(), Arc::new(NoopTokenRegistry));
    let role = phase.parameters.role();
    let handshake = ArcHandshake::new(role, phase.spaces.data.reliable_frames.clone());
    receive_1rtt_pkt_and_deliver_frames(
        (rx, (role == Role::Server).then_some(scopes)),
        phase.spaces.data.clone(),
        phase.flow_ctrl.clone(),
        phase.puncher.clone(),
        paths.clone(),
        phase.parameters.clone(),
        phase.cid_registry.clone(),
        tokens,
        handshake.clone(),
    )
    .await;
    assert!(
        notification.notified().is_none(),
        "received frames must not close the connection"
    );
    handshake
}

#[tokio::test]
async fn data_reception_delivers_crypto_and_streams_to_the_data_space() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let pair = pair();
    for (sender, receiver) in [(&pair[0], &pair[1]), (&pair[1], &pair[0])] {
        let data = &sender.spaces.data;
        data.crypto.writer().write_all(b"ticket").await.unwrap();
        let (_, mut writer) = data.streams.open_uni().await.unwrap().unwrap();
        writer.write_all(b"stream").await.unwrap();
        let mut crypto = data.crypto.outgoing();
        let mut streams = data.streams.clone();
        let bytes = encode_frames(sender, [&mut crypto, &mut streams]);
        let link = Link::new(
            "127.0.0.1:47001".parse().unwrap(),
            "127.0.0.1:47002".parse().unwrap(),
        );
        receive(receiver, vec![bytes.clone(), bytes], link.into(), link).await;

        let mut body = [0; 6];
        receiver
            .spaces
            .data
            .crypto
            .reader()
            .read_exact(&mut body)
            .now_or_never()
            .unwrap()
            .unwrap();
        assert_eq!(&body, b"ticket");
        for space in [receiver.spaces.initial.as_ref(), &receiver.spaces.handshake.0] {
            assert!(
                space
                    .crypto
                    .reader()
                    .read(&mut body)
                    .now_or_never()
                    .is_none()
            );
        }
        let (_, mut reader) = receiver
            .spaces
            .data
            .streams
            .accept_uni()
            .now_or_never()
            .unwrap()
            .unwrap();
        reader
            .read_exact(&mut body)
            .now_or_never()
            .unwrap()
            .unwrap();
        assert_eq!(&body, b"stream");
        assert!(reader.read(&mut body).now_or_never().is_none());
    }
}

#[tokio::test]
async fn handshake_done_confirms_the_shared_client_handshake() {
    let [receiver, sender] = pair();
    let paths = empty_paths(&receiver);
    let link = Link::new(
        "127.0.0.1:45001".parse().unwrap(),
        "127.0.0.1:45002".parse().unwrap(),
    );
    let handshake = receive_on_paths(
        &receiver,
        &paths,
        vec![
            encode_frame(&sender, HandshakeDoneFrame),
            encode_frame(&sender, HandshakeDoneFrame),
        ],
        link.into(),
        link,
        Scopes::ALL,
    )
    .await;
    assert!(handshake.is_handshake_done());
    assert_eq!(handshake.now_or_never(), Some(()));
    paths.retire_all();
}

#[tokio::test]
async fn data_close_follows_frame_order_and_reception_continues_after_errors() {
    use tokio::io::AsyncReadExt;

    let close = ConnectionCloseFrame::new_app(7u32.into(), "peer closed");
    for (role, bundled_close) in [
        (Role::Client, true),
        (Role::Server, true),
        (Role::Server, false),
    ] {
        let pair = pair();
        let (receiver, sender) = if role == Role::Client {
            (&pair[0], &pair[1])
        } else {
            (&pair[1], &pair[0])
        };
        let paths = empty_paths(receiver);
        let closed = paths.phase().terminator();
        let notification = crate::common::observe_close(&closed);
        let first = if bundled_close {
            encode_frames(sender, [&mut HandshakeDoneFrame, &mut close.clone()])
        } else {
            encode_frame(sender, HandshakeDoneFrame)
        };
        let link = Link::new(
            "127.0.0.1:46001".parse().unwrap(),
            "127.0.0.1:46002".parse().unwrap(),
        );
        let (tx, rx) = tokio::sync::mpsc::channel(3);
        for bytes in [
            first,
            encode_frame(sender, close.clone()),
            encode_frame(sender, PingFrame),
        ] {
            let Packet::Data(packet) = PacketReader::new(bytes, 8).next().unwrap().unwrap() else {
                panic!("expected Data packet");
            };
            let DataHeader::Short(header) = packet.header else {
                panic!("expected 1-RTT packet");
            };
            tx.try_send((
                qtransport::packet::CipherPacket::new(header, packet.bytes, packet.offset),
                link.into(),
                link,
            ))
            .unwrap();
        }
        drop(tx);
        let handshake = ArcHandshake::new(
            receiver.parameters.role(),
            receiver.spaces.data.reliable_frames.clone(),
        );
        receive_1rtt_pkt_and_deliver_frames(
            (rx, Some(Scopes::ALL)),
            receiver.spaces.data.clone(),
            receiver.flow_ctrl.clone(),
            receiver.puncher.clone(),
            paths.clone(),
            receiver.parameters.clone(),
            receiver.cid_registry.clone(),
            ArcTokenRegistry::with_sink("localhost".into(), Arc::new(NoopTokenRegistry)),
            handshake.clone(),
        )
        .await;
        let stream_error = receiver.spaces.data.streams.accept_uni().await.unwrap_err();
        assert_eq!(notification.notified(), Some(stream_error.clone()));
        if role == Role::Client {
            assert_eq!(stream_error, close.clone().into());
        } else {
            assert_eq!(stream_error.kind(), ErrorKind::ProtocolViolation);
        }
        assert!(futures::poll!(std::pin::pin!(closed.clone())).is_pending());
        assert_eq!(handshake.is_handshake_done(), role == Role::Client);
        assert!(receiver.spaces.data.streams.accept_uni().await.is_err());
        assert!(receiver.spaces.data.streams.accept_bi().await.is_err());
        assert!(
            receiver
                .spaces
                .data
                .crypto
                .reader()
                .read(&mut [0; 1])
                .now_or_never()
                .unwrap()
                .is_err()
        );
        let journal = &receiver.spaces.data.rcvd_journal;
        for pn in [0, 1] {
            assert_eq!(journal.decode_pn(PacketNumber::encode(pn, 0)), Ok(pn));
        }
        assert_eq!(
            journal.decode_pn(PacketNumber::encode(2, 0)),
            Err(qbase::packet::InvalidPacketNumber::Duplicate)
        );
        paths.retire_all();
        assert_eq!(closed.await, close.clone().into());
    }
}

#[tokio::test]
async fn data_authentication_controls_path_admission_and_receive_credit() {
    use qtransport::path::PathState;

    let pair = pair();
    for (receiver, sender) in [(&pair[0], &pair[1]), (&pair[1], &pair[0])] {
        let paths = empty_paths(receiver);
        let link = Link::new(
            "127.0.0.1:43001".parse().unwrap(),
            "127.0.0.1:43002".parse().unwrap(),
        );
        let packet = encoder(sender)
            .encode_probe(PunchDoneFrame::new(1, 2, 3))
            .unwrap();
        let mut forged = packet.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(
            paths.pto_for(&link.into(), Epoch::Data),
            Duration::from_secs(1)
        );
        assert!(paths.snapshot().is_empty());
        receive_on_paths(
            receiver,
            &paths,
            vec![forged.clone()],
            link.into(),
            link,
            Scopes::ALL,
        )
        .await;
        assert!(
            paths.snapshot().is_empty(),
            "forged 1-RTT must not start a path sender"
        );

        receive_on_paths(
            receiver,
            &paths,
            vec![packet.clone()],
            link.into(),
            link,
            Scopes::ALL,
        )
        .await;
        let admitted = paths.snapshot();
        assert_eq!(admitted.len(), 1);
        let path = &admitted[0];
        assert_eq!(path.pathway, link.into());
        let expected = PathState::AmplifyGuard {
            rcvd_bytes: packet.len(),
            sent_bytes: 0,
        };
        assert_eq!(path.state(), expected);

        // Neither failed authentication nor duplicate packets credit an existing path.
        receive_on_paths(
            receiver,
            &paths,
            vec![forged, packet.clone()],
            link.into(),
            link,
            Scopes::ALL,
        )
        .await;
        assert!(Arc::ptr_eq(&paths.snapshot()[0], path));
        assert_eq!(path.state(), expected);

        // A replay with a new source address must not create a second path.
        let replay_link = Link::new(link.src, "127.0.0.1:43003".parse().unwrap());
        receive_on_paths(
            receiver,
            &paths,
            vec![packet],
            replay_link.into(),
            replay_link,
            Scopes::ALL,
        )
        .await;
        assert_eq!(paths.snapshot().len(), 1);
        paths.retire_all();
    }
}

#[tokio::test]
async fn server_rejects_out_of_scope_sources_before_path_admission() {
    use qbase::net::route::Scope;

    let [sender, receiver] = pair();
    let paths = empty_paths(&receiver);
    let scopes = Scope::Loopback.into();
    let link = Link::new(
        "127.0.0.1:44001".parse().unwrap(),
        "127.0.0.1:44002".parse().unwrap(),
    );
    let outside = Pathway::new(
        link.src.into(),
        EndpointAddr::direct("192.0.2.1:44002".parse().unwrap()),
    );
    let packet = encoder(&sender)
        .encode_probe(PunchDoneFrame::new(1, 2, 3))
        .unwrap();
    receive_on_paths(
        &receiver,
        &paths,
        vec![packet.clone()],
        outside,
        link,
        scopes,
    )
    .await;
    assert!(paths.snapshot().is_empty());
    receive_on_paths(&receiver, &paths, vec![packet], link.into(), link, scopes).await;
    assert_eq!(paths.snapshot().len(), 1);
    paths.retire_all();
}

#[tokio::test]
async fn authenticated_packets_start_validation_on_new_post_handshake_paths() {
    let pair = pair();
    for (receiver, sender) in [(&pair[0], &pair[1]), (&pair[1], &pair[0])] {
        let paths = empty_paths(receiver);
        let local: EndpointAddr = "127.0.0.1:44501".parse().unwrap();
        let original = paths
            .add_path(Pathway::new(local, "127.0.0.1:44502".parse().unwrap()));
        paths.select_path(&original);
        super::confirm_handshake(&paths);
        paths.activate_paths(&original);
        let link = Link::new(local.addr(), "127.0.0.1:44503".parse().unwrap());
        let packet = encoder(sender)
            .encode_probe(PunchDoneFrame::new(1, 2, 3))
            .unwrap();
        let mut forged = packet.clone();
        *forged.last_mut().unwrap() ^= 1;
        receive_on_paths(
            receiver,
            &paths,
            vec![forged],
            link.into(),
            link,
            Scopes::ALL,
        )
        .await;
        assert!(
            paths.get(&link.into()).is_none(),
            "forged packet admitted a path"
        );
        receive_on_paths(
            receiver,
            &paths,
            vec![packet],
            link.into(),
            link,
            Scopes::ALL,
        )
        .await;
        tokio::task::yield_now().await;
        let path = paths.get(&link.into()).unwrap();
        assert_eq!(path.selected(), Path::HANDSHAKED);
        assert!(
            path.challenge().is_some(),
            "authenticated ingress must start validation"
        );
        assert!(!path.is_validated());
        assert!(original.is_validated());
        paths.retire_all();
    }
}

fn take_reliable(phase: &super::MatureFixture) -> Vec<Frame> {
    use qbase::packet::{PacketBuffer, Constraints, GetType, Package};
    let mut bytes = BytesMut::with_capacity(1200);
    let mut limits = Constraints {
        flow_ctrl: usize::MAX,
        send_quota: 1200,
        credit: 1200,
        max_size: 1200,
        ..Default::default()
    };
    let mut frames = Vec::new();
    let _ = phase.spaces.data.reliable_frames.clone().poll_dump(
        &mut std::task::Context::from_waker(std::task::Waker::noop()),
        &mut PacketBuffer::new(
            &mut bytes,
            &mut limits,
            &mut frames,
            OneRttHeader::new(Default::default(), phase.dcid).get_type(),
            0,
            0,
        ),
    );
    frames.into_iter().map(Into::into).collect()
}

#[tokio::test]
async fn both_roles_dispatch_all_five_authenticated_punch_frames() {
    let pair = pair();
    for (receiver, sender) in [(&pair[0], &pair[1]), (&pair[1], &pair[0])] {
        let encoder = encoder(sender);
        let hello = PunchHelloFrame::new(11, 22, 33);
        let packets = vec![
            encoder
                .encode_probe(AddAddressFrame::new(
                    11,
                    "127.0.0.1:41002".parse().unwrap(),
                    0,
                    NatType::FullCone,
                ))
                .unwrap(),
            encoder
                .encode_probe(PunchMeNowFrame::new(
                    11,
                    22,
                    "127.0.0.1:41002".parse().unwrap(),
                    0,
                    NatType::FullCone,
                ))
                .unwrap(),
            encoder.encode_probe(hello).unwrap(),
            encoder
                .encode_probe(PunchDoneFrame::new(11, 22, 33))
                .unwrap(),
            encoder
                .encode_probe(RemoveAddressFrame {
                    seq_num: 11u32.into(),
                })
                .unwrap(),
        ];
        let link = Link::new(
            "127.0.0.1:41001".parse().unwrap(),
            "127.0.0.1:41002".parse().unwrap(),
        );
        receive(receiver, packets, link.into(), link).await;
        assert!(
            matches!(take_reliable(receiver).as_slice(), [Frame::PunchDone(done)]
            if *done == PunchDoneFrame::respond_to(&hello))
        );
    }
}

#[tokio::test]
async fn unauthenticated_hello_does_not_reach_puncher() {
    let pair = pair();
    for (receiver, sender) in [(&pair[0], &pair[1]), (&pair[1], &pair[0])] {
        let hello = PunchHelloFrame::new(1, 2, 3);
        let packet = encoder(sender).encode_probe(hello).unwrap();
        let mut corrupted = packet.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        let link = Link::new(
            "127.0.0.1:42001".parse().unwrap(),
            "127.0.0.1:42002".parse().unwrap(),
        );
        receive(receiver, vec![corrupted], link.into(), link).await;
        assert!(take_reliable(receiver).is_empty());
        receive(receiver, vec![packet], link.into(), link).await;
        assert!(
            matches!(take_reliable(receiver).as_slice(), [Frame::PunchDone(done)]
            if *done == PunchDoneFrame::respond_to(&hello))
        );
    }
}

#[tokio::test]
async fn hello_replies_on_received_link_using_connection_keys_and_packet_numbers() {
    let [receiver, sender] = pair();
    let local = qprotocol::EphemeralSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let peer = qprotocol::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let link = Link::new(
        local.udp_socket().local_addr().unwrap(),
        peer.local_addr().unwrap(),
    );
    // The advertised peer differs from the datagram source. Replies must use Link.
    let pathway = Pathway::new(
        link.src.into(),
        EndpointAddr::direct("192.0.2.1:9".parse().unwrap()),
    );
    let hello = PunchHelloFrame::new(1, 2, 3);
    let prior = receiver.spaces.data.next_pn().unwrap().0;
    qtransport::space::Recover::cancel(
        receiver.spaces.data.as_ref(),
        prior,
        &mut std::iter::empty(),
    );
    receive(
        &receiver,
        vec![encoder(&sender).encode_probe(hello).unwrap()],
        pathway,
        link,
    )
    .await;
    let mut buffers = [BytesMut::with_capacity(1500)];
    buffers[0].resize(1500, 0);
    let mut lines = [Line::new(link.flip(), 64, None, 1500)];
    tokio::time::timeout(
        Duration::from_secs(1),
        peer.receive(&mut buffers, &mut lines),
    )
    .await
    .unwrap()
    .unwrap();
    buffers[0].truncate(lines[0].seg_size as usize);
    let Packet::Data(packet) = PacketReader::new(buffers[0].clone(), 8)
        .next()
        .unwrap()
        .unwrap()
    else {
        panic!()
    };
    let DataHeader::Short(header) = packet.header else {
        panic!()
    };
    let opened = sender
        .spaces
        .data
        .keys
        .get()
        .unwrap()
        .open_packet(
            qtransport::packet::CipherPacket::new(header, packet.bytes, packet.offset),
            |pn| sender.spaces.data.rcvd_journal.decode_pn(pn),
            Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();
    assert_eq!(opened.pn(), prior + 1);
    use qbase::packet::GetType;
    assert!(FrameReader::new(opened.body(), opened.get_type()).any(|frame|
        matches!(frame.unwrap().0, Frame::PunchDone(done) if done == PunchDoneFrame::respond_to(&hello))
    ));
    // Let the finite direct-confirmation task finish before releasing its socket.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test(start_paused = true)]
async fn data_packets_update_shared_idle_and_only_effective_payload_starts_heartbeat() {
    use qbase::frame::{AckFrame, CryptoFrame};
    use tokio::time::Instant;

    for kind in 0..3 {
        let [sender, receiver] = pair();
        let paths = empty_paths(&receiver);
        paths.update_max_idle_timeout(Duration::from_secs(5));
        let link = Link::new(
            "127.0.0.1:47001".parse().unwrap(),
            "127.0.0.1:47002".parse().unwrap(),
        );
        let crate::ConnPhase::Initial(initial) = paths.phase().get() else {
            panic!("expected Initial");
        };
        let path = Arc::new(Path::new(
            link.into(),
            paths.handshake.clone(),
            ArcHeartbeat::new(Duration::from_secs(60), Duration::ZERO),
            initial.resender.clone(),
        ));
        paths
            .entries
            .lock()
            .unwrap()
            .insert(path.pathway, path.clone());
        let data = &receiver.spaces.data;
        let pn = data.next_pn().unwrap().0;
        qtransport::space::Transmit::on_sealed(data.as_ref(), pn, Some(0), 0,
            qbase::packet::assemble::Metadata::new(qbase::packet::GetType::get_type(&OneRttHeader::new(Default::default(), Default::default()))),
            &mut std::iter::empty());
        data.on_sent(
            [(pn, false)],
            Duration::from_secs(1),
            Duration::from_secs(3),
        );
        let bytes = match kind {
            0 => encode_frame(
                &sender,
                AckFrame::new(0u32.into(), 0u32.into(), 0u32.into(), vec![], None),
            ),
            1 => encode_frame(&sender, PingFrame),
            _ => encode_frame(
                &sender,
                (CryptoFrame::new(0u32.into(), 1u32.into()), b"x".as_slice()),
            ),
        };
        let start = Instant::now();
        receive_on_paths(
            &receiver,
            &paths,
            vec![bytes],
            path.pathway,
            link,
            Scopes::ALL,
        )
        .await;
        let closing_duration = path.cc.pto_base(Epoch::Data) * 3;
        let reason = paths.phase().terminator().await;
        assert!(
            matches!(reason, crate::Error::Quic(error) if error.reason() == "connection idle timeout")
        );
        assert_eq!(Instant::now() - start, Duration::from_secs(5) + closing_duration);
        tokio::time::advance(Duration::from_secs(15)).await;
        assert_eq!(super::take_heartbeat(&path), kind == 2);
        paths.retire_all();
    }
}
