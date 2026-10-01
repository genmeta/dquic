use std::time::Duration;

use bytes::BytesMut;
use futures::FutureExt;
use qbase::{
    cid::ConnectionId,
    frame::{
        AddAddressFrame, ConnectionCloseFrame, FrameReader, HandshakeDoneFrame, PingFrame,
        PunchDoneFrame, PunchHelloFrame, PunchMeNowFrame, RemoveAddressFrame,
    },
    net::{NatType, addr::EndpointAddr, route::Line},
    packet::{DataHeader, Packet, PacketNumber, PacketReader},
    time::ArcConnIdle,
    token::handy::NoopTokenRegistry,
};
use qtraversal::punch::{ProbeEncoder, PunchPacketEncoder};

use super::*;
use crate::{ArcConnPhase, InitialPhase};

#[path = "../../tests/common/mod.rs"]
mod common;

fn pair() -> [Arc<MaturePhase>; 2] {
    let [mut client, mut server] = common::backends(false);
    let mut material = [None, None];
    while material.iter().any(Option::is_none) {
        while let Some(event) = client.next_event() {
            match event {
                qtls::TlsEvent::WriteCrypto { epoch: level, bytes } => {
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
                qtls::TlsEvent::WriteCrypto { epoch: level, bytes } => {
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
            let initial = InitialPhase::new(
                scid,
                ConnectionId::from_slice(b"original"),
                super::tests::keys(role == Role::Server),
            );
            let router = Arc::new(qtransport::router::QuicRouter::new());
            let (inbox, _) = qtransport::packet::channel::new();
            let registry = crate::CidRegistry::new(
                role,
                initial.odcid,
                crate::ArcLocalCids::new(
                    scid,
                    router.registry_on_issuing_scid(inbox, initial.reliable_frames.clone()),
                ),
                qbase::cid::ArcRemoteCids::new(2, initial.reliable_frames.clone()),
            );
            let dcid = registry.remote.apply_dcid();
            registry.remote.apply_initial_dcid(peer, &dcid);
            let phase = MaturePhase::new(
                &initial,
                Arc::new(Space::new(
                    Epoch::Handshake,
                    ArcKeys::new(Arc::new(super::tests::keys(role == Role::Server))),
                )),
                parameters,
                peer,
                initial.reliable_frames.clone(),
                registry,
                dcid,
                keys.unwrap().into(),
            );
            // CID registration can queue NEW_CONNECTION_ID before any punch input.
            take_reliable(&phase);
            phase
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| unreachable!())
}

fn encoder(phase: &MaturePhase) -> ProbeEncoder {
    ProbeEncoder::new(phase.spaces.data.clone(), phase.peer_cid)
}

fn encode_frame(
    phase: &MaturePhase,
    mut frame: impl for<'b> qbase::packet::Package<&'b mut BytesMut>,
) -> BytesMut {
    encode_frames(phase, [&mut frame])
}

fn encode_frames<const N: usize>(
    phase: &MaturePhase,
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
        OneRttHeader::new(Default::default(), phase.peer_cid),
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
    let mut sending = crate::send::SendingPacket {
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

fn empty_paths(phase: &MaturePhase) -> Arc<Paths> {
    let role = phase.parameters.role();
    let snapshot = ArcConnPhase::initial(InitialPhase::new(
        phase.scid,
        ConnectionId::from_slice(b"original"),
        super::tests::keys(role == Role::Server),
    ));
    let idle = ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
    Paths::new(role, snapshot, idle)
}

async fn receive(phase: &Arc<MaturePhase>, packets: Vec<BytesMut>, pathway: Pathway, link: Link) {
    let paths = empty_paths(phase);
    // Preinstall a path without a sender so responses stay inspectable in the queue.
    let path = Arc::new(Path::new(
        pathway,
        paths.handshake.clone(),
        paths.idle().timer(),
        paths.phase().get().trackers(),
    ));
    paths.entries.lock().unwrap().insert(pathway, path);
    receive_on_paths(phase, &paths, packets, pathway, link, Scopes::ALL).await;
    paths.retire_all();
}

async fn receive_on_paths(
    phase: &Arc<MaturePhase>,
    paths: &Arc<Paths>,
    packets: Vec<BytesMut>,
    pathway: Pathway,
    link: Link,
    scopes: Scopes,
) -> ArcHandshake<ArcReliableFrames> {
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
    let closed = paths.closed();
    let tokens = ArcTokenRegistry::with_sink("localhost".into(), Arc::new(NoopTokenRegistry));
    let role = phase.parameters.role();
    let handshake = ArcHandshake::new(role, phase.spaces.data.reliable_frames.clone());
    receive_data(
        (rx, (role == Role::Server).then_some(scopes)),
        phase.clone(),
        paths.clone(),
        phase.parameters.clone(),
        phase.cid_registry.clone(),
        tokens,
        handshake.clone(),
    )
    .await;
    assert!(
        closed.now_or_never().is_none(),
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
        for space in [&receiver.spaces.initial, &receiver.spaces.handshake] {
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
async fn data_close_takes_priority_and_reception_continues_after_errors() {
    use tokio::io::AsyncReadExt;

    let close = ConnectionCloseFrame::new_app(7u32.into(), "peer closed");
    for (role, peer_close) in [
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
        let closed = paths.closed();
        let first = if peer_close {
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
        receive_data(
            (rx, Some(Scopes::ALL)),
            receiver.clone(),
            paths.clone(),
            receiver.parameters.clone(),
            receiver.cid_registry.clone(),
            ArcTokenRegistry::with_sink("localhost".into(), Arc::new(NoopTokenRegistry)),
            handshake.clone(),
        )
        .await;
        let reason = closed.now_or_never().unwrap().unwrap().unwrap();
        if peer_close {
            assert!(matches!(reason, CloseReason::Peer(frame) if frame == close));
        } else {
            assert!(matches!(reason, CloseReason::Internal(error)
                if error.kind() == ErrorKind::ProtocolViolation));
        }
        assert!(matches!(
            &*paths.terminator().lock_guard(),
            Terminator::Draining { .. }
        ));
        assert!(!handshake.is_handshake_done());
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
        assert!(journal.decode_pn(PacketNumber::encode(2, 0)).is_err());
        paths.retire_all();
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
            .add_path(Pathway::new(local, "127.0.0.1:44502".parse().unwrap()))
            .unwrap();
        paths.select_path(&original);
        paths.handshake_confirmed();
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

fn take_reliable(phase: &MaturePhase) -> Vec<Frame> {
    use qbase::packet::{ConstraintBuffer, Constraints, GetType, Package};
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
        &mut ConstraintBuffer::new(
            &mut bytes,
            &mut limits,
            OneRttHeader::new(Default::default(), phase.peer_cid).get_type(),
            0,
            0,
        ),
        &mut frames,
    );
    frames
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
    receiver.spaces.data.cancel(prior);
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
