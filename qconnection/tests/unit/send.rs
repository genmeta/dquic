use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::BytesMut;
use futures::FutureExt;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    frame::{Frame, FrameReader, GuaranteedFrame, PingFrame},
    net::{addr::EndpointAddr, route::Pathway},
    packet::{
        DataHeader, LongHeaderBuilder, Packet as ParsedPacket, PacketReader,
        assemble::{Assemble, Constraints},
        long,
    },
    param::ParameterId,
    role::Role,
    time::heartbeat::ArcHeartbeat,
};
use qcongestion::Transport as _;
use qtransport::{keys::ArcKeys, packet::CipherPacket, path::Path, space::HandshakeSpace};
use tokio::io::AsyncWriteExt;

use crate::{
    ConnPhase, InitialPhase, MaturePhase, Paths,
    common::initial_keys as keys,
    send::{BurstPns, Envelope, MAX_BURST_PACKETS, Packet, burst, sending, task},
};

#[tokio::test]
async fn idle_sending_loop_waits_for_sources_and_exits_when_retired() {
    let initial = crate::common::initial_phase(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let trackers = initial.resender.clone();
    let phase = crate::ArcConnPhase::initial(initial);
    let paths = Paths::new(Role::Client, phase.clone(), Duration::ZERO, Duration::ZERO);
    let pathway = Pathway::new(
        EndpointAddr::direct("127.0.0.1:30001".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:30002".parse().unwrap()),
    );
    let path = Arc::new(Path::new(
        pathway,
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        trackers.clone(),
    ));
    path.client_handshaking();
    let watchdog = std::thread::spawn({
        let path = path.clone();
        move || {
            std::thread::sleep(Duration::from_millis(50));
            path.retire();
        }
    });
    let mut running = Box::pin(sending(paths, path));
    assert!(futures::poll!(&mut running).is_pending());
    watchdog.join().unwrap();
    running.await;
}

#[tokio::test(start_paused = true)]
async fn retired_initial_is_discarded_before_polling_an_expired_pto() {
    let dcid_cell = OnceLock::new();
    let initial = crate::common::initial_phase(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let trackers = initial.resender.clone();
    let phase = crate::ArcConnPhase::initial(initial);
    super::enter_handshake(&phase, Arc::new(HandshakeSpace::new(
        Default::default(),
        ArcKeys::new(Arc::new(keys(false))),
    )));
    let paths = Paths::new(Role::Client, phase, Duration::ZERO, Duration::ZERO);
    let path = Arc::new(Path::new(
        Pathway::new(
            "127.0.0.1:4400".parse::<EndpointAddr>().unwrap(),
            "127.0.0.1:5500".parse().unwrap(),
        ),
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        trackers.clone(),
    ));
    path.client_handshaking();
    path.decide(true);
    path.cc
        .on_pkt_sent(Epoch::Initial, 0, true, 1200, true, None);
    paths.on_handshake_sent();
    // Initial remains queued until growing cleans up; retired keys must already stop assembly.
    assert_eq!(paths.phase().get().spaces().read().unwrap().0.offset(), 0);
    tokio::time::advance(Duration::from_secs(10)).await;
    let mut datagrams =
        std::array::from_fn::<_, MAX_BURST_PACKETS, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::new();
    let mut pns: BurstPns = [[None; 3]; MAX_BURST_PACKETS];
    let mut collect = Box::pin(
        burst(
            &path.cc,
            &path.anti_amplifier,
            &mut datagrams,
            &mut frames,
            &mut pns,
        )
        .collect(&paths, &path, &dcid_cell),
    );
    assert!(futures::poll!(&mut collect).is_pending());
    assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Initial), 0);
    // While waiting for HANDSHAKE_DONE, an anti-deadlock probe must use live Handshake keys.
    tokio::time::advance(path.cc.pto_base(Epoch::Handshake)).await;
    path.cc.do_tick().unwrap();
    assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Initial), 0);
    assert_eq!(path.cc.need_send_ack_eliciting(Epoch::Handshake), 1);
    assert!(matches!(futures::poll!(&mut collect), Poll::Ready(Ok(1))));
    assert_eq!(pns_for(collect.burst.pns, Epoch::Handshake).count(), 1);
}

#[tokio::test(start_paused = true)]
async fn failed_submission_closes_crypto_and_waits_for_termination() {
    let initial = crate::common::initial_phase(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let space = crate::common::initial_space(&initial.spaces);
    space.crypto.writer().write_all(b"hello").await.unwrap();
    let trackers = initial.resender.clone();
    let phase = crate::ArcConnPhase::initial(initial);
    let paths = Paths::new(Role::Client, phase, Duration::ZERO, Duration::ZERO);
    // No registered socket: collect succeeds, but submitting the batch fails.
    let path = Arc::new(Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:0".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:35002".parse().unwrap()),
        ),
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        trackers.clone(),
    ));
    path.client_handshaking();
    path.decide(true);
    paths
        .entries
        .lock()
        .unwrap()
        .insert(path.pathway, path.clone());
    tokio::time::timeout(Duration::from_secs(4), sending(paths.clone(), path.clone()))
        .await
        .unwrap();
    assert!(paths.snapshot().is_empty());
    assert_eq!(path.state(), qtransport::path::PathState::Retired);

    assert!(
        space
            .crypto
            .writer()
            .write_all(b"after close")
            .await
            .is_err()
    );
    assert!(paths.phase().terminator().now_or_never().is_some());
}

#[tokio::test]
async fn collector_mixes_spaces_and_selected_crypto_advances() {
    let dcid_cell = OnceLock::new();
    let initial = crate::common::initial_phase(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let message = vec![42; 7200];
    crate::common::initial_space(&initial.spaces)
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
    crate::common::initial_space(&initial.spaces)
        .rcvd_journal
        .on_rcvd_pn(3, true, Duration::from_secs(1));
    handshake
        .rcvd_journal
        .on_rcvd_pn(7, true, Duration::from_secs(1));
    let trackers = initial.resender.clone();
    let phase = crate::ArcConnPhase::initial(initial);
    super::enter_handshake(&phase, handshake);
    let paths = Paths::new(Role::Client, phase.clone(), Duration::ZERO, Duration::ZERO);
    let pathway = Pathway::new(
        EndpointAddr::direct("127.0.0.1:31001".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:31002".parse().unwrap()),
    );
    let path = Arc::new(Path::new(
        pathway,
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        trackers.clone(),
    ));
    path.client_handshaking();
    path.decide(true);

    path.cc.on_pkt_rcvd(Epoch::Initial, 3, true);
    path.cc.on_pkt_rcvd(Epoch::Handshake, 7, true);
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::new();
    let mut pns = [[None; 3]; MAX_BURST_PACKETS];
    let count = burst(
        &path.cc,
        &path.anti_amplifier,
        &mut datagrams,
        &mut frames,
        &mut pns,
    )
    .collect(&paths, &path, &dcid_cell)
    .now_or_never()
    .unwrap()
    .unwrap();
    assert_eq!(count, 7);
    assert!(!pns_for(&pns, Epoch::Initial).next().is_none());
    assert_eq!(pns_for(&pns, Epoch::Handshake).count(), 1);
    for (epoch, largest) in [(Epoch::Initial, 3), (Epoch::Handshake, 7)] {
        assert_eq!(
            pns_for(&pns, epoch)
                .filter_map(|(_, pn)| phase
                    .get()
                    .spaces()
                    .read()
                    .unwrap()
                    .0
                    .get(epoch as u64)
                    .unwrap()
                    .sent_journal()
                    .lock_guard()
                    .packet(pn)
                    .unwrap()
                    .ack)
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
    let dcid_cell = OnceLock::new();
    for role in [Role::Client, Role::Server] {
        for handshaking in [false, true] {
            for selected in [u8::MAX, 0, 1, 2] {
                let phase = crate::ArcConnPhase::initial(crate::common::initial_phase(
                    role,
                    ConnectionId::from_slice(b"localcid"),
                    ConnectionId::from_slice(b"original"),
                    keys(role == Role::Server),
                ));
                let ConnPhase::Initial(initial) = phase.get() else {
                    unreachable!()
                };
                crate::common::initial_space(&initial.spaces)
                    .crypto
                    .writer()
                    .write_all(b"hello")
                    .await
                    .unwrap();
                if handshaking {
                    super::enter_handshake(&phase, Arc::new(HandshakeSpace::new(
                        Default::default(),
                        crate::common::initial_space(&initial.spaces).keys.clone(),
                    )));
                }
                let paths = Paths::new(role, phase.clone(), Duration::ZERO, Duration::ZERO);
                let path = Arc::new(Path::new(
                    Pathway::new(
                        EndpointAddr::direct("127.0.0.1:35001".parse().unwrap()),
                        EndpointAddr::direct("127.0.0.1:35002".parse().unwrap()),
                    ),
                    paths.handshake.clone(),
                    ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                    initial.resender.clone(),
                ));
                path.validate();
                match selected {
                    0 => path.decide(false),
                    1 => path.decide(true),
                    2 => path.handshake_confirmed(),
                    _ => {}
                }
                let mut datagrams = [BytesMut::with_capacity(1200)];
                let mut frames = Vec::new();
                let mut pns = [[None; 3]; MAX_BURST_PACKETS];
                for attempt in 0..2 {
                    let result = burst(
                        &path.cc,
                        &path.anti_amplifier,
                        &mut datagrams,
                        &mut frames,
                        &mut pns,
                    )
                    .collect(&paths, &path, &dcid_cell)
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

#[test]
fn packet_continues_after_pending_and_no_space_sources() {
    let header =
        LongHeaderBuilder::with_cid(Default::default(), Default::default()).initial(vec![]);
    let mut bytes = [0u8; 64];
    let mut packet = Packet::new(
        header,
        (7, qbase::packet::PacketNumber::U16(7)),
        &mut bytes[..],
    )
    .unwrap();
    let mut absent: Option<PingFrame> = None;
    let data = [0u8; 100];
    let mut large = (
        qbase::frame::CryptoFrame::new(0u32.into(), 100u32.into()),
        data.as_slice(),
    );
    let mut ping = PingFrame;
    let mut frames = Vec::new();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        packet.assemble(&mut cx, [&mut absent, &mut large, &mut ping], &mut frames),
        Poll::Ready(Ok(1))
    ));
    assert!(frames.is_empty());
    assert_eq!(packet.meta.content, qbase::packet::PacketContent::JustPing);
}

#[test]
fn repeated_assembly_does_not_append_after_close() {
    let header = qbase::packet::OneRttHeader::new(Default::default(), Default::default());
    let mut bytes = BytesMut::with_capacity(128);
    let mut packet =
        Packet::new(header, (0, qbase::packet::PacketNumber::U16(0)), &mut bytes).unwrap();
    let mut close = qbase::frame::ConnectionCloseFrame::new_app(0u32.into(), "closed");
    let mut frames = Vec::new();
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(
        packet.assemble(&mut cx, [&mut close], &mut frames),
        Poll::Ready(Ok(1))
    );
    let size = packet.buffer.len();
    assert_eq!(
        packet.assemble(&mut cx, [&mut PingFrame], &mut frames),
        Poll::Ready(Ok(0))
    );
    assert_eq!(packet.buffer.len(), size);
    assert_eq!(packet.meta.nframes, 1);
    assert!(frames.is_empty());
}

#[tokio::test]
async fn mixed_packets_consume_shared_budget_once() {
    use qtransport::space::{InitialSpace, Spaces, assemble::Constraints};
    let initial = Arc::new(InitialSpace::new(
        Default::default(),
        ArcKeys::new(Arc::new(keys(false))),
        None,
    ));
    let handshake = Arc::new(HandshakeSpace::new(
        Default::default(),
        initial.keys.clone(),
    ));
    initial.crypto.writer().write_all(b"hello").await.unwrap();
    handshake
        .crypto
        .writer()
        .write_all(b"handshake")
        .await
        .unwrap();
    let mut spaces = Spaces(qbase::util::IndexDeque::with_capacity(3));
    spaces.0.push_back(initial.clone()).unwrap();
    spaces.0.push_back(handshake.clone()).unwrap();
    let mut limits = Constraints {
        credit: 2400,
        send_quota: 2400,
        ..Default::default()
    };
    let mut bytes = [0; 1200];
    let mut frames = Vec::new();
    let mut pns = [None; 3];
    let mut cx = Context::from_waker(Waker::noop());
    let (size, _) = spaces
        .package(
            &mut cx,
            [Some(Default::default()); 3],
            &mut [&mut [], &mut [], &mut []],
            &mut bytes,
            &mut limits,
            &mut frames,
            &mut pns,
            false,
        )
        .unwrap();
    assert_eq!(size, 1200);
    assert_eq!((limits.send_quota, limits.credit), (1200, 1200));
    let a = initial.sent_journal.lock_guard();
    let b = handshake.sent_journal.lock_guard();
    assert!(a.packet(pns[0].unwrap()).unwrap().size < 100);
    assert_eq!(
        a.packet(pns[0].unwrap()).unwrap().size + b.packet(pns[1].unwrap()).unwrap().size,
        1200
    );
    assert_eq!(a.frames(pns[0].unwrap()).count(), 1);
    assert_eq!(b.frames(pns[1].unwrap()).count(), 1);
    for (index, packet) in PacketReader::new(BytesMut::from(&bytes[..size]), 0).enumerate() {
        let ParsedPacket::Data(packet) = packet.unwrap() else {
            panic!()
        };
        let opened = match packet.header {
            DataHeader::Long(long::DataHeader::Initial(header)) => {
                CipherPacket::new(header, packet.bytes, packet.offset)
                    .decrypt_long_packet(&keys(true).opening, |_| Ok(pns[index].unwrap()))
                    .unwrap()
                    .unwrap()
                    .body()
            }
            DataHeader::Long(long::DataHeader::Handshake(header)) => {
                CipherPacket::new(header, packet.bytes, packet.offset)
                    .decrypt_long_packet(&keys(true).opening, |_| Ok(pns[index].unwrap()))
                    .unwrap()
                    .unwrap()
                    .body()
            }
            _ => panic!(),
        };
        use qbase::packet::GetType;
        let ty = if index == 0 {
            LongHeaderBuilder::with_cid(Default::default(), Default::default())
                .initial(vec![])
                .get_type()
        } else {
            LongHeaderBuilder::with_cid(Default::default(), Default::default())
                .handshake()
                .get_type()
        };
        assert_eq!(
            FrameReader::new(opened, ty).any(|frame| matches!(frame.unwrap().0, Frame::Padding(_))),
            index == 1
        );
    }
    assert!(frames.is_empty());
}

#[test]
fn probe_uses_credit_without_replenishing_congestion_budget() {
    let keys = keys(false);
    let mut limits = Constraints {
        send_quota: 0,
        credit: 2400,
        min_size: 1200,
        max_size: 1200,
        overhead: 40,
        probe_quota: 1200,
        ..Default::default()
    };
    let mut cx = Context::from_waker(Waker::noop());
    let mut frames = Vec::new();
    for pn in 0..2 {
        let header =
            LongHeaderBuilder::with_cid(Default::default(), Default::default()).initial(vec![]);
        let packet = Packet::new(
            header,
            (pn, qbase::packet::PacketNumber::U8(pn as u8)),
            Vec::new(),
        )
        .unwrap();
        let mut packet = Envelope {
            packet,
            keys: &keys.sealing,
            limits: &mut limits,
        };
        let result = packet.assemble(&mut cx, [&mut PingFrame], &mut frames);
        if pn == 0 {
            assert!(matches!(result, Poll::Ready(Ok(n)) if n > 0));
            packet.seal().unwrap();
            assert_eq!(packet.packet.buffer.len(), 1160);
        } else {
            assert!(matches!(result, Poll::Ready(Ok(0))));
        }
        assert_eq!(limits.credit, 1200);
        assert_eq!(limits.send_quota, 0);
        assert_eq!(limits.probe_quota, 0);
        frames.clear();
    }
}

#[test]
fn vec_sealing_and_io_slice_encoding_preserve_the_encoded_pn() {
    use std::io::IoSliceMut;

    use qbase::packet::{GetType, PacketNumber};
    fn limits() -> Constraints {
        Constraints {
            flow_ctrl: 0,
            send_quota: 1200,
            credit: 1200,
            min_size: 1200,
            max_size: 1200,
            ..Default::default()
        }
    }
    fn verify(bytes: BytesMut) {
        assert_eq!(bytes.len(), 1200);
        let ParsedPacket::Data(parsed) = PacketReader::new(bytes, 0).next().unwrap().unwrap()
        else {
            panic!()
        };
        let DataHeader::Long(long::DataHeader::Initial(header)) = parsed.header else {
            panic!()
        };
        let ty = header.get_type();
        let opened = CipherPacket::new(header, parsed.bytes, parsed.offset)
            .decrypt_long_packet(&keys(true).opening, |_| Ok(7))
            .unwrap()
            .unwrap();
        assert!(
            FrameReader::new(opened.body(), ty).any(|f| matches!(f.unwrap().0, Frame::Ping(_)))
        );
    }
    let keys = keys(false);
    let header =
        || LongHeaderBuilder::with_cid(Default::default(), Default::default()).initial(vec![]);
    let mut frames = Vec::new();
    let mut cx = Context::from_waker(Waker::noop());
    let packet = Packet::new(header(), (7, PacketNumber::U16(7)), Vec::new()).unwrap();
    let mut constraints = limits();
    let mut packet = Envelope {
        packet,
        keys: &keys.sealing,
        limits: &mut constraints,
    };
    assert!(matches!(
        packet.assemble(&mut cx, [&mut PingFrame], &mut frames),
        Poll::Ready(Ok(_))
    ));
    packet.seal().unwrap();
    verify(BytesMut::from(packet.packet.buffer.as_slice()));
    assert_eq!(constraints.send_quota, 0);
    assert_eq!(constraints.credit, 0);

    let mut storage = [0; 1200];
    let mut io = IoSliceMut::new(&mut storage);
    let header = header();
    let pn_offset = qbase::packet::HeaderSize::size(&header) + 2;
    let mut packet = Packet::new(header, (7, PacketNumber::U16(7)), &mut io[..]).unwrap();
    frames.clear();
    assert!(matches!(
        packet.assemble(&mut cx, [&mut PingFrame], &mut frames),
        Poll::Ready(Ok(1))
    ));
    let written = 1200 - packet.buffer.len();
    drop(packet);
    assert_eq!(&io[pn_offset..pn_offset + 2], &[0, 7]);
    assert_eq!(io[written - 1], 1);
}

#[tokio::test]
async fn blocked_ack_does_not_wake_itself_and_collector_drop_keeps_subscription() {
    let dcid_cell = OnceLock::new();
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let initial = crate::common::initial_phase(
        Role::Server,
        ConnectionId::from_slice(b"serverid"),
        ConnectionId::from_slice(b"original"),
        keys(true),
    );
    let trackers = initial.resender.clone();
    let phase = crate::ArcConnPhase::initial(initial);
    let paths = Paths::new(Role::Server, phase.clone(), Duration::ZERO, Duration::ZERO);
    let pathway = Pathway::new(
        EndpointAddr::direct("127.0.0.1:31001".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:31002".parse().unwrap()),
    );
    let path = Arc::new(Path::new(
        pathway,
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        trackers.clone(),
    ));

    path.cc.on_pkt_rcvd(Epoch::Initial, 0, true);
    let ConnPhase::Initial(initial) = phase.get() else {
        panic!()
    };
    crate::common::initial_space(&initial.spaces)
        .rcvd_journal
        .on_rcvd_pn(0, true, Duration::from_secs(1));
    let mut datagrams = [BytesMut::with_capacity(1200)];
    let mut frames = Vec::new();
    let mut pns = [[None; 3]; MAX_BURST_PACKETS];
    let count = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    let mut collector = burst(
        &path.cc,
        &path.anti_amplifier,
        &mut datagrams,
        &mut frames,
        &mut pns,
    )
    .collect(&paths, &path, &dcid_cell);
    assert!(Pin::new(&mut collector).poll(&mut cx).is_pending());
    assert_eq!(
        count.0.load(Ordering::Relaxed),
        0,
        "waiting for credit must not continuously wake this task"
    );
    drop(collector);
    crate::common::initial_space(&initial.spaces)
        .crypto
        .writer()
        .write_all(b"hello")
        .await
        .unwrap();
    path.anti_amplifier.on_received(1200);
    path.retire();
    assert!(count.0.load(Ordering::Relaxed) > 0);

    let mut running = Box::pin(sending(paths, path));
    assert!(running.as_mut().poll(&mut cx).is_pending());
    initial.terminator.terminate();
    assert!(running.as_mut().poll(&mut cx).is_ready());
    drop(running);
    assert_eq!(
        Arc::strong_count(&count),
        2,
        "task exit releases subscriptions"
    );
}

#[tokio::test]
async fn collector_drop_keeps_subscriptions_until_path_task_exits() {
    let first_dcid = OnceLock::new();
    let second_dcid = OnceLock::new();
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let initial = crate::common::initial_phase(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let trackers = initial.resender.clone();
    let phase = crate::ArcConnPhase::initial(initial);
    let paths = Paths::new(Role::Client, phase.clone(), Duration::ZERO, Duration::ZERO);
    let make_path = |port| {
        let path = Arc::new(Path::new(
            Pathway::new(
                EndpointAddr::direct(([127, 0, 0, 1], port).into()),
                EndpointAddr::direct("127.0.0.1:32002".parse().unwrap()),
            ),
            paths.handshake.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            trackers.clone(),
        ));

        path.client_handshaking();
        path
    };
    let first = make_path(32001);
    let second = make_path(32003);
    let mut first_bytes = [BytesMut::with_capacity(1200)];
    let mut second_bytes = [BytesMut::with_capacity(1200)];
    let mut first_frames = Vec::new();
    let mut second_frames = Vec::new();
    let mut first_pns = [[None; 3]; MAX_BURST_PACKETS];
    let mut second_pns = [[None; 3]; MAX_BURST_PACKETS];
    let a = Arc::new(Counter(AtomicUsize::new(0)));
    let b = Arc::new(Counter(AtomicUsize::new(0)));
    let wa = Waker::from(a.clone());
    let wb = Waker::from(b.clone());
    let mut one = burst(
        &first.cc,
        &first.anti_amplifier,
        &mut first_bytes,
        &mut first_frames,
        &mut first_pns,
    )
    .collect(&paths, &first, &first_dcid);
    let mut two = burst(
        &second.cc,
        &second.anti_amplifier,
        &mut second_bytes,
        &mut second_frames,
        &mut second_pns,
    )
    .collect(&paths, &second, &second_dcid);
    assert!(
        Pin::new(&mut one)
            .poll(&mut Context::from_waker(&wa))
            .is_pending()
    );
    assert!(
        Pin::new(&mut two)
            .poll(&mut Context::from_waker(&wb))
            .is_pending()
    );
    drop(one);
    let ConnPhase::Initial(initial) = phase.get() else {
        panic!()
    };
    crate::common::initial_space(&initial.spaces)
        .crypto
        .writer()
        .write_all(b"hello")
        .await
        .unwrap();
    assert!(a.0.load(Ordering::Relaxed) > 0);
    assert!(b.0.load(Ordering::Relaxed) > 0);
    task::cancel_waiters(&paths, &first);
    let first_before = a.0.load(Ordering::Relaxed);
    assert!(matches!(
        Pin::new(&mut two).poll(&mut Context::from_waker(&wb)),
        Poll::Ready(Ok(1))
    ));
    drop(two);
    let before = b.0.load(Ordering::Relaxed);
    crate::common::initial_space(&initial.spaces)
        .crypto
        .writer()
        .write_all(b"again")
        .await
        .unwrap();
    assert_eq!(a.0.load(Ordering::Relaxed), first_before);
    assert!(b.0.load(Ordering::Relaxed) > before);
    task::cancel_waiters(&paths, &second);
    let before = b.0.load(Ordering::Relaxed);
    first.retire();
    second.retire();
    assert_eq!(a.0.load(Ordering::Relaxed), first_before);
    assert_eq!(b.0.load(Ordering::Relaxed), before);
}

#[tokio::test]
async fn closing_is_collected_before_failed_crypto_and_draining_returns_error() {
    for epoch in [Epoch::Initial, Epoch::Handshake] {
        let dcid_cell = OnceLock::new();
        let initial = crate::common::initial_phase(
            Role::Server,
            ConnectionId::from_slice(b"server00"),
            ConnectionId::from_slice(b"original"),
            keys(true),
        );
        let terminator = initial.terminator.clone();
        let mut space = crate::common::initial_space(&initial.spaces);
        let trackers = initial.resender.clone();
        let phase = crate::ArcConnPhase::initial(initial);
        if epoch == Epoch::Handshake {
            let handshake = Arc::new(HandshakeSpace::new(
                Default::default(),
                ArcKeys::new(Arc::new(keys(true))),
            ));
            super::enter_handshake(&phase, handshake.clone());
            space.retire();
            space = Arc::new(handshake.0.clone());
        }
        let paths = Paths::new(Role::Server, phase, Duration::ZERO, Duration::ZERO);
        let path = Arc::new(Path::new(
            Pathway::new(
                EndpointAddr::direct("127.0.0.1:33001".parse().unwrap()),
                EndpointAddr::direct("127.0.0.1:33002".parse().unwrap()),
            ),
            paths.handshake.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            trackers.clone(),
        ));
        path.validate();
        path.decide(true);
        let error = QuicError::with_default_fty(ErrorKind::Internal, "TLS failed");
        terminator.close(
            crate::CloseReason::Internal(error.clone()),
            paths.closing_pto(),
        );
        space.crypto.on_error(&error.into());
        let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
        let mut frames = Vec::new();
        let mut pns = [[None; 3]; MAX_BURST_PACKETS];
        let mut collector = burst(
            &path.cc,
            &path.anti_amplifier,
            &mut datagrams,
            &mut frames,
            &mut pns,
        )
        .collect(&paths, &path, &dcid_cell);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut collector).poll(&mut cx),
            Poll::Ready(Ok(1))
        ));
        let pn = pns_for(&collector.burst.pns, epoch).next().unwrap().1;
        assert_eq!(space.sent_journal.lock_guard().frames(pn).count(), 0);
        drop(collector);
        let ParsedPacket::Data(packet) = PacketReader::new(datagrams[0].clone(), 8).next().unwrap().unwrap() else { panic!() };
        use qbase::packet::GetType;
        let ty = packet.get_type();
        let body = match packet.header {
            DataHeader::Long(long::DataHeader::Initial(header)) => CipherPacket::new(header, packet.bytes, packet.offset)
                .decrypt_long_packet(&keys(false).opening, |_| Ok(pn)).unwrap().unwrap().body(),
            DataHeader::Long(long::DataHeader::Handshake(header)) => CipherPacket::new(header, packet.bytes, packet.offset)
                .decrypt_long_packet(&keys(false).opening, |_| Ok(pn)).unwrap().unwrap().body(),
            _ => panic!(),
        };
        let decoded = FrameReader::new(body, ty).collect::<Result<Vec<_>, _>>().unwrap();
        assert!(decoded.iter().any(|(frame, _)| matches!(frame, Frame::Close(_))));
        assert!(decoded.iter().all(|(frame, _)| matches!(frame, Frame::Close(_) | Frame::Padding(_))));
        for slots in &mut pns {
            slots[epoch] = None;
        }
        let mut collector = burst(
            &path.cc,
            &path.anti_amplifier,
            &mut datagrams,
            &mut frames,
            &mut pns,
        )
        .collect(&paths, &path, &dcid_cell);
        assert!(Pin::new(&mut collector).poll(&mut cx).is_pending());
        terminator.terminate();
        assert!(matches!(
            Pin::new(&mut collector).poll(&mut cx),
            Poll::Ready(Err(_))
        ));
    }
}

fn server_one_rtt_keys() -> qtls::OneRttKeyMaterial {
    use tls_backend::pki_types::pem::PemObject;
    let provider = Arc::new(qtls::default_provider());
    qtls::RootCerts::set([qtls::CertificateDer::from_pem_slice(include_bytes!(
        "../../../tests/keychain/localhost/ca.cert"
    ))
    .unwrap()])
    .unwrap();
    let client = qtls::TlsClient::new(qtls::ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: None,
        resumption: qtls::ClientResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .unwrap();
    let server = qtls::TlsServer::new(qtls::ServerTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        local: qtls::LocalAuthority::new(
            &provider,
            Arc::from("localhost"),
            vec![
                qtls::CertificateDer::from_pem_slice(include_bytes!(
                    "../../../tests/keychain/localhost/server.cert"
                ))
                .unwrap(),
            ],
            qtls::PrivateKeyDer::from_pem_slice(include_bytes!(
                "../../../tests/keychain/localhost/server.key"
            ))
            .unwrap(),
            include_bytes!("../../../tests/keychain/localhost/server.ocsp").to_vec(),
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

fn mature_server_phase() -> (InitialPhase, super::MatureFixture) {
    use qbase::param::{
        ArcParameters,
        handy::{client_parameters, server_parameters},
    };
    let initial = crate::common::initial_phase(
        Role::Server,
        ConnectionId::from_slice(b"server00"),
        ConnectionId::from_slice(b"original"),
        keys(true),
    );
    let mut client = client_parameters();
    client
        .set(
            ParameterId::InitialSourceConnectionId,
            ConnectionId::from_slice(b"client00"),
        )
        .unwrap();
    let parameters = ArcParameters::new(
        Role::Server,
        Arc::new(client),
        Arc::new(server_parameters()),
    );
    let terminator = &initial.terminator;
    let registry = initial.cid_registry.clone();
    let handshake = Arc::new(HandshakeSpace::new(
        Default::default(),
        ArcKeys::new(Arc::new(keys(true))),
    ));
    terminator.register(Arc::new(handshake.crypto.clone()));
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
    terminator.register(Arc::new(streams.clone()));
    let flow = crate::FlowController::new(
        parameters.remote(qbase::param::ParameterId::InitialMaxData),
        parameters.local(qbase::param::ParameterId::InitialMaxData),
        reliable_frames.clone(),
    );
    terminator.register(Arc::new(flow.clone()));
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
        initial: crate::common::initial_space(&initial.spaces),
        handshake,
        data,
    };
    let mature = Arc::new(MaturePhase {
        spaces: initial.spaces.clone(),
        scid: initial.scid,
        flow_ctrl: flow,
        cid_registry: registry,
        dcid: ConnectionId::from_slice(b"client00"),
        parameters,
        puncher,
        resender: initial.resender.clone(),
        terminator: initial.terminator.clone(),
    });
    (
        initial,
        super::MatureFixture {
            phase: mature,
            spaces: concrete,
        },
    )
}

#[test]
fn phase_upgrade_wakes_senders_and_releases_subscriptions() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let (initial, mature) = mature_server_phase();
    let phase = crate::ArcConnPhase::initial(initial);
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
    phase.set_dcid(ConnectionId::from_slice(b"peer0000"));
    assert_eq!(initial.dcid(), ConnectionId::from_slice(b"peer0000"));
    assert_eq!(first.0.load(Ordering::Relaxed), 1);
    assert_eq!(second.0.load(Ordering::Relaxed), 0);
    drop(phase.poll_phase(&mut Context::from_waker(&b)));

    phase.enter_handshake();
    assert_eq!(mature.phase.spaces.read().unwrap().0.len(), 1);
    assert_eq!(mature.resender.read().unwrap().len(), 1);
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
    assert!(Arc::ptr_eq(&handshake.spaces, &mature.phase.spaces));
    assert_eq!(handshake.scid, mature.scid);
    assert_eq!(handshake.dcid, ConnectionId::from_slice(b"peer0000"));
    handshake.upgrade_wakers.unregister(&b);
    phase.set_dcid(ConnectionId::from_slice(b"peer0001"));
    assert_eq!(handshake.dcid, ConnectionId::from_slice(b"peer0000"));
    assert_eq!(first.0.load(Ordering::Relaxed), 2);
    assert_eq!(second.0.load(Ordering::Relaxed), 1);
    drop(phase.poll_phase(&mut cx));
    drop(phase.poll_phase(&mut cx));
    drop(phase.poll_phase(&mut Context::from_waker(&b)));

    phase.enter_mature(mature.phase.clone());
    assert_eq!(mature.phase.spaces.read().unwrap().0.len(), 1);
    assert_eq!(mature.resender.read().unwrap().len(), 1);
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
    phase.set_dcid(ConnectionId::from_slice(b"ignored0"));
    assert_eq!(first.0.load(Ordering::Relaxed), 3);
    let ConnPhase::Mature(mature) = phase.get() else {
        panic!("expected Mature");
    };
    assert_eq!(mature.dcid, ConnectionId::from_slice(b"client00"));
}

#[test]
fn phase_upgrades_preserve_cid_cleanup_and_termination() {
    let (initial, mature) = mature_server_phase();
    let cid_registry = initial.cid_registry.clone();
    let terminator = initial.terminator.clone();
    let phase = crate::ArcConnPhase::initial(initial);
    super::enter_handshake(&phase, mature.spaces.handshake.clone());
    let ConnPhase::Handshake(handshake) = phase.get() else {
        panic!("expected Handshake");
    };
    super::enter_mature(&phase, &mature);

    cid_registry.local.clear();
    assert!(handshake.cid_registry.local.initial_scid().is_none());
    assert!(mature.cid_registry.local.initial_scid().is_none());
    terminator.terminate();
    let error = terminator.now_or_never().unwrap();
    assert_eq!(
        handshake.terminator.clone().now_or_never(),
        Some(error.clone())
    );
    assert_eq!(phase.terminator().now_or_never(), Some(error));
}

#[tokio::test(start_paused = true)]
async fn existing_path_recovers_new_spaces_after_phase_upgrade() {
    let dcid_cell = OnceLock::new();
    let (initial, mature) = mature_server_phase();
    let dcid = initial.dcid();
    let phase = crate::ArcConnPhase::initial(initial);
    let paths = Paths::new(Role::Server, phase.clone(), Duration::ZERO, Duration::ZERO);
    let path = Arc::new(Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:34101".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:34102".parse().unwrap()),
        ),
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        mature.resender.clone(),
    ));
    dcid_cell.set(crate::common::dcid(dcid)).unwrap();
    path.validate();
    path.decide(true);
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::new();
    let mut pns = [[None; 3]; MAX_BURST_PACKETS];

    for epoch in [Epoch::Handshake, Epoch::Data] {
        let (crypto, journal) = if epoch == Epoch::Handshake {
            super::enter_handshake(&phase, mature.spaces.handshake.clone());
            (
                &mature.spaces.handshake.crypto,
                &mature.spaces.handshake.sent_journal,
            )
        } else {
            super::enter_mature(&phase, &mature);
            super::confirm_handshake(&paths);
            path.handshake_confirmed();
            (&mature.spaces.data.crypto, &mature.spaces.data.sent_journal)
        };
        let mut sent = Vec::new();
        for _ in 0..4 {
            crypto.writer().write_all(b"crypto").await.unwrap();
            burst(
                &path.cc,
                &path.anti_amplifier,
                &mut datagrams,
                &mut frames,
                &mut pns,
            )
            .collect(&paths, &path, &dcid_cell)
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
        burst(
            &path.cc,
            &path.anti_amplifier,
            &mut datagrams,
            &mut frames,
            &mut pns,
        )
        .collect(&paths, &path, &dcid_cell)
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
async fn selected_sender_requests_its_cell_before_other_paths_are_released() {
    use qbase::frame::{NewConnectionIdFrame, io::ReceiveFrame};

    for confirmed_first in [false, true] {
        let (initial, mature) = mature_server_phase();
        let remote = &mature.cid_registry.remote;
        remote.set_initial_dcid(mature.dcid);
        let next = ConnectionId::from_slice(b"client01");
        remote
            .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
            .unwrap();
        let phase = crate::ArcConnPhase::initial(initial);
        let paths = Paths::new(Role::Server, phase.clone(), Duration::ZERO, Duration::ZERO);
        let make_path = |port| {
            let path = Arc::new(Path::new(
                Pathway::new(
                    EndpointAddr::direct(([127, 0, 0, 1], port).into()),
                    EndpointAddr::direct("127.0.0.1:34300".parse().unwrap()),
                ),
                paths.handshake.clone(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                mature.resender.clone(),
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
        other.validate();
        selected.validate();
        let selected_cell = OnceLock::new();
        let other_cell = OnceLock::new();
        let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
        let mut frames = Vec::new();
        let mut pns = [[None; 3]; MAX_BURST_PACKETS];
        let mut cx = Context::from_waker(Waker::noop());
        // Selection alone does not request a cell while sending Initial packets.
        let _ = Pin::new(
            &mut burst(
                &selected.cc,
                &selected.anti_amplifier,
                &mut datagrams,
                &mut frames,
                &mut pns,
            )
            .collect(&paths, &selected, &selected_cell),
        )
        .poll(&mut cx);
        assert!(selected_cell.get().is_none());
        super::enter_mature(&phase, &mature);
        if confirmed_first {
            super::confirm_handshake(&paths);
        }
        // Poll the losing sender first, even when TLS has already confirmed the handshake.
        assert!(
            Pin::new(
                &mut burst(
                    &other.cc,
                    &other.anti_amplifier,
                    &mut datagrams,
                    &mut frames,
                    &mut pns
                )
                .collect(&paths, &other, &other_cell)
            )
            .poll(&mut cx)
            .is_pending()
        );
        assert!(other_cell.get().is_none());
        let _ = Pin::new(
            &mut burst(
                &selected.cc,
                &selected.anti_amplifier,
                &mut datagrams,
                &mut frames,
                &mut pns,
            )
            .collect(&paths, &selected, &selected_cell),
        )
        .poll(&mut cx);
        assert!(
            matches!(selected_cell.get().unwrap().borrow_cid(selected.send_waker.clone()),
            Poll::Ready(Some(cid)) if *cid == mature.dcid)
        );
        // The sender notifies path control after collection releases the phase lock.
        paths.activate_paths(&selected);
        if !confirmed_first {
            assert_eq!(selected.selected(), Path::SELECTED);
            assert_eq!(other.selected(), Path::SUSPEND);
            super::confirm_handshake(&paths);
            assert_eq!(selected.selected(), Path::SELECTED);
            assert_eq!(other.selected(), Path::SUSPEND);
            paths.activate_paths(&selected);
        }
        assert_eq!(selected.selected(), Path::HANDSHAKED);
        assert_eq!(other.selected(), Path::HANDSHAKED);
        for entries in &mut pns {
            entries.fill(None);
        }
        let _ = Pin::new(
            &mut burst(
                &other.cc,
                &other.anti_amplifier,
                &mut datagrams,
                &mut frames,
                &mut pns,
            )
            .collect(&paths, &other, &other_cell),
        )
        .poll(&mut cx);
        assert!(
            matches!(other_cell.get().unwrap().borrow_cid(other.send_waker.clone()),
            Poll::Ready(Some(cid)) if *cid == next)
        );
        paths.retire_all();
    }
}

#[tokio::test]
async fn pending_path_cid_allows_long_headers_and_later_supplies_one_rtt_header() {
    let dcid_cell = OnceLock::new();
    use qbase::{
        frame::{NewConnectionIdFrame, io::ReceiveFrame},
        packet::GetDcid,
    };

    let (initial, mature) = mature_server_phase();
    let remote = &mature.cid_registry.remote;
    remote.set_initial_dcid(mature.dcid);
    let initial_cell = remote.apply_dcid();
    let phase = crate::ArcConnPhase::initial(initial);
    super::enter_mature(&phase, &mature);
    let paths = Paths::new(Role::Server, phase, Duration::ZERO, Duration::ZERO);
    let path = Arc::new(Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:34201".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:34202".parse().unwrap()),
        ),
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        mature.resender.clone(),
    ));
    assert!(dcid_cell.get().is_none());
    path.validate();
    path.decide(true);
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
    assert_eq!(
        burst(
            &path.cc,
            &path.anti_amplifier,
            &mut datagrams,
            &mut frames,
            &mut pns
        )
        .collect(&paths, &path, &dcid_cell)
        .now_or_never()
        .unwrap()
        .unwrap(),
        1
    );
    assert!(pns_for(&pns, Epoch::Data).next().is_none());
    let headers = PacketReader::new(datagrams[0].clone(), 8)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(headers.len(), 2);
    for packet in headers {
        let ParsedPacket::Data(packet) = packet else {
            panic!()
        };
        assert_eq!(*packet.header.dcid(), mature.dcid);
    }
    for entries in &mut pns {
        entries.fill(None);
    }

    let mut collector = burst(
        &path.cc,
        &path.anti_amplifier,
        &mut datagrams,
        &mut frames,
        &mut pns,
    )
    .collect(&paths, &path, &dcid_cell);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut collector).poll(&mut cx).is_pending());
    let next = ConnectionId::from_slice(b"client01");
    remote
        .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
        .unwrap();
    assert!(matches!(
        Pin::new(&mut collector).poll(&mut cx),
        Poll::Ready(Ok(1))
    ));
    // Keep the CID borrowed while the assembled datagram awaits UDP submission.
    let borrowed = collector.dcid.take().unwrap();
    drop(collector);
    let ParsedPacket::Data(packet) = PacketReader::new(
        datagrams[pns_for(&pns, Epoch::Data).next().unwrap().0].clone(),
        8,
    )
    .next()
    .unwrap()
    .unwrap() else {
        panic!()
    };
    assert_eq!(*packet.header.dcid(), next);
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
    assert_eq!(current.dcid, mature.dcid);
    drop(borrowed);
    assert!(
        matches!(dcid_cell.get().unwrap().borrow_cid(path.send_waker.clone()),
        Poll::Ready(Some(cid)) if *cid == replacement)
    );

    for slots in &mut pns {
        slots[Epoch::Data] = None;
    }
    mature
        .spaces
        .data
        .crypto
        .writer()
        .write_all(b"next")
        .await
        .unwrap();
    burst(
        &path.cc,
        &path.anti_amplifier,
        &mut datagrams,
        &mut frames,
        &mut pns,
    )
    .collect(&paths, &path, &dcid_cell)
    .now_or_never()
    .unwrap()
    .unwrap();
    let ParsedPacket::Data(packet) = PacketReader::new(
        datagrams[pns_for(&pns, Epoch::Data).next().unwrap().0].clone(),
        8,
    )
    .next()
    .unwrap()
    .unwrap() else {
        panic!()
    };
    assert_eq!(*packet.header.dcid(), replacement);
}

#[tokio::test]
async fn mature_server_collects_its_three_spaces_and_one_rtt_close() {
    let dcid_cell = OnceLock::new();
    let (initial, mature) = mature_server_phase();
    for crypto in [
        &mature.spaces.initial.crypto,
        &mature.spaces.handshake.crypto,
        &mature.spaces.data.crypto,
    ] {
        crypto.writer().write_all(b"crypto").await.unwrap();
    }
    let phase = crate::ArcConnPhase::initial(initial);
    super::enter_mature(&phase, &mature);
    let paths = Paths::new(Role::Server, phase, Duration::ZERO, Duration::ZERO);
    let path = Arc::new(Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:34001".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:34002".parse().unwrap()),
        ),
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        mature.resender.clone(),
    ));
    dcid_cell.set(crate::common::dcid(mature.dcid)).unwrap();
    path.validate();
    path.decide(true);
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::new();
    let mut pns = [[None; 3]; MAX_BURST_PACKETS];
    assert_eq!(
        burst(
            &path.cc,
            &path.anti_amplifier,
            &mut datagrams,
            &mut frames,
            &mut pns
        )
        .collect(&paths, &path, &dcid_cell)
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
    path.decide(false);
    assert!(
        burst(
            &path.cc,
            &path.anti_amplifier,
            &mut datagrams,
            &mut frames,
            &mut pns
        )
        .collect(&paths, &path, &dcid_cell)
        .now_or_never()
        .is_none()
    );
    assert!(pns.iter().flatten().all(Option::is_none));
    path.handshake_confirmed();
    assert!(matches!(
        burst(
            &path.cc,
            &path.anti_amplifier,
            &mut datagrams,
            &mut frames,
            &mut pns
        )
        .collect(&paths, &path, &dcid_cell)
        .now_or_never(),
        Some(Ok(1))
    ));
    assert_eq!(pns_for(&pns, Epoch::Initial).count(), 1);
    for slots in &mut pns {
        slots[Epoch::Initial] = None;
    }
    // An undecided path must wait instead of collecting 1-RTT data. Retirement
    // must wake that wait even though the socket has never been polled.
    let waiting_path = Arc::new(Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:34003".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:34002".parse().unwrap()),
        ),
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        mature.resender.clone(),
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
    let error = QuicError::with_default_fty(ErrorKind::Internal, "connection failed");
    mature.terminator.close(
        crate::CloseReason::Internal(error.clone()),
        paths.closing_pto(),
    );
    mature.flow_ctrl.on_error(&error.clone().into());
    mature.spaces.data.crypto.on_error(&error.into());
    assert_eq!(
        burst(
            &path.cc,
            &path.anti_amplifier,
            &mut datagrams,
            &mut frames,
            &mut pns
        )
        .collect(&paths, &path, &dcid_cell)
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
        let (initial, mature) = mature_server_phase();
        let phase = crate::ArcConnPhase::initial(initial);
        if epoch == Epoch::Handshake {
            super::enter_handshake(&phase, mature.spaces.handshake.clone());
            mature.spaces.initial.retire();
        } else if epoch == Epoch::Data {
            super::enter_mature(&phase, &mature);
        }
        let paths = Paths::new(Role::Server, phase, Duration::ZERO, Duration::from_secs(60));
        if epoch == Epoch::Data {
            super::confirm_handshake(&paths);
        }
        let path = Arc::new(Path::new(
            Pathway::new(
                "127.0.0.1:30001".parse::<EndpointAddr>().unwrap(),
                "127.0.0.1:30002".parse().unwrap(),
            ),
            paths.handshake.clone(),
            ArcHeartbeat::new(Duration::from_secs(60), Duration::ZERO),
            mature.resender.clone(),
        ));
        path.validate();
        path.decide(true);
        path.heartbeat
            .on_rcvd_at(PacketContent::EffectivePayload, tokio::time::Instant::now())
            .unwrap();
        let dcid = OnceLock::new();
        if epoch == Epoch::Data {
            dcid.set(crate::common::dcid(mature.dcid)).unwrap();
        }
        let mut datagrams = [BytesMut::with_capacity(1200)];
        let mut frames = Vec::new();
        let mut pns = [[None; 3]; MAX_BURST_PACKETS];
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let mut collector = burst(
            &path.cc,
            &path.anti_amplifier,
            &mut datagrams,
            &mut frames,
            &mut pns,
        )
        .collect(&paths, &path, &dcid);
        if epoch == Epoch::Data {
            // Consume the CID advertisement queued by the fixture before testing idleness.
            assert!(matches!(
                Pin::new(&mut collector).poll(&mut cx),
                Poll::Ready(Ok(1))
            ));
            for slots in &mut *collector.burst.pns {
                slots[Epoch::Data] = None;
            }
        }
        assert!(Pin::new(&mut collector).poll(&mut cx).is_pending());
        tokio::task::yield_now().await;
        let before = counter.0.load(Ordering::Relaxed);
        tokio::time::advance(Duration::from_secs(20)).await;
        tokio::task::yield_now().await;
        assert!(counter.0.load(Ordering::Relaxed) > before);
        let result = Pin::new(&mut collector).poll(&mut cx);
        assert!(
            matches!(result, Poll::Ready(Ok(1))),
            "{epoch:?}: {result:?}"
        );
        drop(collector);
        assert_eq!(pns_for(&pns, epoch).count(), 1);
        let pn = pns_for(&pns, epoch).next().unwrap().1;
        let snapshot = paths.phase().get();
        assert_eq!(
            snapshot
                .spaces()
                .read()
                .unwrap()
                .0
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

#[tokio::test(start_paused = true)]
async fn submitting_an_ack_only_packet_starts_the_connection_idle_timer() {
    use qbase::net::route::{Line, Link};
    use qprotocol::{QuicProtocol, UdpSocket};
    use tokio::time::Instant;

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let local = EndpointAddr::direct(socket.local_addr().unwrap());
    QuicProtocol::global().register(local, &socket).unwrap();
    let initial = crate::common::initial_phase(
        Role::Server,
        ConnectionId::from_slice(b"server00"),
        ConnectionId::from_slice(b"original"),
        keys(true),
    );
    let space = crate::common::initial_space(&initial.spaces);
    let trackers = initial.resender.clone();
    let paths = Paths::new(
        Role::Server,
        crate::ArcConnPhase::initial(initial),
        Duration::from_secs(5),
        Duration::ZERO,
    );
    let path = Arc::new(Path::new(
        Pathway::new(local, EndpointAddr::direct(peer.local_addr().unwrap())),
        paths.handshake.clone(),
        ArcHeartbeat::new(Duration::from_secs(60), Duration::ZERO),
        trackers.clone(),
    ));
    path.validate();
    path.decide(true);
    space
        .rcvd_journal
        .on_rcvd_pn(0, true, Duration::from_secs(1));
    path.cc.on_pkt_rcvd(Epoch::Initial, 0, true);
    let start = Instant::now();
    let sender = tokio::spawn(sending(paths.clone(), path.clone()));
    let mut buffers = [BytesMut::zeroed(1500)];
    let mut lines = [Line::new(
        Link::new(local.addr(), peer.local_addr().unwrap()),
        64,
        None,
        1500,
    )];
    tokio::time::timeout(
        Duration::from_secs(1),
        peer.receive(&mut buffers, &mut lines),
    )
    .await
    .unwrap()
    .unwrap();
    let received = Instant::now();
    buffers[0].truncate(lines[0].seg_size as usize);
    let ParsedPacket::Data(packet) = PacketReader::new(buffers[0].clone(), 8)
        .next()
        .unwrap()
        .unwrap()
    else {
        panic!()
    };
    let DataHeader::Long(long::DataHeader::Initial(header)) = packet.header else {
        panic!()
    };
    let opened = CipherPacket::new(header, packet.bytes, packet.offset)
        .decrypt_long_packet(&keys(false).opening, |_| Ok(0))
        .unwrap()
        .unwrap();
    use qbase::packet::GetType;
    assert!(
        FrameReader::new(opened.body(), opened.get_type())
            .all(|frame| matches!(frame.unwrap().0, Frame::Ack(_) | Frame::Padding(_)))
    );
    let reason = paths.phase().terminator().await;
    assert!(
        matches!(reason, crate::Error::Quic(error) if error.reason() == "connection idle timeout")
    );
    assert!(Instant::now() >= start + Duration::from_secs(5));
    assert!(Instant::now() <= received + Duration::from_secs(8));
    assert!(!super::take_heartbeat(&path));
    path.retire();
    sender.await.unwrap();
    QuicProtocol::global().unregister(socket.local_addr().unwrap());
}

#[tokio::test(start_paused = true)]
async fn credit_blocked_sender_keeps_path_until_termination() {
    let phase = crate::ArcConnPhase::initial(crate::common::initial_phase(
        Role::Server,
        ConnectionId::from_slice(b"localcid"),
        ConnectionId::from_slice(b"original"),
        keys(true),
    ));
    let terminator = phase.terminator();
    let paths = Paths::new(Role::Server, phase, Duration::ZERO, Duration::ZERO);
    let path = paths.add_path(Pathway::new(
        EndpointAddr::direct("127.0.0.1:49001".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:49002".parse().unwrap()),
    ));
    tokio::task::yield_now().await;
    let pto = path.cc.pto_base(Epoch::Data);
    terminator.close(
        crate::CloseReason::Internal(QuicError::with_default_fty(
            ErrorKind::Internal,
            "closed while credit blocked",
        )),
        pto,
    );
    tokio::task::yield_now().await;
    assert!(paths.get(&path.pathway).is_some());
    assert_ne!(path.state(), qtransport::path::PathState::Retired);
    tokio::time::advance(3 * pto).await;
    terminator.await;
    tokio::task::yield_now().await;
    assert!(paths.get(&path.pathway).is_none());
    assert_eq!(path.state(), qtransport::path::PathState::Retired);
}

#[tokio::test]
async fn trackers_follow_space_creation_and_retirement_in_epoch_order() {
    for role in [Role::Client, Role::Server] {
        for retire_before_handshake in [false, true] {
            let (initial, mature) = mature_server_phase();
            let trackers = initial.resender.clone();
            assert!(Arc::ptr_eq(&trackers, &mature.resender));
            let phase = crate::ArcConnPhase::initial(initial);
            let paths = Paths::new(role, phase.clone(), Duration::ZERO, Duration::ZERO);
            let epochs = || {
                trackers
                    .read()
                    .unwrap()
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
            super::enter_handshake(&phase, mature.spaces.handshake.clone());
            let ConnPhase::Handshake(handshake) = phase.get() else {
                panic!("expected Handshake");
            };
            assert!(Arc::ptr_eq(&trackers, &handshake.resender));
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

            super::enter_mature(&phase, &mature);
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

fn pns_for(pns: &BurstPns, epoch: Epoch) -> impl Iterator<Item = (usize, u64)> + '_ {
    pns.iter()
        .enumerate()
        .filter_map(move |(index, slots)| slots[epoch].map(|pn| (index, pn)))
}

#[test]
fn recursive_packing_pads_the_last_packet_and_decrypts_each_space() {
    use qbase::{
        frame::{CryptoFrame, EncodeSize},
        packet::{GetType, HeaderSize, Package},
    };
    use qtransport::space::assemble::Constraints;
    for (sizes, expected) in [
        ([700, 0, 0], [1200, 0, 0]),
        ([700, 200, 0], [700, 500, 0]),
        ([700, 200, 100], [700, 200, 300]),
        ([0, 400, 0], [0, 400, 0]),
        ([0, 0, 100], [0, 0, 100]),
        ([0, 0, 0], [0, 0, 0]),
    ] {
        let [sender, receiver] = super::punch::pair();
        let mut spaces = sender.phase.spaces.read().unwrap().snapshot();
        spaces.0.push_back(sender.spaces.handshake.clone()).unwrap();
        spaces.0.push_back(sender.spaces.data.clone()).unwrap();
        let mut sources = Epoch::EPOCHS.map(|epoch| {
            let size = sizes[epoch];
            if size == 0 {
                return None;
            }
            let header = match epoch {
                Epoch::Initial => {
                    LongHeaderBuilder::with_cid(sender.dcid, sender.scid)
                        .initial(vec![])
                        .size()
                        + 2
                }
                Epoch::Handshake => {
                    LongHeaderBuilder::with_cid(sender.dcid, sender.spaces.handshake.initial_scid)
                        .handshake()
                        .size()
                        + 2
                }
                Epoch::Data => {
                    qbase::packet::OneRttHeader::new(Default::default(), sender.dcid).size()
                }
            };
            let len = (0..size)
                .find(|&len| {
                    header
                        + 2
                        + 16
                        + CryptoFrame::new(0u32.into(), (len as u32).into()).encoding_size()
                        + len
                        == size
                })
                .unwrap();
            Some((
                CryptoFrame::new(0u32.into(), (len as u32).into()),
                bytes::Bytes::from(vec![epoch as u8 + 1; len]),
            ))
        });
        let [a, b, c] = &mut sources;
        let mut external: [&mut [&mut dyn for<'b> Package<&'b mut [u8]>]; 3] =
            [&mut [a], &mut [b], &mut [c]];
        let mut bytes = [0xa5; 1216];
        let mut limits = Constraints {
            send_quota: 2400,
            credit: 2400,
            ..Default::default()
        };
        let mut frames = Vec::new();
        let mut pns = [None; 3];
        let (size, nframes) = spaces
            .package(
                &mut Context::from_waker(Waker::noop()),
                [Some(sender.dcid); 3],
                &mut external,
                &mut bytes[..1200],
                &mut limits,
                &mut frames,
                &mut pns,
                false,
            )
            .unwrap();
        assert_eq!(size, expected.iter().sum::<usize>());
        assert_eq!(limits.credit, 2400 - size);
        assert_eq!(limits.send_quota, 2400 - size);
        assert_eq!(&bytes[1200..], &[0xa5; 16]);
        assert!(frames.is_empty());
        let mut recorded = 0;
        for epoch in Epoch::EPOCHS {
            assert_eq!(pns[epoch].is_some(), expected[epoch] != 0);
            if let Some(pn) = pns[epoch] {
                let journal = spaces
                    .0
                    .get(epoch as u64)
                    .unwrap()
                    .sent_journal()
                    .lock_guard();
                assert_eq!(journal.packet(pn).unwrap().size, expected[epoch]);
                recorded += journal.frames(pn).count();
            }
        }
        assert_eq!(recorded, expected.iter().filter(|&&size| size != 0).count());
        assert_eq!(nframes, recorded + expected.iter().zip(sizes).filter(|(size, original)| **size > *original).count());
        let packets = PacketReader::new(BytesMut::from(&bytes[..size]), sender.dcid.len());
        for packet in packets {
            let ParsedPacket::Data(packet) = packet.unwrap() else {
                panic!()
            };
            let (epoch, plaintext) = match packet.header {
                DataHeader::Long(long::DataHeader::Initial(header)) => {
                    let opened = CipherPacket::new(header, packet.bytes, packet.offset)
                        .decrypt_long_packet(&keys(true).opening, |_| Ok(pns[0].unwrap()))
                        .unwrap()
                        .unwrap();
                    (
                        Epoch::Initial,
                        FrameReader::new(opened.body(), opened.get_type())
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap(),
                    )
                }
                DataHeader::Long(long::DataHeader::Handshake(header)) => {
                    let opened = CipherPacket::new(header, packet.bytes, packet.offset)
                        .decrypt_long_packet(&keys(true).opening, |_| Ok(pns[1].unwrap()))
                        .unwrap()
                        .unwrap();
                    (
                        Epoch::Handshake,
                        FrameReader::new(opened.body(), opened.get_type())
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap(),
                    )
                }
                DataHeader::Short(header) => {
                    let opened = receiver
                        .spaces
                        .data
                        .keys
                        .get()
                        .unwrap()
                        .open_packet(
                            CipherPacket::new(header, packet.bytes, packet.offset),
                            |_| Ok(pns[2].unwrap()),
                            Duration::from_secs(1),
                        )
                        .unwrap()
                        .unwrap();
                    (
                        Epoch::Data,
                        FrameReader::new(opened.body(), opened.get_type())
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap(),
                    )
                }
                _ => panic!(),
            };
            let padding = plaintext
                .iter()
                .filter(|(frame, _)| matches!(frame, Frame::Padding(_)))
                .count();
            assert_eq!(padding, expected[epoch] - sizes[epoch]);
            assert!(plaintext.iter().any(|(frame, _)| matches!(frame, Frame::Crypto(_, bytes) if bytes.iter().all(|&b| b == epoch as u8 + 1))));
        }
    }
}

#[test]
fn recursive_packing_validation_checks_capacity_before_consuming_the_frame() {
    use qbase::{
        frame::{CryptoFrame, PathChallengeFrame},
        packet::Package,
    };
    use qtransport::space::assemble::Constraints;
    for capacity in [1199, 1200] {
        let [sender, _] = super::punch::pair();
        let mut spaces = sender.phase.spaces.read().unwrap().snapshot();
        spaces.0.push_back(sender.spaces.handshake.clone()).unwrap();
        spaces.0.push_back(sender.spaces.data.clone()).unwrap();
        spaces.0.pop_front();
        let mut crypto = Some((
            CryptoFrame::new(0u32.into(), 300u32.into()),
            bytes::Bytes::from_static(&[1; 300]),
        ));
        let mut challenge = Some(PathChallengeFrame::random());
        let mut external: [&mut [&mut dyn for<'b> Package<&'b mut [u8]>]; 3] =
            [&mut [], &mut [&mut crypto], &mut [&mut challenge]];
        let mut bytes = [0xa5; 1216];
        let mut limits = Constraints {
            send_quota: 1200,
            credit: 1200,
            ..Default::default()
        };
        let mut frames = Vec::new();
        let mut pns = [None; 3];
        let (size, _) = spaces
            .package(
                &mut Context::from_waker(Waker::noop()),
                [Some(sender.dcid); 3],
                &mut external,
                &mut bytes[..capacity],
                &mut limits,
                &mut frames,
                &mut pns,
                false,
            )
            .unwrap();
        assert!(pns[0].is_none());
        assert!(pns[1].is_some());
        assert_eq!(pns[2].is_some(), capacity == 1200);
        assert_eq!(challenge.is_none(), capacity == 1200);
        assert_eq!(size == 1200, capacity == 1200);
        assert_eq!(limits.credit, 1200 - size);
        assert_eq!(&bytes[capacity..], &vec![0xa5; 1216 - capacity]);
        assert!(frames.is_empty());
        spaces.0.pop_front();
        assert_eq!(spaces.0.offset(), 2);
        let mut ping = Some(PingFrame);
        let (size, _) = spaces
            .package(
                &mut Context::from_waker(Waker::noop()),
                [Some(sender.dcid); 3],
                &mut [&mut [], &mut [], &mut [&mut ping]],
                &mut bytes[..1200],
                &mut Constraints {
                    send_quota: 1200,
                    credit: 1200,
                    ..Default::default()
                },
                &mut frames,
                &mut [None; 3],
                false,
            )
            .unwrap();
        assert!(size > 0 && size < 1200);
    }
}

#[test]
fn recursive_packing_retains_initial_token_and_cancels_ancestors_on_error() {
    use qbase::packet::{GetDcid, GetScid, GetType, Package};
    use qtransport::space::{InitialSpace, Spaces, assemble::Constraints};
    let scid = ConnectionId::from_slice(b"local000");
    let initial = Arc::new(InitialSpace::new(
        scid,
        ArcKeys::new(Arc::new(keys(false))),
        Some(b"token".to_vec()),
    ));
    let handshake = Arc::new(HandshakeSpace::new(scid, initial.keys.clone()));
    let mut spaces = Spaces(qbase::util::IndexDeque::with_capacity(3));
    spaces.0.push_back(initial.clone()).unwrap();
    spaces.0.push_back(handshake.clone()).unwrap();
    let mut bytes = [0; 1200];
    let mut frames = Vec::new();
    let mut cx = Context::from_waker(Waker::noop());
    for cid in [b"remote00", b"remote01"] {
        let dcid = ConnectionId::from_slice(cid);
        let mut ping = Some(PingFrame);
        let mut pns = [None; 3];
        spaces
            .package(
                &mut cx,
                [Some(dcid); 3],
                &mut [&mut [&mut ping], &mut [], &mut []],
                &mut bytes,
                &mut Constraints {
                    send_quota: 1200,
                    credit: 1200,
                    ..Default::default()
                },
                &mut frames,
                &mut pns,
                false,
            )
            .unwrap();
        let ParsedPacket::Data(packet) = PacketReader::new(BytesMut::from(bytes.as_slice()), 8)
            .next()
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        let DataHeader::Long(long::DataHeader::Initial(header)) = packet.header else {
            panic!()
        };
        assert_eq!(header.token(), b"token");
        assert_eq!(*header.scid(), scid);
        assert_eq!(*header.dcid(), dcid);
        let opened = CipherPacket::new(header, packet.bytes, packet.offset)
            .decrypt_long_packet(&keys(true).opening, |_| Ok(pns[0].unwrap()))
            .unwrap()
            .unwrap();
        assert!(
            FrameReader::new(opened.body(), opened.get_type())
                .any(|f| matches!(f.unwrap().0, Frame::Ping(_)))
        );
    }
    struct Failed;
    impl<B: bytes::BufMut + ?Sized> Package<B> for Failed {
        fn poll_dump(
            &mut self,
            _: &mut Context<'_>,
            _: &mut qbase::packet::PacketBuffer<'_, B>,
        ) -> Poll<Result<usize, crate::Error>> {
            Poll::Ready(Err(QuicError::with_default_fty(
                ErrorKind::Internal,
                "assembly failed",
            )
            .into()))
        }
    }
    initial
        .crypto
        .writer()
        .write_all(b"retry")
        .now_or_never()
        .unwrap()
        .unwrap();
    let mut ping = Some(PingFrame);
    let mut pns = [None; 3];
    let mut limits = Constraints {
        send_quota: 1200,
        credit: 1200,
        ..Default::default()
    };
    let result = spaces.package(
        &mut cx,
        [Some(Default::default()); 3],
        &mut [&mut [&mut ping], &mut [&mut Failed], &mut []],
        &mut bytes,
        &mut limits,
        &mut frames,
        &mut pns,
        false,
    );
    assert!(result.is_err());
    assert_eq!(pns, [None; 3]);
    assert!(frames.is_empty());
    assert_eq!((limits.send_quota, limits.credit), (1200, 1200));
    spaces
        .package(
            &mut cx,
            [Some(Default::default()); 3],
            &mut [&mut [], &mut [], &mut []],
            &mut bytes,
            &mut limits,
            &mut frames,
            &mut pns,
            false,
        )
        .unwrap();
    assert!(initial.sent_journal.lock_guard().frames(pns[0].unwrap())
        .any(|frame| matches!(frame, GuaranteedFrame::Crypto(frame) if frame.offset() == 0 && frame.len() == 5)));
}

#[tokio::test(start_paused = true)]
async fn path_validation_respects_small_amplification_credit() {
    use qbase::frame::{PathChallengeFrame, io::ReceiveFrame};

    for received in [0, 128, 399, 400] {
        for reply in [false, true] {
            let (initial, mature) = mature_server_phase();
            let phase = crate::ArcConnPhase::initial(initial);
            super::enter_mature(&phase, &mature);
            let paths = Paths::new(Role::Server, phase, Duration::ZERO, Duration::ZERO);
            super::confirm_handshake(&paths);
            let path = Arc::new(Path::new(
                Pathway::new(
                    EndpointAddr::direct("127.0.0.1:35101".parse().unwrap()),
                    EndpointAddr::direct("127.0.0.1:35102".parse().unwrap()),
                ),
                paths.handshake.clone(),
                ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
                mature.resender.clone(),
            ));
            path.handshake_confirmed();
            path.on_datagram_received(received);
            let challenge = PathChallengeFrame::from_slice(&[7; 8]);
            if reply {
                path.recv_frame(challenge).unwrap();
            } else {
                path.set_challenge(challenge);
            }
            let credit = path.amplification_credit();
            let dcid_cell = OnceLock::new();
            dcid_cell.set(crate::common::dcid(mature.dcid)).unwrap();
            let mut datagrams = [BytesMut::with_capacity(1200)];
            let mut frames = Vec::new();
            let mut pns: BurstPns = [[None; 3]; MAX_BURST_PACKETS];
            let mut collector = burst(
                &path.cc,
                &path.anti_amplifier,
                &mut datagrams,
                &mut frames,
                &mut pns,
            )
            .collect(&paths, &path, &dcid_cell);
            let result = Pin::new(&mut collector).poll(&mut Context::from_waker(Waker::noop()));
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
                        .packet(pns[0][Epoch::Data].unwrap())
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
            paths.phase().terminator().terminate();
        }
    }
}
