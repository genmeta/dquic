use std::{task::Waker, time::Duration};

use futures::FutureExt;
use qbase::{
    cid::ConnectionId,
    frame::FrameReader,
    net::{addr::EndpointAddr, route::Pathway},
    packet::{DataHeader, Packet as ParsedPacket, PacketReader, long},
    role::Role,
    time::ArcConnIdle,
};
use qtransport::{keys::ArcKeys, packet::CipherPacket, space::Space};
use tokio::io::AsyncWriteExt;

use super::*;
use crate::InitialPhase;
fn keys(server: bool) -> qtls::BidirectionalKeys {
    qtls::default_provider()
        .cipher_suites
        .iter()
        .find_map(|suite| suite.tls13().and_then(|suite| suite.quic_suite()))
        .unwrap()
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

#[tokio::test]
async fn idle_sending_loop_waits_for_sources_and_exits_when_retired() {
    let phase = crate::ArcConnPhase::initial(InitialPhase::new(
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    ));
    let idle = ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let paths = Paths::new(Role::Client, phase.clone(), idle.clone());
    let pathway = Pathway::new(
        EndpointAddr::direct("127.0.0.1:30001".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:30002".parse().unwrap()),
    );
    let path = Arc::new(Path::new(
        pathway,
        Role::Client,
        idle.timer(),
        paths.phase().get().trackers(),
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

#[tokio::test]
async fn failed_submission_returns_crypto_and_exits_the_sending_task() {
    let initial = InitialPhase::new(
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let space = initial.initial.clone();
    space.crypto.writer().write_all(b"hello").await.unwrap();
    let phase = crate::ArcConnPhase::initial(initial);
    let idle = ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let paths = Paths::new(Role::Client, phase, idle.clone());
    // No registered socket: collect succeeds, but submitting the batch fails.
    let path = Arc::new(Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:0".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:35002".parse().unwrap()),
        ),
        Role::Client,
        idle.timer(),
        paths.phase().get().trackers(),
    ));
    path.client_handshaking();
    path.decide(true);
    paths
        .entries
        .lock()
        .unwrap()
        .insert(path.pathway, path.clone());
    tokio::time::timeout(Duration::from_secs(1), sending(paths.clone(), path.clone()))
        .await
        .unwrap();
    assert!(paths.snapshot().is_empty());
    assert_eq!(path.state(), qtransport::path::PathState::Retired);
    assert!(paths.closed().now_or_never().is_some());

    let header =
        LongHeaderBuilder::with_cid(Default::default(), Default::default()).initial(vec![]);
    let mut buffer = [0; 128];
    let mut packet = Packet::new(
        header,
        (2, qbase::packet::PacketNumber::U8(2)),
        &mut buffer[..],
    )
    .unwrap();
    let mut frames = Vec::new();
    assert!(matches!(
        packet.assemble(
            &mut Context::from_waker(Waker::noop()),
            [&mut space.crypto.outgoing()],
            &mut frames,
        ),
        Poll::Ready(Ok(1))
    ));
    assert!(matches!(frames.as_slice(), [Frame::Crypto(frame, ())]
        if frame.offset() == 0 && frame.len() == 5));
}

#[tokio::test]
async fn collector_mixes_spaces_and_selected_crypto_advances() {
    let initial = InitialPhase::new(
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let message = vec![42; 7200];
    initial
        .initial
        .crypto
        .writer()
        .write_all(&message)
        .await
        .unwrap();
    let handshake = Arc::new(Space::new(
        Epoch::Handshake,
        ArcKeys::new(Arc::new(keys(false))),
    ));
    handshake
        .crypto
        .writer()
        .write_all(b"handshake")
        .await
        .unwrap();
    let phase = crate::ArcConnPhase::initial(initial);
    phase.enter_handshake(handshake);
    let idle = ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let paths = Paths::new(Role::Client, phase.clone(), idle.clone());
    let pathway = Pathway::new(
        EndpointAddr::direct("127.0.0.1:31001".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:31002".parse().unwrap()),
    );
    let path = Arc::new(Path::new(
        pathway,
        Role::Client,
        idle.timer(),
        paths.phase().get().trackers(),
    ));
    path.client_handshaking();
    path.decide(true);

    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::new();
    let mut pns = std::array::from_fn(|_| Vec::new());
    let count = burst(
        &path.cc,
        &path.anti_amplifier,
        &mut datagrams,
        &mut frames,
        &mut pns,
    )
    .collect(&paths, &path, paths.phase().get().dcid())
    .now_or_never()
    .unwrap()
    .unwrap();
    assert_eq!(count, 8);
    assert!(!pns[Epoch::Initial].is_empty());
    assert_eq!(pns[Epoch::Handshake].len(), 1);
    assert!(frames.is_empty());
    let mut recovered = Vec::new();
    for &PendingPacket { index, pn, .. } in &pns[Epoch::Initial] {
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
                let phase = crate::ArcConnPhase::initial(InitialPhase::new(
                    ConnectionId::from_slice(b"localcid"),
                    ConnectionId::from_slice(b"original"),
                    keys(role == Role::Server),
                ));
                let ConnPhase::Initial(initial) = phase.get() else {
                    unreachable!()
                };
                initial
                    .initial
                    .crypto
                    .writer()
                    .write_all(b"hello")
                    .await
                    .unwrap();
                if handshaking {
                    phase.enter_handshake(Arc::new(Space::new(
                        Epoch::Handshake,
                        initial.initial.keys.clone(),
                    )));
                }
                let idle = ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
                let paths = Paths::new(role, phase.clone(), idle.clone());
                let path = Arc::new(Path::new(
                    Pathway::new(
                        EndpointAddr::direct("127.0.0.1:35001".parse().unwrap()),
                        EndpointAddr::direct("127.0.0.1:35002".parse().unwrap()),
                    ),
                    role,
                    idle.timer(),
                    paths.phase().get().trackers(),
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
                let mut pns = std::array::from_fn(|_| Vec::new());
                for attempt in 0..2 {
                    let result = burst(
                        &path.cc,
                        &path.anti_amplifier,
                        &mut datagrams,
                        &mut frames,
                        &mut pns,
                    )
                    .collect(&paths, &path, phase.get().dcid())
                    .now_or_never();
                    let replays = role == Role::Client && !handshaking && selected == u8::MAX;
                    if selected != 0 && (attempt == 0 || replays) {
                        assert!(
                            matches!(result, Some(Ok(1))),
                            "{role:?} {handshaking} {selected} {attempt}"
                        );
                        pns[Epoch::Initial].clear();
                    } else {
                        assert!(
                            result.is_none(),
                            "{role:?} {handshaking} {selected} {attempt}"
                        );
                        assert!(pns.iter().all(Vec::is_empty));
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
    assert_eq!(frames.len(), 1);
}

#[tokio::test]
async fn mixed_packets_consume_shared_budget_once_including_envelope() {
    for overhead in [0, 40] {
        let initial = InitialPhase::new(
            ConnectionId::from_slice(b"clientid"),
            ConnectionId::from_slice(b"original"),
            keys(false),
        );
        let space = initial.initial.clone();
        space.crypto.writer().write_all(b"hello").await.unwrap();
        let handshake = Space::new(Epoch::Handshake, space.keys.clone());
        handshake
            .crypto
            .writer()
            .write_all(b"handshake")
            .await
            .unwrap();
        let idle = ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
        let paths = Paths::new(
            Role::Client,
            crate::ArcConnPhase::initial(initial),
            idle.clone(),
        );
        let path = Arc::new(Path::new(
            Pathway::new(
                EndpointAddr::direct("127.0.0.1:35001".parse().unwrap()),
                EndpointAddr::direct("127.0.0.1:35002".parse().unwrap()),
            ),
            Role::Client,
            idle.timer(),
            paths.phase().get().trackers(),
        ));
        let mut datagrams = std::array::from_fn::<_, 3, _>(|_| BytesMut::new());
        let mut frames = Vec::new();
        let mut pns = std::array::from_fn(|_| Vec::new());
        let mut collector = burst(
            &path.cc,
            &path.anti_amplifier,
            &mut datagrams,
            &mut frames,
            &mut pns,
        )
        .collect(&paths, &path, paths.phase().get().dcid());
        let mut limits = Constraints {
            send_quota: 2400,
            credit: 2400,
            overhead,
            ..Default::default()
        };
        let mut cx = Context::from_waker(Waker::noop());
        let header = || LongHeaderBuilder::with_cid(Default::default(), Default::default());
        assert_eq!(
            collector
                .collect_long(
                    &mut cx,
                    &space,
                    header().initial(vec![]),
                    &mut space.crypto.outgoing(),
                    &mut limits,
                    &mut None,
                )
                .unwrap(),
            1
        );
        assert_eq!(collector.burst.datagrams[0].len() + overhead, 1200);
        assert_eq!((limits.send_quota, limits.credit), (1200, 1200));
        assert_eq!(
            collector
                .collect_long(
                    &mut cx,
                    &handshake,
                    header().handshake(),
                    &mut handshake.crypto.outgoing(),
                    &mut limits,
                    &mut None,
                )
                .unwrap(),
            1
        );
        let size = collector.burst.datagrams[1].len() + overhead;
        assert!(size < 1200); // Initial padding does not carry into Handshake.
        assert_eq!(
            (limits.send_quota, limits.credit),
            (1200 - size, 1200 - size)
        );
        assert_eq!(
            collector
                .collect_long(
                    &mut cx,
                    &handshake,
                    header().handshake(),
                    &mut handshake.crypto.outgoing(),
                    &mut limits,
                    &mut None,
                )
                .unwrap(),
            0
        );
        assert_eq!(
            (limits.send_quota, limits.credit),
            (1200 - size, 1200 - size)
        );
        assert!(collector.burst.frames.is_empty());
        assert_eq!(collector.burst.pns[Epoch::Initial].len(), 1);
        assert_eq!(collector.burst.pns[Epoch::Handshake].len(), 1);
        let pn = collector.burst.pns[Epoch::Handshake][0].pn;
        assert!(
            handshake
                .sent_journal
                .lock_guard()
                .frames(pn)
                .any(|frame| matches!(frame, Frame::Crypto(_, ())))
        );
    }
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
        let mut packet = SendingPacket {
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
    let mut packet = SendingPacket {
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let phase = crate::ArcConnPhase::initial(InitialPhase::new(
        ConnectionId::from_slice(b"serverid"),
        ConnectionId::from_slice(b"original"),
        keys(true),
    ));
    let idle = ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let paths = Paths::new(Role::Server, phase.clone(), idle.clone());
    let pathway = Pathway::new(
        EndpointAddr::direct("127.0.0.1:31001".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:31002".parse().unwrap()),
    );
    let path = Arc::new(Path::new(
        pathway,
        Role::Server,
        idle.timer(),
        paths.phase().get().trackers(),
    ));

    path.cc.on_pkt_rcvd(Epoch::Initial, 0, true);
    let ConnPhase::Initial(initial) = phase.get() else {
        panic!()
    };
    initial
        .initial
        .rcvd_journal
        .on_rcvd_pn(0, true, Duration::from_secs(1));
    let mut datagrams = [BytesMut::with_capacity(1200)];
    let mut frames = Vec::new();
    let mut pns = std::array::from_fn(|_| Vec::new());
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
    .collect(&paths, &path, paths.phase().get().dcid());
    assert!(Pin::new(&mut collector).poll(&mut cx).is_pending());
    assert_eq!(
        count.0.load(Ordering::Relaxed),
        0,
        "waiting for credit must not continuously wake this task"
    );
    drop(collector);
    initial
        .initial
        .crypto
        .writer()
        .write_all(b"hello")
        .await
        .unwrap();
    path.anti_amplifier.on_received(1200);
    path.retire();
    assert!(count.0.load(Ordering::Relaxed) > 0);

    let mut running = Box::pin(sending(paths, path));
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let phase = crate::ArcConnPhase::initial(InitialPhase::new(
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    ));
    let idle = ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let paths = Paths::new(Role::Client, phase.clone(), idle.clone());
    let make_path = |port| {
        let path = Arc::new(Path::new(
            Pathway::new(
                EndpointAddr::direct(([127, 0, 0, 1], port).into()),
                EndpointAddr::direct("127.0.0.1:32002".parse().unwrap()),
            ),
            Role::Client,
            idle.timer(),
            paths.phase().get().trackers(),
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
    let mut first_pns = std::array::from_fn(|_| Vec::new());
    let mut second_pns = std::array::from_fn(|_| Vec::new());
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
    .collect(&paths, &first, paths.phase().get().dcid());
    let mut two = burst(
        &second.cc,
        &second.anti_amplifier,
        &mut second_bytes,
        &mut second_frames,
        &mut second_pns,
    )
    .collect(&paths, &second, paths.phase().get().dcid());
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
    initial
        .initial
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
    initial
        .initial
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
    let initial = InitialPhase::new(
        ConnectionId::from_slice(b"server00"),
        ConnectionId::from_slice(b"original"),
        keys(true),
    );
    let terminator = initial.terminator.clone();
    let space = initial.initial.clone();
    let phase = crate::ArcConnPhase::initial(initial);
    let idle = ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let paths = Paths::new(Role::Server, phase, idle.clone());
    let path = Arc::new(Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:33001".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:33002".parse().unwrap()),
        ),
        Role::Server,
        idle.timer(),
        paths.phase().get().trackers(),
    ));
    path.validate();
    path.decide(true);
    let error = QuicError::with_default_fty(ErrorKind::Internal, "TLS failed");
    terminator.on_error(
        &crate::CloseReason::Internal(error.clone()),
        Duration::from_secs(3),
    );
    space.crypto.on_error(&error.into());
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::new();
    let mut pns = std::array::from_fn(|_| Vec::new());
    let mut collector = burst(
        &path.cc,
        &path.anti_amplifier,
        &mut datagrams,
        &mut frames,
        &mut pns,
    )
    .collect(&paths, &path, paths.phase().get().dcid());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut collector).poll(&mut cx),
        Poll::Ready(Ok(1))
    ));
    let pn = collector.burst.pns[Epoch::Initial][0].pn;
    assert!(
        space
            .sent_journal
            .lock_guard()
            .frames(pn)
            .any(|frame| matches!(frame, Frame::Close(_)))
    );
    assert!(
        space
            .sent_journal
            .lock_guard()
            .frames(pn)
            .all(|frame| matches!(frame, Frame::Close(_) | Frame::Padding(_)))
    );
    drop(collector);
    pns[Epoch::Initial].clear();
    let mut collector = burst(
        &path.cc,
        &path.anti_amplifier,
        &mut datagrams,
        &mut frames,
        &mut pns,
    )
    .collect(&paths, &path, paths.phase().get().dcid());
    assert!(Pin::new(&mut collector).poll(&mut cx).is_pending());
    terminator.terminate();
    assert!(matches!(
        Pin::new(&mut collector).poll(&mut cx),
        Poll::Ready(Err(_))
    ));
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
        if let qtls::TlsEvent::WriteCrypto { epoch: level, bytes } = event {
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

fn mature_server_phase() -> (InitialPhase, Arc<MaturePhase>) {
    use qbase::param::{
        ArcParameters,
        handy::{client_parameters, server_parameters},
    };
    let initial = InitialPhase::new(
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
    let router = Arc::new(qtransport::router::QuicRouter::new());
    let (inbox, _receiver) = qtransport::packet::channel::new();
    let registry = crate::CidRegistry::new(
        Role::Server,
        initial.odcid,
        crate::ArcLocalCids::new(
            initial.scid,
            router.registry_on_issuing_scid(inbox, initial.reliable_frames.clone()),
        ),
        qbase::cid::ArcRemoteCids::new(2, initial.reliable_frames.clone()),
    );
    let dcid = registry.remote.apply_dcid();
    registry
        .remote
        .apply_initial_dcid(ConnectionId::from_slice(b"client00"), &dcid);
    let handshake = Arc::new(Space::new(
        Epoch::Handshake,
        ArcKeys::new(Arc::new(keys(true))),
    ));
    let mature = crate::MaturePhase::new(
        &initial,
        handshake,
        parameters,
        ConnectionId::from_slice(b"client00"),
        initial.reliable_frames.clone(),
        registry,
        dcid,
        qtransport::keys::ArcOneRttKeys::from(server_one_rtt_keys()),
    );
    (initial, mature)
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
    phase.cancel(&b);
    phase.set_dcid(ConnectionId::from_slice(b"peer0000"));
    assert_eq!(initial.dcid(), ConnectionId::from_slice(b"peer0000"));
    assert_eq!(first.0.load(Ordering::Relaxed), 1);
    assert_eq!(second.0.load(Ordering::Relaxed), 0);
    drop(phase.poll_phase(&mut Context::from_waker(&b)));

    phase.enter_handshake(mature.spaces.handshake.clone());
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
    assert!(Arc::ptr_eq(&handshake.initial, &mature.spaces.initial));
    assert_eq!(handshake.scid, mature.scid);
    assert_eq!(phase.get().dcid(), ConnectionId::from_slice(b"peer0000"));
    phase.cancel(&b);
    phase.set_dcid(ConnectionId::from_slice(b"peer0001"));
    assert_eq!(handshake.dcid(), ConnectionId::from_slice(b"peer0001"));
    assert_eq!(first.0.load(Ordering::Relaxed), 3);
    assert_eq!(second.0.load(Ordering::Relaxed), 1);
    drop(phase.poll_phase(&mut cx));
    drop(phase.poll_phase(&mut cx));
    drop(phase.poll_phase(&mut Context::from_waker(&b)));

    phase.enter_mature(mature);
    assert_eq!(first.0.load(Ordering::Relaxed), 4);
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
    phase.cancel(&a);
    phase.set_dcid(ConnectionId::from_slice(b"ignored0"));
    assert_eq!(first.0.load(Ordering::Relaxed), 4);
    assert_eq!(phase.get().dcid(), ConnectionId::from_slice(b"client00"));
}

#[tokio::test(start_paused = true)]
async fn existing_path_recovers_new_spaces_after_phase_upgrade() {
    let (initial, mature) = mature_server_phase();
    let phase = crate::ArcConnPhase::initial(initial);
    let idle = ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let paths = Paths::new(Role::Server, phase.clone(), idle.clone());
    let path = Arc::new(Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:34101".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:34102".parse().unwrap()),
        ),
        Role::Server,
        idle.timer(),
        phase.get().trackers(),
    ));
    path.validate();
    path.decide(true);
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::new();
    let mut pns = std::array::from_fn(|_| Vec::new());

    for epoch in [Epoch::Handshake, Epoch::Data] {
        let (crypto, journal) = if epoch == Epoch::Handshake {
            phase.enter_handshake(mature.spaces.handshake.clone());
            (
                &mature.spaces.handshake.crypto,
                &mature.spaces.handshake.sent_journal,
            )
        } else {
            phase.enter_mature(mature.clone());
            mature.retire_handshake_spaces();
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
            .collect(&paths, &path, phase.get().dcid())
            .now_or_never()
            .unwrap()
            .unwrap();
            assert_eq!(pns[epoch].len(), 1);
            let PendingPacket { index, pn, .. } = pns[epoch][0];
            journal.on_sent(pn, true, Duration::from_secs(1), Duration::from_secs(3));
            path.cc
                .on_pkt_sent(epoch, pn, true, datagrams[index].len(), true, None);
            sent.push(pn);
            for entries in &mut pns {
                entries.clear();
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
        .collect(&paths, &path, phase.get().dcid())
        .now_or_never()
        .expect("loss must make the original CRYPTO range sendable")
        .unwrap();
        assert_eq!(pns[epoch].len(), 1);
        let records = journal.lock_guard();
        assert!(records.frames(pns[epoch][0].pn).any(|frame| {
            matches!(frame, Frame::Crypto(frame, _) if frame.offset() == 0 && frame.len() == 6)
        }));
        for entries in &mut pns {
            entries.clear();
        }
    }
}
#[tokio::test]
async fn mature_server_collects_its_three_spaces_and_one_rtt_close() {
    let (initial, mature) = mature_server_phase();
    for crypto in [
        &mature.spaces.initial.crypto,
        &mature.spaces.handshake.crypto,
        &mature.spaces.data.crypto,
    ] {
        crypto.writer().write_all(b"crypto").await.unwrap();
    }
    let phase = crate::ArcConnPhase::initial(initial);
    phase.enter_mature(mature.clone());
    let idle = ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let paths = Paths::new(Role::Server, phase, idle.clone());
    let path = Arc::new(Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:34001".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:34002".parse().unwrap()),
        ),
        Role::Server,
        idle.timer(),
        paths.phase().get().trackers(),
    ));
    path.validate();
    path.decide(true);
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::new();
    let mut pns = std::array::from_fn(|_| Vec::new());
    assert_eq!(
        burst(
            &path.cc,
            &path.anti_amplifier,
            &mut datagrams,
            &mut frames,
            &mut pns
        )
        .collect(&paths, &path, paths.phase().get().dcid())
        .now_or_never()
        .unwrap()
        .unwrap(),
        3
    );
    for epoch in Epoch::EPOCHS {
        assert_eq!(pns[epoch].len(), 1);
    }
    assert_eq!(pns[Epoch::Initial][0].index, 0);
    assert_eq!(pns[Epoch::Handshake][0].index, 1);
    assert_eq!(pns[Epoch::Data][0].index, 2);
    assert!(frames.is_empty());
    // Consume this burst's packet numbers before collecting the next burst.
    for entries in &mut pns {
        entries.clear();
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
        .collect(&paths, &path, paths.phase().get().dcid())
        .now_or_never()
        .is_none()
    );
    assert!(pns.iter().all(Vec::is_empty));
    path.handshake_confirmed();
    assert!(matches!(
        burst(
            &path.cc,
            &path.anti_amplifier,
            &mut datagrams,
            &mut frames,
            &mut pns
        )
        .collect(&paths, &path, paths.phase().get().dcid())
        .now_or_never(),
        Some(Ok(1))
    ));
    assert_eq!(pns[Epoch::Initial].len(), 1);
    pns[Epoch::Initial].clear();
    // An undecided path must wait instead of collecting 1-RTT data. Retirement
    // must wake that wait even though the socket has never been polled.
    let waiting_path = Arc::new(Path::new(
        Pathway::new(
            EndpointAddr::direct("127.0.0.1:34003".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:34002".parse().unwrap()),
        ),
        Role::Server,
        idle.timer(),
        paths.phase().get().trackers(),
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
    mature.terminator.on_error(
        &crate::CloseReason::Internal(error.clone()),
        Duration::from_secs(3),
    );
    mature.flow.on_conn_error(&error.clone().into());
    mature.spaces.data.crypto.on_error(&error.into());
    assert_eq!(
        burst(
            &path.cc,
            &path.anti_amplifier,
            &mut datagrams,
            &mut frames,
            &mut pns
        )
        .collect(&paths, &path, paths.phase().get().dcid())
        .now_or_never()
        .unwrap()
        .unwrap(),
        1
    );
    assert!(pns[Epoch::Initial].is_empty());
    assert!(pns[Epoch::Handshake].is_empty());
    let pn = pns[Epoch::Data][0].pn;
    assert!(
        mature
            .spaces
            .data
            .sent_journal
            .lock_guard()
            .frames(pn)
            .any(|f| matches!(f, Frame::Close(_)))
    );
}
