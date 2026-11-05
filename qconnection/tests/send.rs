use std::{
    future::Future,
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
    frame::{Frame, FrameReader, GuaranteedFrame, PingFrame},
    net::{addr::EndpointAddr, route::Pathway},
    packet::{
        DataHeader, LongHeaderBuilder, Packet as ParsedPacket, PacketReader,
        assemble::{Constraints, Limit},
        long,
    },
    role::Role,
};
use qcongestion::Transport as _;
use qconnection::send::{Burst, MAX_BURST_PACKETS, Packet};
use qtransport::{keys::ArcKeys, packet::CipherPacket, space::HandshakeSpace};
use tokio::io::AsyncWriteExt;

mod common;
mod send {
    mod task;
}
use common::initial_keys as keys;

#[test]
fn packet_continues_after_pending_and_no_space_sources() {
    let header =
        LongHeaderBuilder::with_cid(Default::default(), Default::default()).initial(vec![]);
    let keys = keys(false);
    let mut bytes = [0u8; 64];
    let mut frames = Vec::new();
    let mut limits = Constraints {
        send_quota: 64,
        credit: 64,
        max_size: 64,
        ..Default::default()
    };
    let mut packet = Packet::new(
        DataHeader::Long(header.into()),
        (7, qbase::packet::PacketNumber::U16(7)),
        &keys.sealing,
    );
    let mut absent: Option<PingFrame> = None;
    let data = [0u8; 100];
    let mut large = (
        qbase::frame::CryptoFrame::new(0u32.into(), 100u32.into()),
        data.as_slice(),
    );
    let mut ping = PingFrame;
    assert!(matches!(
        packet.assemble(&mut Context::from_waker(Waker::noop()), &mut &mut bytes[..], &mut limits, &mut frames, &mut [&mut absent, &mut large, &mut ping]),
        Poll::Ready(Ok(n)) if n > 0
    ));
    assert_eq!(packet.meta.content, qbase::packet::PacketContent::JustPing);
    assert!(frames.is_empty());
}

#[test]
fn repeated_assembly_does_not_append_after_close() {
    let header = qbase::packet::OneRttHeader::new(Default::default(), Default::default());
    let keys = keys(false);
    let mut bytes = BytesMut::with_capacity(128);
    let mut frames = Vec::new();
    let mut limits = Constraints {
        send_quota: 128,
        credit: 128,
        max_size: 128,
        ..Default::default()
    };
    let mut packet = Packet::new(
        DataHeader::Short(header),
        (0, qbase::packet::PacketNumber::U16(0)),
        &keys.sealing,
    );
    let mut close = qbase::frame::ConnectionCloseFrame::new_app(0u32.into(), "closed");
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        matches!(packet.assemble(&mut cx, &mut &mut bytes, &mut limits, &mut frames, &mut [&mut close]), Poll::Ready(Ok(n)) if n > 0)
    );
    let size = bytes.len();
    assert_eq!(
        packet.assemble(
            &mut cx,
            &mut &mut bytes,
            &mut limits,
            &mut frames,
            &mut [&mut PingFrame]
        ),
        Poll::Ready(Ok(0))
    );
    assert_eq!(bytes.len(), size);
    assert_eq!(packet.meta.nframes, 1);
    assert!(frames.is_empty());
}

#[tokio::test]
async fn mixed_packets_consume_shared_budget_once() {
    use qtransport::space::{InitialSpace, Spaces, assemble::Constraints};
    let facts = common::handshake_facts(Role::Client, false);
    let initial = Arc::new(InitialSpace::new(
        Default::default(),
        ArcKeys::new(Arc::new(keys(false))),
        None,
        facts.clone(),
    ));
    let handshake = Arc::new(HandshakeSpace::new(
        Default::default(),
        initial.keys.clone(),
        facts.clone(),
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
        credit: 2432,
        send_quota: 2432,
        overhead: 32,
        ..Default::default()
    };
    let mut bytes = [0; 1200];
    let mut frames = Vec::new();
    let mut pns = [None; 3];
    let mut cx = Context::from_waker(Waker::noop());
    let size = spaces
        .poll_dump(
            &mut cx,
            Default::default(),
            &mut bytes,
            &mut limits,
            &mut frames,
            &mut pns,
            &mut [],
        )
        .unwrap();
    assert_eq!(size, 1200);
    assert_eq!((limits.send_quota, limits.credit), (1200, 1200));
    let a = initial.sent_journal.lock_guard();
    let b = handshake.sent_journal.lock_guard();
    assert!(a.packet(pns[0].unwrap().pn).unwrap().size < 100);
    assert_eq!(
        a.packet(pns[0].unwrap().pn).unwrap().size + b.packet(pns[1].unwrap().pn).unwrap().size,
        1200
    );
    assert_eq!(a.frames(pns[0].unwrap().pn).count(), 1);
    assert_eq!(b.frames(pns[1].unwrap().pn).count(), 1);
    for (index, packet) in PacketReader::new(BytesMut::from(&bytes[..size]), 0).enumerate() {
        let ParsedPacket::Data(packet) = packet.unwrap() else {
            panic!()
        };
        let opened = match packet.header {
            DataHeader::Long(long::DataHeader::Initial(header)) => {
                CipherPacket::new(header, packet.bytes, packet.offset)
                    .decrypt_long_packet(&keys(true).opening, |_| Ok(pns[index].unwrap().pn))
                    .unwrap()
                    .unwrap()
                    .body()
            }
            DataHeader::Long(long::DataHeader::Handshake(header)) => {
                CipherPacket::new(header, packet.bytes, packet.offset)
                    .decrypt_long_packet(&keys(true).opening, |_| Ok(pns[index].unwrap().pn))
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
    let mut frames = Vec::new();
    for pn in 0..2 {
        let header =
            LongHeaderBuilder::with_cid(Default::default(), Default::default()).initial(vec![]);
        let mut packet = Packet::new(
            DataHeader::Long(header.into()),
            (pn, qbase::packet::PacketNumber::U8(pn as u8)),
            &keys.sealing,
        );
        let mut bytes = Vec::new();
        let result = packet.assemble(
            &mut Context::from_waker(Waker::noop()),
            &mut bytes,
            &mut limits,
            &mut frames,
            &mut [&mut PingFrame],
        );
        if pn == 0 {
            assert!(matches!(result, Poll::Ready(Ok(n)) if n > 0));
            bytes.resize(1160, 0);
            packet.padding(&mut bytes, 1160 - packet.len()).unwrap();
            packet.seal(&mut bytes).unwrap();
            limits.take(packet.len(), packet.len());
            assert_eq!(bytes.len(), 1160);
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
    let keys = keys(false);
    let header =
        || LongHeaderBuilder::with_cid(Default::default(), Default::default()).initial(vec![]);
    let mut frames = Vec::new();
    let mut limits = Constraints {
        send_quota: 1200,
        credit: 1200,
        min_size: 1200,
        max_size: 1200,
        ..Default::default()
    };
    let mut packet = Packet::new(
        DataHeader::Long(header().into()),
        (7, PacketNumber::U16(7)),
        &keys.sealing,
    );
    let mut bytes = Vec::new();
    assert!(
        matches!(packet.assemble(&mut Context::from_waker(Waker::noop()), &mut bytes, &mut limits, &mut frames, &mut [&mut PingFrame]), Poll::Ready(Ok(n)) if n > 0)
    );
    bytes.resize(1200, 0);
    packet.padding(&mut bytes, 1200 - packet.len()).unwrap();
    packet.seal(&mut bytes).unwrap();
    limits.take(packet.len(), packet.len());
    assert_eq!(packet.meta.pn, 7);
    assert_eq!(packet.meta.pktlen, 1200);
    let ParsedPacket::Data(parsed) = PacketReader::new(BytesMut::from(bytes.as_slice()), 0)
        .next()
        .unwrap()
        .unwrap()
    else {
        panic!()
    };
    let DataHeader::Long(long::DataHeader::Initial(parsed_header)) = parsed.header else {
        panic!()
    };
    let ty = parsed_header.get_type();
    let opened = CipherPacket::new(parsed_header, parsed.bytes, parsed.offset)
        .decrypt_long_packet(&common::initial_keys(true).opening, |_| Ok(7))
        .unwrap()
        .unwrap();
    assert!(
        FrameReader::new(opened.body(), ty).any(|frame| matches!(frame.unwrap().0, Frame::Ping(_)))
    );
    assert_eq!(limits.send_quota, 0);
    assert_eq!(limits.credit, 0);

    let mut storage = [0; 1200];
    let mut io = IoSliceMut::new(&mut storage);
    let header = header();
    let pn_offset = qbase::packet::HeaderSize::size(&header) + 2;
    let mut packet = Packet::new(
        DataHeader::Long(header.into()),
        (7, PacketNumber::U16(7)),
        &keys.sealing,
    );
    let mut limits = Constraints {
        send_quota: 1200,
        credit: 1200,
        max_size: 1200,
        ..Default::default()
    };
    assert!(
        matches!(packet.assemble(&mut Context::from_waker(Waker::noop()), &mut &mut io[..], &mut limits, &mut frames, &mut [&mut PingFrame]), Poll::Ready(Ok(n)) if n > 0)
    );
    assert_eq!(&io[pn_offset..pn_offset + 2], &[0, 7]);
    assert_eq!(io[pn_offset + 2], 1);
}

#[tokio::test]
async fn recursive_packing_pads_the_last_packet_and_decrypts_each_space() {
    use qbase::{
        frame::{CryptoFrame, EncodeSize},
        packet::{GetType, HeaderSize, Package},
    };
    use qtransport::space::{Spaces, assemble::Constraints};
    for (sizes, expected) in [
        ([700, 0, 0], [1200, 0, 0]),
        ([700, 200, 0], [700, 500, 0]),
        ([700, 200, 100], [700, 200, 300]),
        ([0, 400, 0], [0, 400, 0]),
        ([0, 0, 100], [0, 0, 100]),
        ([0, 0, 0], [0, 0, 0]),
    ] {
        let [sender, receiver] = common::spaces::pair();
        let mut spaces = Spaces(sender.paths.spaces.read_guard().clone());
        spaces.0.push_back(sender.spaces.handshake.clone()).unwrap();
        spaces.0.push_back(sender.spaces.data.clone()).unwrap();
        let mut sources = Epoch::EPOCHS.map(|epoch| {
            let size = sizes[epoch];
            if size == 0 {
                return None;
            }
            let header = match epoch {
                Epoch::Initial => {
                    LongHeaderBuilder::with_cid(
                        sender.peer_cid(),
                        sender.spaces.initial.initial_scid,
                    )
                    .initial(vec![])
                    .size()
                        + 2
                }
                Epoch::Handshake => {
                    LongHeaderBuilder::with_cid(
                        sender.peer_cid(),
                        sender.spaces.handshake.initial_scid,
                    )
                    .handshake()
                    .size()
                        + 2
                }
                Epoch::Data => {
                    qbase::packet::OneRttHeader::new(Default::default(), sender.peer_cid()).size()
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
        let mut sources = Epoch::EPOCHS.map(|epoch| (epoch, sources[epoch].take()));
        let [a, b, c] = &mut sources;
        let mut external: [&mut dyn for<'b> Package<&'b mut [u8]>; 3] = [a, b, c];
        let mut bytes = [0xa5; 1216];
        let mut limits = Constraints {
            send_quota: 2400,
            credit: 2400,
            ..Default::default()
        };
        let mut frames = Vec::new();
        let mut pns = [None; 3];
        let size = spaces
            .poll_dump(
                &mut Context::from_waker(Waker::noop()),
                sender.peer_cid(),
                &mut bytes[..1200],
                &mut limits,
                &mut frames,
                &mut pns,
                &mut external,
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
            if let Some(meta) = pns[epoch] {
                let journal = spaces
                    .0
                    .get(epoch as u64)
                    .unwrap()
                    .sent_journal()
                    .lock_guard();
                let packet = journal.packet(meta.pn).unwrap();
                assert_eq!(meta.pktlen, expected[epoch]);
                assert_eq!(meta.pktlen, packet.size);
                assert_eq!(meta.content, packet.content);
                assert_eq!(meta.in_flight, packet.in_flight);
                assert_eq!(meta.ack, packet.ack);
                recorded += journal.frames(meta.pn).count();
            }
        }
        assert_eq!(recorded, expected.iter().filter(|&&size| size != 0).count());
        assert_eq!(
            pns.iter().flatten().map(|meta| meta.nframes).sum::<usize>(),
            recorded
                + expected
                    .iter()
                    .zip(sizes)
                    .filter(|(size, original)| **size > *original)
                    .count()
        );
        let packets = PacketReader::new(BytesMut::from(&bytes[..size]), sender.peer_cid().len());
        for packet in packets {
            let ParsedPacket::Data(packet) = packet.unwrap() else {
                panic!()
            };
            let (epoch, plaintext) = match packet.header {
                DataHeader::Long(long::DataHeader::Initial(header)) => {
                    let opened = CipherPacket::new(header, packet.bytes, packet.offset)
                        .decrypt_long_packet(&keys(true).opening, |_| Ok(pns[0].unwrap().pn))
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
                        .decrypt_long_packet(&keys(true).opening, |_| Ok(pns[1].unwrap().pn))
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
                        .open_packet(
                            CipherPacket::new(header, packet.bytes, packet.offset),
                            |_| Ok(pns[2].unwrap().pn),
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

#[tokio::test]
async fn recursive_packing_validation_checks_capacity_before_consuming_the_frame() {
    use qbase::{
        frame::{CryptoFrame, PathChallengeFrame},
        packet::Package,
    };
    use qtransport::space::{Spaces, assemble::Constraints};
    for capacity in [1199, 1200] {
        let [sender, _] = common::spaces::pair();
        let mut spaces = Spaces(sender.paths.spaces.read_guard().clone());
        spaces.0.push_back(sender.spaces.handshake.clone()).unwrap();
        spaces.0.push_back(sender.spaces.data.clone()).unwrap();
        spaces.0.pop_front();
        let mut crypto = Some((
            CryptoFrame::new(0u32.into(), 300u32.into()),
            bytes::Bytes::from_static(&[1; 300]),
        ));
        let mut challenge = Some(PathChallengeFrame::random());
        let mut crypto = (Epoch::Handshake, &mut crypto);
        let mut external: [&mut dyn for<'b> Package<&'b mut [u8]>; 2] =
            [&mut crypto, &mut challenge];
        let mut bytes = [0xa5; 1216];
        let mut limits = Constraints {
            send_quota: 1200,
            credit: 1200,
            ..Default::default()
        };
        let mut frames = Vec::new();
        let mut pns = [None; 3];
        let size = spaces
            .poll_dump(
                &mut Context::from_waker(Waker::noop()),
                sender.peer_cid(),
                &mut bytes[..capacity],
                &mut limits,
                &mut frames,
                &mut pns,
                &mut external,
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
        let size = spaces
            .poll_dump(
                &mut Context::from_waker(Waker::noop()),
                sender.peer_cid(),
                &mut bytes[..1200],
                &mut Constraints {
                    send_quota: 1200,
                    credit: 1200,
                    ..Default::default()
                },
                &mut frames,
                &mut [None; 3],
                &mut [&mut (Epoch::Data, &mut ping)],
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
    let facts = common::handshake_facts(Role::Client, false);
    let initial = Arc::new(InitialSpace::new(
        scid,
        ArcKeys::new(Arc::new(keys(false))),
        Some(b"token".to_vec()),
        facts.clone(),
    ));
    let handshake = Arc::new(HandshakeSpace::new(
        scid,
        initial.keys.clone(),
        facts.clone(),
    ));
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
            .poll_dump(
                &mut cx,
                dcid,
                &mut bytes,
                &mut Constraints {
                    send_quota: 1200,
                    credit: 1200,
                    ..Default::default()
                },
                &mut frames,
                &mut pns,
                &mut [&mut (Epoch::Initial, &mut ping)],
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
            .decrypt_long_packet(&keys(true).opening, |_| Ok(pns[0].unwrap().pn))
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
        ) -> Poll<Result<usize, qconnection::Error>> {
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
        send_quota: 1232,
        overhead: 32,
        credit: 1232,
        ..Default::default()
    };
    let result = spaces.poll_dump(
        &mut cx,
        Default::default(),
        &mut bytes,
        &mut limits,
        &mut frames,
        &mut pns,
        &mut [
            &mut (Epoch::Initial, &mut ping),
            &mut (Epoch::Handshake, Failed),
        ],
    );
    assert!(result.is_err());
    assert!(pns.iter().all(Option::is_none));
    assert!(frames.is_empty());
    assert_eq!((limits.send_quota, limits.credit), (1232, 1232));
    spaces
        .poll_dump(
            &mut cx,
            Default::default(),
            &mut bytes,
            &mut limits,
            &mut frames,
            &mut pns,
            &mut [],
        )
        .unwrap();
    assert!(initial.sent_journal.lock_guard().frames(pns[0].unwrap().pn)
        .any(|frame| matches!(frame, GuaranteedFrame::Crypto(frame) if frame.offset() == 0 && frame.len() == 5)));
}

#[test]
fn datagram_overhead_is_charged_once_and_empty_attempts_preserve_budgets() {
    use qbase::{frame::AckFrame, util::IndexDeque};
    use qtransport::space::{Spaces, assemble::Constraints};

    let mut spaces = Spaces(IndexDeque::with_capacity(1));
    spaces.0.reset_offset(Epoch::Handshake as u64);
    spaces
        .0
        .push_back(Arc::new(HandshakeSpace::new(
            Default::default(),
            ArcKeys::new(Arc::new(keys(false))),
            crate::common::handshake_facts(Role::Client, false),
        )))
        .unwrap();
    for flight in [false, true] {
        let mut limits = Constraints {
            credit: 2400,
            send_quota: 2400,
            probe_quota: [1200; 3],
            overhead: 32,
        };
        let mut ack = Some(AckFrame::new(
            0u32.into(),
            0u32.into(),
            0u32.into(),
            vec![],
            None,
        ));
        let mut ping = flight.then_some(PingFrame);
        let mut sources: [&mut dyn for<'b> qbase::packet::Package<&'b mut [u8]>; 2] =
            [&mut ack, &mut ping];
        let mut bytes = [0; 1200];
        let mut frames = Vec::new();
        let mut pns = [None; 3];
        let mut cx = Context::from_waker(Waker::noop());
        let size = spaces
            .poll_dump(
                &mut cx,
                Default::default(),
                &mut bytes,
                &mut limits,
                &mut frames,
                &mut pns,
                &mut sources,
            )
            .unwrap();
        assert!(size > 0);
        assert_eq!(limits.credit, 2400 - size - 32);
        assert_eq!(limits.send_quota, 2400 - if flight { size + 32 } else { 0 });
        assert_eq!(limits.probe_quota, [1200, 0, 1200]);
        let before = limits.clone();
        let size = spaces
            .poll_dump(
                &mut cx,
                Default::default(),
                &mut bytes,
                &mut limits,
                &mut frames,
                &mut [None; 3],
                &mut sources,
            )
            .unwrap();
        assert_eq!(size, 0);
        assert_eq!(limits.credit, before.credit);
        assert_eq!(limits.send_quota, before.send_quota);
        assert_eq!(limits.probe_quota, before.probe_quota);
    }
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
    let paths = common::initial_paths(
        Role::Server,
        ConnectionId::from_slice(b"serverid"),
        ConnectionId::from_slice(b"original"),
        keys(true),
    );
    let path = paths.add_path(Pathway::new(
        EndpointAddr::direct("127.0.0.1:31001".parse().unwrap()),
        EndpointAddr::direct("127.0.0.1:31002".parse().unwrap()),
    ));
    path.cc.on_pkt_rcvd(Epoch::Initial, 0, true);
    let initial = common::initial_space(&paths.spaces);
    initial
        .rcvd_journal
        .on_rcvd_pn(0, true, Duration::from_secs(1));
    let mut datagrams = [BytesMut::with_capacity(1200)];
    let mut frames = Vec::new();
    let mut pns = [[None; 3]; MAX_BURST_PACKETS];
    let count = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    let mut collector = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut pns);
    assert!(
        std::pin::pin!(collector.collect())
            .poll(&mut cx)
            .is_pending()
    );
    assert_eq!(
        count.0.load(Ordering::Relaxed),
        0,
        "waiting for credit must not continuously wake this task"
    );
    drop(collector);
    initial.crypto.writer().write_all(b"hello").await.unwrap();
    path.validation.on_received(1200);
    path.close();
    assert!(count.0.load(Ordering::Relaxed) > 0);
    paths.terminator.terminate();
    common::wait_for_sender_exit(&path).await;
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
    let paths = common::initial_paths(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        keys(false),
    );
    let make_path = |port| {
        paths.add_path(Pathway::new(
            EndpointAddr::direct(([127, 0, 0, 1], port).into()),
            EndpointAddr::direct("127.0.0.1:32002".parse().unwrap()),
        ))
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
    let mut one = Burst::new(
        &paths,
        &first,
        &mut first_bytes,
        &mut first_frames,
        &mut first_pns,
    );
    let mut two = Burst::new(
        &paths,
        &second,
        &mut second_bytes,
        &mut second_frames,
        &mut second_pns,
    );
    assert!(
        std::pin::pin!(one.collect())
            .poll(&mut Context::from_waker(&wa))
            .is_pending()
    );
    assert!(
        std::pin::pin!(two.collect())
            .poll(&mut Context::from_waker(&wb))
            .is_pending()
    );
    drop(one);
    let initial = common::initial_space(&paths.spaces);
    initial.crypto.writer().write_all(b"hello").await.unwrap();
    assert!(a.0.load(Ordering::Relaxed) > 0);
    assert!(b.0.load(Ordering::Relaxed) > 0);
    // Keep the second task credit-blocked while the first task retires.
    second.validation.revalidate().unwrap();
    first.close();
    common::wait_for_sender_exit(&first).await;
    let first_before = a.0.load(Ordering::Relaxed);
    second.validation.on_received(1200);
    second.send_waker.wake_all();
    assert!(matches!(
        std::pin::pin!(two.collect()).poll(&mut Context::from_waker(&wb)),
        Poll::Ready(Ok(1))
    ));
    drop(two);
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
async fn collected_burst_cancels_on_deactivation_and_completes_when_cid_source_changes() {
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
        let paths = common::initial_paths(
            Role::Client,
            ConnectionId::from_slice(b"client00"),
            ConnectionId::from_slice(b"original"),
            keys(false),
        );
        let first = paths.add_path(Pathway::new(
            local,
            EndpointAddr::direct(peer.local_addr().unwrap()),
        ));
        let second = paths.add_path(Pathway::new(
            local,
            EndpointAddr::direct("127.0.0.1:9".parse().unwrap()),
        ));
        if change == 2 {
            paths.progress.on_initial_received(crate::common::cid_value(
                &paths.cid_registry.remote.apply_dcid(),
            ));
            paths.progress.on_path_selected(&paths, &first);
        }
        let initial = common::initial_space(&paths.spaces);
        initial
            .crypto
            .writer()
            .write_all(b"client hello")
            .await
            .unwrap();
        let mut datagrams = std::array::from_fn::<_, MAX_BURST_PACKETS, _>(|_| BytesMut::new());
        let mut frames = Vec::new();
        let mut packets = [[None; 3]; MAX_BURST_PACKETS];
        let mut burst = Burst::new(&paths, &first, &mut datagrams, &mut frames, &mut packets);
        let count = burst.collect().now_or_never().unwrap().unwrap();
        match change {
            0 => {
                paths.progress.on_initial_received(crate::common::cid_value(
                    &paths.cid_registry.remote.apply_dcid(),
                ));
                paths.progress.on_path_selected(&paths, &second);
            }
            1 => {
                paths
                    .progress
                    .on_initial_received(ConnectionId::from_slice(b"server00"));
            }
            _ => {
                paths
                    .cid_registry
                    .remote
                    .recv_frame(NewConnectionIdFrame::new(
                        ConnectionId::from_slice(b"server00"),
                        1u32.into(),
                        1u32.into(),
                    ))
                    .unwrap();
            }
        }
        // Verify the CID on the wire after the policy changes and submission completes.
        burst.submit(count).await.unwrap();
        drop(burst);
        assert!(packets.iter().flatten().all(Option::is_none));
        let mut received = [BytesMut::zeroed(1500)];
        let mut lines = [Line::new(
            Link::new(local.addr(), peer.local_addr().unwrap()),
            64,
            None,
            1500,
        )];
        if change == 0 {
            assert!(!first.is_active());
            assert!(
                peer.receive(&mut received, &mut lines)
                    .now_or_never()
                    .is_none()
            );
            common::retire_all(&paths);
            common::wait_for_sender_exit(&first).await;
            common::wait_for_sender_exit(&second).await;
            QuicProtocol::global().unregister(socket.local_addr().unwrap());
            continue;
        }
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
            panic!("expected Initial packet");
        };
        assert_eq!(*packet.header.dcid(), ConnectionId::from_slice(b"original"));
        {
            let journal = initial.sent_journal.lock_guard();
            assert!(count > 0);
            for bytes in &datagrams[..count] {
                let ParsedPacket::Data(packet) =
                    PacketReader::new(bytes.clone(), 8).next().unwrap().unwrap()
                else {
                    panic!("expected Initial packet");
                };
                let DataHeader::Long(long::DataHeader::Initial(header)) = packet.header else {
                    panic!("expected Initial header");
                };
                let opened = CipherPacket::new(header, packet.bytes, packet.offset)
                    .decrypt_long_packet(&keys(true).opening, |pn| Ok(pn.decode(0)))
                    .unwrap()
                    .unwrap();
                assert!(journal.packet(opened.pn()).unwrap().size > 0);
            }
        }
        assert_eq!(
            first
                .dcid
                .poll_borrow(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(ConnectionId::from_slice(b"server00")))
        );
        first.dcid.refresh();
        common::retire_all(&paths);
        common::wait_for_sender_exit(&first).await;
        common::wait_for_sender_exit(&second).await;
        QuicProtocol::global().unregister(socket.local_addr().unwrap());
    }
}
