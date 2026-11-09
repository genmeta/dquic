use std::{
    io::Cursor,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::BytesMut;
use futures::FutureExt;
use qbase::{
    Epoch,
    cid::ConnectionId,
    frame::{Frame, FrameReader, GuaranteedFrame, PingFrame},
    packet::{DataHeader, LongHeaderBuilder, Packet as ParsedPacket, PacketContent, PacketReader, long},
    role::Role,
};
use qcongestion::Transport as _;
use qconnection::send::Packet;
use qtransport::{keys::ArcKeys, packet::CipherPacket, space::HandshakeSpace};
use tokio::io::AsyncWriteExt;

use crate::common::opening::{PacketOpen as _, ShortOpen as _};

mod common;
mod send {
    mod task;
}
use common::{initial_keys as keys, packet_metadata};

#[test]
fn packet_continues_after_pending_and_no_space_sources() {
    let header = LongHeaderBuilder::with_cid(Default::default(), Default::default()).initial(vec![]);
    let keys = keys(false);
    let mut bytes = [0u8; 64];
    let mut frames = Vec::new();
    let mut packet = Packet::new(DataHeader::Long(header.into()), (7, qbase::packet::PacketNumber::U16(7)), &keys.sealing);
    let mut absent: Option<PingFrame> = None;
    let data = [0u8; 100];
    let mut large = (qbase::frame::CryptoFrame::new(0u32.into(), 100u32.into()), data.as_slice());
    let mut ping = PingFrame;
    assert!(matches!(
        packet.assemble(&mut Context::from_waker(Waker::noop()), &mut Cursor::new(&mut bytes[..]), 64, PacketContent::EffectivePayload, &mut frames, &mut [&mut absent, &mut large, &mut ping]),
        Poll::Ready((n, _)) if n > 0
    ));
    assert_eq!(packet.meta.content, qbase::packet::PacketContent::JustPing);
    assert!(frames.is_empty());
}

#[test]
fn repeated_assembly_does_not_append_after_close() {
    let header = qbase::packet::OneRttHeader::new(Default::default(), Default::default());
    let keys = keys(false);
    let mut bytes = BytesMut::zeroed(128);
    let mut frames = Vec::new();
    let mut packet = Packet::new(DataHeader::Short(header), (0, qbase::packet::PacketNumber::U16(0)), &keys.sealing);
    let mut close = qbase::frame::ConnectionCloseFrame::new_app(0u32.into(), "closed");
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        matches!(packet.assemble(&mut cx, &mut Cursor::new(bytes.as_mut()), 128, PacketContent::EffectivePayload, &mut frames, &mut [&mut close]), Poll::Ready((n, _)) if n > 0)
    );
    let size = bytes.len();
    assert_eq!(
        packet.assemble(
            &mut cx,
            &mut Cursor::new(bytes.as_mut()),
            128,
            PacketContent::EffectivePayload,
            &mut frames,
            &mut [&mut PingFrame]
        ),
        Poll::Ready((0, 0))
    );
    assert_eq!(bytes.len(), size);
    assert_eq!(packet.meta.nframes, 1);
    assert!(frames.is_empty());
}

#[tokio::test]
async fn mixed_packets_record_each_space() {
    use qtransport::space::{ArcSpaces, InitialSpace};
    let facts = common::handshake_facts(Role::Client, false);
    let initial = Arc::new(InitialSpace::new(Default::default(), ArcKeys::new(Arc::new(keys(false))), None, facts.clone()));
    let handshake = Arc::new(HandshakeSpace::new(Default::default(), initial.keys.clone(), facts.clone()));
    initial.crypto.writer().write_all(b"hello").await.unwrap();
    handshake.crypto.writer().write_all(b"handshake").await.unwrap();
    let spaces = ArcSpaces::default();
    spaces.add(initial.clone());
    spaces.add(handshake.clone());
    let mut bytes = [0; 1200];
    let mut frames = Vec::new();
    let mut cx = Context::from_waker(Waker::noop());
    let (size, pns) = spaces.poll_dump(
        &mut cx,
        &common::send_cc(),
        0,
        Default::default(),
        &mut bytes[..],
        PacketContent::EffectivePayload,
        &mut frames,
        &mut [],
    );
    assert_eq!(size, 1200);
    let a = initial.sent_journal.lock_guard();
    let b = handshake.sent_journal.lock_guard();
    assert!(a.packet(packet_metadata(&pns, Epoch::Initial).unwrap().pn).unwrap().size < 100);
    assert_eq!(
        a.packet(packet_metadata(&pns, Epoch::Initial).unwrap().pn).unwrap().size
            + b.packet(packet_metadata(&pns, Epoch::Handshake).unwrap().pn).unwrap().size,
        1200
    );
    assert_eq!(a.frames(packet_metadata(&pns, Epoch::Initial).unwrap().pn).count(), 1);
    assert_eq!(b.frames(packet_metadata(&pns, Epoch::Handshake).unwrap().pn).count(), 1);
    for (index, packet) in PacketReader::new(BytesMut::from(&bytes[..size]), 0).enumerate() {
        let ParsedPacket::Data(packet) = packet.unwrap() else {
            panic!()
        };
        let opened = match packet.header {
            DataHeader::Long(long::DataHeader::Initial(header)) => CipherPacket::new(header, packet.bytes, packet.offset)
                .open_long(&keys(true).opening, |_| Ok(pns[index].pn))
                .unwrap()
                .unwrap()
                .body(),
            DataHeader::Long(long::DataHeader::Handshake(header)) => CipherPacket::new(header, packet.bytes, packet.offset)
                .open_long(&keys(true).opening, |_| Ok(pns[index].pn))
                .unwrap()
                .unwrap()
                .body(),
            _ => panic!(),
        };
        use qbase::packet::GetType;
        let ty = if index == 0 {
            LongHeaderBuilder::with_cid(Default::default(), Default::default()).initial(vec![]).get_type()
        } else {
            LongHeaderBuilder::with_cid(Default::default(), Default::default()).handshake().get_type()
        };
        assert_eq!(FrameReader::new(opened, ty).any(|frame| matches!(frame.unwrap().0, Frame::Padding(_))), index == 1);
    }
    assert!(frames.is_empty());
}

#[test]
fn probe_packet_uses_an_explicit_quota_and_a_bounded_window() {
    let keys = keys(false);
    let mut frames = Vec::new();
    for (pn, quota) in [1160, 0].into_iter().enumerate() {
        let header = LongHeaderBuilder::with_cid(Default::default(), Default::default()).initial(vec![]);
        let mut packet =
            Packet::new(DataHeader::Long(header.into()), (pn as u64, qbase::packet::PacketNumber::U8(pn as u8)), &keys.sealing);
        let mut bytes = vec![0; 1160];
        let result = packet.assemble(
            &mut Context::from_waker(Waker::noop()),
            &mut Cursor::new(bytes.as_mut_slice()),
            quota,
            PacketContent::EffectivePayload,
            &mut frames,
            &mut [&mut PingFrame],
        );
        if pn == 0 {
            assert!(matches!(result, Poll::Ready((n, _)) if n > 0));
            packet.padding(&mut bytes, 1160 - packet.len());
            packet.seal(&mut bytes);
            assert_eq!(packet.len(), 1160);
        } else {
            assert_eq!(result, Poll::Ready((0, 0)));
            assert_eq!(packet.len(), 0);
        }
        assert!(frames.is_empty());
    }
}

#[test]
fn vec_sealing_and_io_slice_encoding_preserve_the_encoded_pn() {
    use std::io::IoSliceMut;

    use qbase::packet::{GetType, PacketNumber};
    let keys = keys(false);
    let header = || LongHeaderBuilder::with_cid(Default::default(), Default::default()).initial(vec![]);
    let mut frames = Vec::new();
    let mut packet = Packet::new(DataHeader::Long(header().into()), (7, PacketNumber::U16(7)), &keys.sealing);
    let mut bytes = vec![0; 1200];
    assert!(
        matches!(packet.assemble(&mut Context::from_waker(Waker::noop()), &mut Cursor::new(bytes.as_mut_slice()), 1200, PacketContent::EffectivePayload, &mut frames, &mut [&mut PingFrame]), Poll::Ready((n, _)) if n > 0)
    );
    bytes.resize(1200, 0);
    packet.padding(&mut bytes, 1200 - packet.len());
    packet.seal(&mut bytes);
    assert_eq!(packet.meta.pn, 7);
    assert_eq!(packet.meta.pktlen, 1200);
    let ParsedPacket::Data(parsed) = PacketReader::new(BytesMut::from(bytes.as_slice()), 0).next().unwrap().unwrap() else {
        panic!()
    };
    let DataHeader::Long(long::DataHeader::Initial(parsed_header)) = parsed.header else {
        panic!()
    };
    let ty = parsed_header.get_type();
    let opened = CipherPacket::new(parsed_header, parsed.bytes, parsed.offset)
        .open_long(&common::initial_keys(true).opening, |_| Ok(7))
        .unwrap()
        .unwrap();
    assert!(FrameReader::new(opened.body(), ty).any(|frame| matches!(frame.unwrap().0, Frame::Ping(_))));

    let mut storage = [0; 1200];
    let mut io = IoSliceMut::new(&mut storage);
    let header = header();
    let pn_offset = qbase::packet::HeaderSize::size(&header) + 2;
    let mut packet = Packet::new(DataHeader::Long(header.into()), (7, PacketNumber::U16(7)), &keys.sealing);
    assert!(
        matches!(packet.assemble(&mut Context::from_waker(Waker::noop()), &mut Cursor::new(&mut io[..]), 1200, PacketContent::EffectivePayload, &mut frames, &mut [&mut PingFrame]), Poll::Ready((n, _)) if n > 0)
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
    for (sizes, expected) in [
        ([700, 0, 0], [1200, 0, 0]),
        ([700, 200, 0], [700, 500, 0]),
        ([700, 0, 100], [700, 0, 500]),
        ([700, 200, 100], [700, 200, 300]),
        ([0, 400, 0], [0, 400, 0]),
        ([0, 0, 100], [0, 0, 100]),
        ([0, 0, 0], [0, 0, 0]),
    ] {
        let [sender, receiver] = common::spaces::pair();
        let spaces = qtransport::space::ArcSpaces::default();
        spaces.add(sender.paths.spaces.get(Epoch::Initial).unwrap());
        spaces.add(sender.spaces.handshake.clone());
        spaces.add(sender.spaces.data.clone());
        let mut sources = Epoch::EPOCHS.map(|epoch| {
            let size = sizes[epoch];
            if size == 0 {
                return None;
            }
            let header = match epoch {
                Epoch::Initial => {
                    LongHeaderBuilder::with_cid(sender.peer_cid(), sender.spaces.initial.initial_scid).initial(vec![]).size() + 2
                }
                Epoch::Handshake => {
                    LongHeaderBuilder::with_cid(sender.peer_cid(), sender.spaces.handshake.initial_scid).handshake().size() + 2
                }
                Epoch::Data => qbase::packet::OneRttHeader::new(Default::default(), sender.peer_cid()).size(),
            };
            let len = (0..size)
                .find(|&len| header + 2 + 16 + CryptoFrame::new(0u32.into(), (len as u32).into()).encoding_size() + len == size)
                .unwrap();
            Some((CryptoFrame::new(0u32.into(), (len as u32).into()), bytes::Bytes::from(vec![epoch as u8 + 1; len])))
        });
        let mut sources = Epoch::EPOCHS.map(|epoch| (epoch, sources[epoch].take()));
        let [a, b, c] = &mut sources;
        let mut external: [&mut dyn for<'b> Package<&'b mut [u8]>; 3] = [a, b, c];
        let mut bytes = [0xa5; 1216];
        let mut frames = Vec::new();
        let (size, pns) = spaces.poll_dump(
            &mut Context::from_waker(Waker::noop()),
            &common::send_cc(),
            0,
            sender.peer_cid(),
            &mut bytes[..1200],
            PacketContent::EffectivePayload,
            &mut frames,
            &mut external,
        );
        assert_eq!(size, expected.iter().sum::<usize>());
        assert_eq!(
            pns.iter().map(|meta| meta.epoch()).collect::<Vec<_>>(),
            Epoch::EPOCHS.into_iter().filter(|&epoch| expected[epoch] > 0).collect::<Vec<_>>()
        );
        assert_eq!(&bytes[1200..], &[0xa5; 16]);
        assert!(frames.is_empty());
        let mut recorded = 0;
        for epoch in Epoch::EPOCHS {
            assert_eq!(packet_metadata(&pns, epoch).is_some(), expected[epoch] != 0);
            if let Some(meta) = packet_metadata(&pns, epoch) {
                let space = spaces.get(epoch).unwrap();
                let journal = space.sent_journal().lock_guard();
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
            pns.iter().map(|meta| meta.nframes).sum::<usize>(),
            recorded + expected.iter().zip(sizes).filter(|(size, original)| **size > *original).count()
        );
        let packets = PacketReader::new(BytesMut::from(&bytes[..size]), sender.peer_cid().len());
        for packet in packets {
            let ParsedPacket::Data(packet) = packet.unwrap() else {
                panic!()
            };
            let (epoch, plaintext) = match packet.header {
                DataHeader::Long(long::DataHeader::Initial(header)) => {
                    let opened = CipherPacket::new(header, packet.bytes, packet.offset)
                        .open_long(&keys(true).opening, |_| Ok(packet_metadata(&pns, Epoch::Initial).unwrap().pn))
                        .unwrap()
                        .unwrap();
                    (Epoch::Initial, FrameReader::new(opened.body(), opened.get_type()).collect::<Result<Vec<_>, _>>().unwrap())
                }
                DataHeader::Long(long::DataHeader::Handshake(header)) => {
                    let opened = CipherPacket::new(header, packet.bytes, packet.offset)
                        .open_long(&keys(true).opening, |_| Ok(packet_metadata(&pns, Epoch::Handshake).unwrap().pn))
                        .unwrap()
                        .unwrap();
                    (Epoch::Handshake, FrameReader::new(opened.body(), opened.get_type()).collect::<Result<Vec<_>, _>>().unwrap())
                }
                DataHeader::Short(header) => {
                    let opened = receiver
                        .spaces
                        .data
                        .keys
                        .open_packet(
                            CipherPacket::new(header, packet.bytes, packet.offset),
                            |_| Ok(packet_metadata(&pns, Epoch::Data).unwrap().pn),
                            Duration::from_secs(1),
                        )
                        .unwrap()
                        .unwrap();
                    (Epoch::Data, FrameReader::new(opened.body(), opened.get_type()).collect::<Result<Vec<_>, _>>().unwrap())
                }
                _ => panic!(),
            };
            let padding = plaintext.iter().filter(|(frame, _)| matches!(frame, Frame::Padding(_))).count();
            assert_eq!(padding, expected[epoch] - sizes[epoch]);
            assert!(
                plaintext.iter().any(|(frame, _)| matches!(frame, Frame::Crypto(_, bytes) if bytes.iter().all(|&b| b == epoch as u8 + 1)))
            );
        }
    }
}

#[tokio::test]
async fn recursive_packing_validation_checks_capacity_before_consuming_the_frame() {
    use qbase::{
        frame::{CryptoFrame, PathChallengeFrame},
        packet::Package,
    };
    for capacity in [1199, 1200] {
        let [sender, _] = common::spaces::pair();
        let spaces = qtransport::space::ArcSpaces::default();
        spaces.add(sender.paths.spaces.get(Epoch::Initial).unwrap());
        spaces.add(sender.spaces.handshake.clone());
        spaces.add(sender.spaces.data.clone());
        spaces.retire(Epoch::Initial);
        let mut crypto = Some((CryptoFrame::new(0u32.into(), 300u32.into()), bytes::Bytes::from_static(&[1; 300])));
        let mut challenge = Some(PathChallengeFrame::random());
        let mut crypto = (Epoch::Handshake, &mut crypto);
        let mut external: [&mut dyn for<'b> Package<&'b mut [u8]>; 2] = [&mut crypto, &mut challenge];
        let mut bytes = [0xa5; 1216];
        let mut frames = Vec::new();
        let (size, pns) = spaces.poll_dump(
            &mut Context::from_waker(Waker::noop()),
            &common::send_cc(),
            0,
            sender.peer_cid(),
            &mut bytes[..capacity],
            PacketContent::EffectivePayload,
            &mut frames,
            &mut external,
        );
        assert!(packet_metadata(&pns, Epoch::Initial).is_none());
        assert!(packet_metadata(&pns, Epoch::Handshake).is_some());
        assert_eq!(packet_metadata(&pns, Epoch::Data).is_some(), capacity == 1200);
        assert_eq!(challenge.is_none(), capacity == 1200);
        assert_eq!(size == 1200, capacity == 1200);
        assert_eq!(&bytes[capacity..], &vec![0xa5; 1216 - capacity]);
        assert!(frames.is_empty());
        spaces.retire(Epoch::Handshake);
        assert_eq!(common::space_epochs(&spaces), [Epoch::Data]);
        let mut ping = Some(PingFrame);
        let (size, _) = spaces.poll_dump(
            &mut Context::from_waker(Waker::noop()),
            &common::send_cc(),
            0,
            sender.peer_cid(),
            &mut bytes[..1200],
            PacketContent::EffectivePayload,
            &mut frames,
            &mut [&mut (Epoch::Data, &mut ping)],
        );
        assert!(size > 0 && size < 1200);
    }
}

#[test]
fn recursive_packing_retains_initial_token_and_skips_closed_sources() {
    use qbase::packet::{GetDcid, GetScid, GetType};
    use qtransport::space::{ArcSpaces, InitialSpace};
    let scid = ConnectionId::from_slice(b"local000");
    let facts = common::handshake_facts(Role::Client, false);
    let initial = Arc::new(InitialSpace::new(scid, ArcKeys::new(Arc::new(keys(false))), Some(b"token".to_vec()), facts.clone()));
    let handshake = Arc::new(HandshakeSpace::new(scid, initial.keys.clone(), facts.clone()));
    let spaces = ArcSpaces::default();
    spaces.add(initial.clone());
    spaces.add(handshake.clone());
    let mut bytes = [0; 1200];
    let mut frames = Vec::new();
    let mut cx = Context::from_waker(Waker::noop());
    for cid in [b"remote00", b"remote01"] {
        let dcid = ConnectionId::from_slice(cid);
        let mut ping = Some(PingFrame);
        let (_, pns) = spaces.poll_dump(
            &mut cx,
            &common::send_cc(),
            0,
            dcid,
            &mut bytes[..],
            PacketContent::EffectivePayload,
            &mut frames,
            &mut [&mut (Epoch::Initial, &mut ping)],
        );
        let ParsedPacket::Data(packet) = PacketReader::new(BytesMut::from(bytes.as_slice()), 8).next().unwrap().unwrap() else {
            panic!()
        };
        let DataHeader::Long(long::DataHeader::Initial(header)) = packet.header else {
            panic!()
        };
        assert_eq!(header.token(), b"token");
        assert_eq!(*header.scid(), scid);
        assert_eq!(*header.dcid(), dcid);
        let opened = CipherPacket::new(header, packet.bytes, packet.offset)
            .open_long(&keys(true).opening, |_| Ok(packet_metadata(&pns, Epoch::Initial).unwrap().pn))
            .unwrap()
            .unwrap();
        assert!(FrameReader::new(opened.body(), opened.get_type()).any(|f| matches!(f.unwrap().0, Frame::Ping(_))));
    }
    let closed = qrecovery::crypto::CryptoStream::with_facts(facts);
    closed.sender.retire();
    initial.crypto.writer().write_all(b"retry").now_or_never().unwrap().unwrap();
    handshake.crypto.writer().write_all(b"later").now_or_never().unwrap().unwrap();
    let mut crypto = handshake.crypto.outgoing();
    let mut ping = Some(PingFrame);
    let (size, pns) = spaces.poll_dump(
        &mut cx,
        &common::send_cc(),
        0,
        Default::default(),
        &mut bytes[..],
        PacketContent::EffectivePayload,
        &mut frames,
        &mut [&mut (Epoch::Initial, &mut ping), &mut (Epoch::Handshake, &mut crypto), &mut (Epoch::Handshake, closed.outgoing())],
    );
    assert_eq!(size, 1200);
    assert!(packet_metadata(&pns, Epoch::Handshake).is_some());
    assert!(frames.is_empty());
    assert!(
        initial
            .sent_journal
            .lock_guard()
            .frames(packet_metadata(&pns, Epoch::Initial).unwrap().pn)
            .any(|frame| matches!(frame, GuaranteedFrame::Crypto(frame) if frame.offset() == 0 && frame.len() == 5))
    );
    assert!(
        handshake
            .sent_journal
            .lock_guard()
            .frames(packet_metadata(&pns, Epoch::Handshake).unwrap().pn)
            .any(|frame| matches!(frame, GuaranteedFrame::Crypto(frame) if frame.offset() == 0 && frame.len() == 5))
    );
    let (size, pns) = spaces.poll_dump(
        &mut cx,
        &common::send_cc(),
        0,
        Default::default(),
        &mut bytes[..],
        PacketContent::EffectivePayload,
        &mut frames,
        &mut [],
    );
    assert_eq!(size, 0);
    assert!(pns.is_empty());
}

#[test]
fn ack_only_and_in_flight_packets_keep_metadata_and_empty_attempts_stay_empty() {
    use qbase::frame::AckFrame;
    use qtransport::space::ArcSpaces;

    let spaces = ArcSpaces::default();
    spaces.retire(Epoch::Initial);
    spaces.add(Arc::new(HandshakeSpace::new(
        Default::default(),
        ArcKeys::new(Arc::new(keys(false))),
        crate::common::handshake_facts(Role::Client, false),
    )));
    for flight in [false, true] {
        let mut ack = Some(AckFrame::new(0u32.into(), 0u32.into(), 0u32.into(), vec![], None));
        let mut ping = flight.then_some(PingFrame);
        let mut sources: [&mut dyn for<'b> qbase::packet::Package<&'b mut [u8]>; 2] = [&mut ack, &mut ping];
        let mut bytes = [0; 1200];
        let mut frames = Vec::new();
        let mut cx = Context::from_waker(Waker::noop());
        let (size, pns) = spaces.poll_dump(
            &mut cx,
            &common::send_cc(),
            0,
            Default::default(),
            &mut bytes[..],
            PacketContent::EffectivePayload,
            &mut frames,
            &mut sources,
        );
        assert!(size > 0);
        assert_eq!(pns.len(), 1);
        assert_eq!(pns[0].in_flight, flight);
        assert_eq!(pns[0].epoch(), Epoch::Handshake);
        let (size, pns) = spaces.poll_dump(
            &mut cx,
            &common::send_cc(),
            0,
            Default::default(),
            &mut bytes[..],
            PacketContent::EffectivePayload,
            &mut frames,
            &mut sources,
        );
        assert_eq!(size, 0);
        assert!(pns.is_empty());
    }
}

#[tokio::test]
async fn datagram_windows_bound_payload_and_cc_keeps_ack_progress() {
    use qbase::frame::AckFrame;
    use qtransport::space::ArcSpaces;

    let [sender, _] = common::spaces::pair();
    let spaces = ArcSpaces::default();
    spaces.retire(Epoch::Handshake);
    spaces.add(sender.spaces.data.clone());
    let (_, mut writer) = sender.spaces.data.streams.open_uni().await.unwrap().unwrap();
    writer.write_all(&[9; 1000]).await.unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let mut bytes = [0xa5; 1200];
    let mut frames = Vec::new();
    let cc = common::send_cc();
    let (size, packets) =
        spaces.poll_dump(&mut cx, &cc, 0, sender.peer_cid(), &mut bytes[..278], PacketContent::EffectivePayload, &mut frames, &mut []);
    assert_eq!(size, 278);
    assert_eq!(&bytes[278..], &[0xa5; 922]);
    assert_eq!(packets[0].pktlen, size);

    let fresh = sender.spaces.data.streams.fresh_bytes();
    let minimum = qbase::packet::HeaderSize::size(&qbase::packet::OneRttHeader::new(Default::default(), sender.peer_cid())) + 20;
    for length in 0..minimum {
        let (size, packets) = spaces.poll_dump(
            &mut cx,
            &cc,
            0,
            sender.peer_cid(),
            &mut bytes[..length],
            PacketContent::EffectivePayload,
            &mut frames,
            &mut [],
        );
        assert_eq!(size, 0);
        assert!(packets.is_empty());
        assert_eq!(sender.spaces.data.streams.fresh_bytes(), fresh);
    }

    cc.on_pkt_sent(Epoch::Data, 0, true, cc.send_quota(), true, None);
    assert_eq!(cc.send_quota(), 0);
    let fresh = sender.spaces.data.streams.fresh_bytes();
    let mut ack = Some(AckFrame::new(0u32.into(), 0u32.into(), 0u32.into(), vec![], None));
    let (size, packets) =
        spaces.poll_dump(&mut cx, &cc, 0, sender.peer_cid(), &mut bytes[..], PacketContent::EffectivePayload, &mut frames, &mut [&mut ack]);
    assert!(size > 0);
    assert_eq!(packets[0].ack, Some(0));
    assert!(!packets[0].in_flight);
    assert_eq!(sender.spaces.data.streams.fresh_bytes(), fresh);
    let (size, packets) =
        spaces.poll_dump(&mut cx, &cc, 0, sender.peer_cid(), &mut bytes[..], PacketContent::EffectivePayload, &mut frames, &mut []);
    assert_eq!(size, 0);
    assert!(packets.is_empty());
}

#[tokio::test]
async fn data_space_uses_cursor_to_pad_validation_without_touching_the_prefix() {
    use qbase::frame::PathChallengeFrame;
    use qtransport::space::{Encapsulate, Recover};

    for probe in [false, true] {
        let [sender, _] = common::spaces::pair();
        let data = &sender.spaces.data;
        let mut bytes = [0xa5; 1216];
        let mut datagram = Cursor::new(&mut bytes[..1200]);
        datagram.set_position(300);
        let mut frames = Vec::new();
        let mut challenge = probe.then_some(PathChallengeFrame::random());
        let mut ping = Some(PingFrame);
        let Poll::Ready((Some(packet), size)) = data.poll_dump(
            &mut Context::from_waker(Waker::noop()),
            &common::send_cc(),
            sender.peer_cid(),
            &mut datagram,
            PacketContent::EffectivePayload,
            &mut frames,
            &mut [&mut challenge, &mut ping],
        ) else {
            panic!("queued frames must produce a packet");
        };
        assert_eq!(datagram.position() as usize, 300 + size);
        assert_eq!(packet.len(), size);
        if probe {
            assert_eq!(size, 900);
        } else {
            assert!(size < 900);
        }
        assert!(challenge.is_none());
        assert_eq!(&bytes[..300], &[0xa5; 300]);
        assert_eq!(&bytes[1200..], &[0xa5; 16]);
        Recover::cancel(data.as_ref(), packet.pn.0, &mut frames.drain(..));
    }
}
