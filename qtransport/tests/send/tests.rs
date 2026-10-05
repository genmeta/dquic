use std::time::Duration;

use bytes::Bytes;
use qbase::{
    cid::ConnectionId,
    frame::{
        CryptoFrame, DatagramFrame, Frame, MaxDataFrame, PathChallengeFrame, PathResponseFrame,
        PingFrame, ReliableFrame,
    },
    packet::{LongHeaderBuilder, Packet as ParsedPacket, PacketReader},
};

use super::{fixture::TestSender as Sender, *};
use crate::{keys::Open, transport::Transport};

fn sender(transport: &Arc<Transport>, path: &Path) -> Sender {
    Sender::new(
        path.pathway,
        path.cc.clone(),
        path.anti_amplifier.clone(),
        Some(transport.data.clone()),
    )
}
fn header() -> OneRttHeader {
    OneRttHeader::new(Default::default(), ConnectionId::from_slice(b"original"))
}
fn long() -> LongHeaderBuilder {
    LongHeaderBuilder::with_cid(
        ConnectionId::from_slice(b"original"),
        ConnectionId::from_slice(b"clientid"),
    )
}
fn decode(bytes: &[u8]) -> qbase::packet::DataPacket {
    let ParsedPacket::Data(packet) = PacketReader::new(BytesMut::from(bytes), 8)
        .next()
        .unwrap()
        .unwrap()
    else {
        panic!()
    };
    packet
}
fn ack(pn: u64) -> AckFrame {
    AckFrame::new(
        VarInt::from_u64(pn).unwrap(),
        0u32.into(),
        0u32.into(),
        vec![],
        None,
    )
}
fn cx() -> Context<'static> {
    Context::from_waker(futures::task::noop_waker_ref())
}

#[tokio::test]
async fn all_four_levels_seal_and_open_and_data_shares_packet_numbers() {
    let [(_client, transport, path), (_server, peer, _)] = crate::transport::pair(1);
    // Encoding-only sources are not owned by the transport's recovery components.
    let mut sender = Sender::new(
        path.pathway,
        path.cc.clone(),
        path.anti_amplifier.clone(),
        None,
    );
    let fixed = crate::transport::fixed_keys();
    let keys = transport.data.keys.get().unwrap();
    let limit = Constraints {
        flow_ctrl: std::cell::Cell::new(usize::MAX),
        capacity: 1200,
        congestion: 1200,
        anti_amplification: 1200,
    };
    let initial = ArcSentJournal::default();
    let handshake = ArcSentJournal::default();
    let data = ArcSentJournal::default();
    let bytes = [Bytes::from_static(b"client hello")];
    let mut crypto = (
        CryptoFrame::new(0u32.into(), 12u32.into()),
        bytes.as_slice(),
    );
    let packet = sender
        .assemble_long_packet(
            &fixed.sealing,
            long().initial(vec![1, 2]),
            &initial,
            &limit,
            [&mut crypto],
        )
        .unwrap()
        .unwrap();
    assert_eq!(packet.bytes().len(), 1200);
    assert_eq!(packet.pn, 0);
    let (_, mut frames) = fixed
        .sealing
        .open(decode(packet.bytes()), |_| Ok(0), Duration::ZERO)
        .unwrap()
        .unwrap();
    assert!(
        matches!(frames.next().unwrap().unwrap().0, Frame::Crypto(_, body) if body.as_ref() == b"client hello")
    );
    let packet = sender
        .assemble_long_packet(
            &fixed.sealing,
            long().handshake(),
            &handshake,
            &limit,
            [&mut PingFrame],
        )
        .unwrap()
        .unwrap();
    assert_eq!(packet.pn, 0);
    assert!(
        fixed
            .sealing
            .open(decode(packet.bytes()), |_| Ok(0), Duration::ZERO)
            .unwrap()
            .is_some()
    );
    let mut datagram = (
        DatagramFrame::new(true, 5u32.into()),
        Bytes::from_static(b"hello"),
    );
    let zero = sender
        .assemble_long_packet(
            &fixed.sealing,
            long().zero_rtt(),
            &data,
            &limit,
            [&mut datagram, &mut PingFrame],
        )
        .unwrap()
        .unwrap();
    assert_eq!(zero.pn, 0);
    assert_eq!(zero.generation, None);
    let (_, mut frames) = fixed
        .sealing
        .open(decode(zero.bytes()), |_| Ok(0), Duration::ZERO)
        .unwrap()
        .unwrap();
    assert!(
        matches!(frames.next().unwrap().unwrap().0, Frame::Datagram(_, body) if body.as_ref() == b"hello")
    );
    assert!(matches!(frames.next().unwrap().unwrap().0, Frame::Ping(_)));
    let one = sender
        .assemble_1rtt_packet(&keys, header(), &data, &limit, [&mut PingFrame])
        .unwrap()
        .unwrap();
    assert_eq!(one.pn, 1);
    assert_eq!(one.generation, Some(0));
    assert!(
        peer.data
            .keys
            .get()
            .unwrap()
            .open(decode(one.bytes()), |_| Ok(1), Duration::ZERO)
            .unwrap()
            .is_some()
    );
    // 0-RTT ACKs must not authorize a 1-RTT generation.
    let mut zero = zero;
    data.on_sent(
        zero.pn,
        zero.in_flight,
        Duration::from_secs(1),
        Duration::from_secs(3),
    );
    zero.journal = None;
    assert!(data.on_acked(&ack(0), |_| {}).unwrap().is_none());
}

#[tokio::test]
async fn burst_submits_many_packets_and_preserves_partial_suffix_and_recovery() {
    let [(_client, transport, path), _peer] = crate::transport::pair(1);
    let keys = transport.data.keys.get().unwrap();
    let journal = ArcSentJournal::default();
    let mut sender = sender(&transport, &path);
    let mut remaining = 16;
    assert_eq!(
        sender
            .burst(|sender, limit| {
                if remaining == 0 {
                    return Ok(None);
                }
                let frame = ReliableFrame::MaxData(MaxDataFrame::new((remaining as u32).into()));
                let packet = sender.assemble_1rtt_packet(
                    &keys,
                    header(),
                    &journal,
                    limit,
                    [&mut frame.clone()],
                )?;
                if packet.is_some() {
                    remaining -= 1;
                }
                Ok(packet)
            })
            .unwrap(),
        8
    );
    assert_eq!(remaining, 8); // ready sources cannot grow this batch beyond eight datagrams
    let original = sender
        .pending()
        .map(|packet| packet.bytes().to_vec())
        .collect::<Vec<_>>();
    let mut committed = Vec::new();
    assert!(
        sender
            .poll_send_with(
                &mut cx(),
                &mut Vec::with_capacity(QuicProtocol::MAX_DATAGRAMS),
                |_, _, packets| {
                    assert_eq!(packets.len(), 8);
                    Poll::Pending
                },
                |_| true,
                |_| panic!()
            )
            .is_pending()
    );
    assert!(matches!(
        sender.poll_send_with(
            &mut cx(),
            &mut Vec::with_capacity(QuicProtocol::MAX_DATAGRAMS),
            |_, _, packets| {
                assert_eq!(packets.len(), 8);
                Poll::Ready(Ok(3))
            },
            |_| true,
            |packet| committed.push(packet.pn)
        ),
        Poll::Ready(Ok(3))
    ));
    assert_eq!(committed, [0, 1, 2]);
    journal.on_acked(&ack(2), |_| {}).unwrap();
    journal.on_acked(&ack(3), |_| {}).unwrap();
    assert_eq!(
        sender
            .burst(|_, _| panic!("pending suffix must be sent first"))
            .unwrap(),
        5
    );
    assert!(matches!(
        sender.poll_send_with(
            &mut cx(),
            &mut Vec::with_capacity(QuicProtocol::MAX_DATAGRAMS),
            |_, _, packets| {
                assert_eq!(packets.len(), 5);
                for (actual, expected) in packets.iter().zip(&original[3..]) {
                    assert_eq!(&actual[..], expected);
                }
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            },
            |_| true,
            |_| panic!()
        ),
        Poll::Ready(Err(_))
    ));
    assert_eq!(
        crate::transport::take_frames(&mut transport.data.reliable_frames.clone()).len(),
        4
    );
    // The successful prefix and early-ACKed packet are not put back into the sources.
    journal.on_acked(&ack(0), |_| {}).unwrap();
    assert!(sender.pending().next().is_none());
}

#[tokio::test]
async fn burst_debits_cumulative_credit_and_congestion_before_submission() {
    let [(_client, transport, path), _peer] = crate::transport::pair(1);
    let keys = transport.data.keys.get().unwrap();
    let status = qcongestion::PathStatus::new(
        Arc::new(qcongestion::HandshakeStatus::new(true)),
        Arc::new(std::sync::atomic::AtomicU16::new(1200)),
    );
    let credit = Arc::new(AntiAmplifier::new(status));
    credit.on_received(800);
    let mut sender = sender(&transport, &path);
    sender.anti_amplifier = credit.clone();
    let quota = sender.congestion.send_quota();
    let bytes = [Bytes::from(vec![7; 800])];
    let mut offset = 0;
    let count = sender
        .burst(|sender, limit| {
            let mut crypto = (
                CryptoFrame::new(VarInt::from_u64(offset).unwrap(), 800u32.into()),
                bytes.as_slice(),
            );
            let packet = sender.assemble_1rtt_packet(
                &keys,
                header(),
                &transport.data.sent_journal,
                limit,
                [&mut crypto],
            )?;
            if packet.is_some() {
                offset += 800;
            }
            Ok(packet)
        })
        .unwrap();
    assert!(count > 1);
    let size: usize = sender.pending().map(|packet| packet.bytes().len()).sum();
    assert!(size <= 2400 && size <= quota);
    assert_eq!(credit.balance(), 2400); // assembly does not debit the real credit
    assert!(
        matches!(sender.poll_send_with(&mut cx(), &mut Vec::with_capacity(QuicProtocol::MAX_DATAGRAMS), |_, _, packets| Poll::Ready(Ok(packets.len())), |_| true, |_| {}), Poll::Ready(Ok(n)) if n == count)
    );
    assert_eq!(credit.balance(), 2400 - size);
}

#[tokio::test]
async fn burst_records_ack_and_path_intents_once_and_drop_returns_reliable_data() {
    let [(_client, transport, path), _peer] = crate::transport::pair(1);
    let keys = transport.data.keys.get().unwrap();
    let journal = ArcSentJournal::default();
    let mut sender = sender(&transport, &path);
    let challenge = PathChallengeFrame::random();
    let mut ack_source = Some(ack(99));
    let mut challenge_source = Some(challenge);
    let mut response_source = Some(PathResponseFrame::from(challenge));
    let mut count = 0;
    assert_eq!(
        sender
            .burst(|sender, limit| {
                if count == 3 {
                    return Ok(None);
                }
                let frame = ReliableFrame::MaxData(MaxDataFrame::new(100u32.into()));
                let packet = sender.assemble_1rtt_packet(
                    &keys,
                    header(),
                    &journal,
                    limit,
                    [
                        &mut ack_source,
                        &mut challenge_source,
                        &mut response_source,
                        &mut frame.clone(),
                    ],
                )?;
                if packet.is_some() {
                    count += 1;
                }
                Ok(packet)
            })
            .unwrap(),
        3
    );
    assert_eq!(
        sender
            .pending()
            .filter(|p| p.largest_acked.is_some())
            .count(),
        1
    );
    assert_eq!(
        sender.pending().filter(|p| p.challenge.is_some()).count(),
        1
    );
    assert_eq!(sender.pending().filter(|p| p.response.is_some()).count(), 1);
    drop(sender);
    assert_eq!(
        crate::transport::take_frames(&mut transport.data.reliable_frames.clone()).len(),
        3
    );
    for pn in 0..3 {
        assert!(journal.on_acked(&ack(pn), |_| {}).is_err());
    }
}

#[tokio::test]
async fn retired_space_is_removed_without_discarding_other_spaces_in_the_batch() {
    let [(_client, transport, path), _peer] = crate::transport::pair(1);
    let mut sender = sender(&transport, &path);
    let keys = crate::transport::fixed_keys();
    let retired = crate::keys::ArcKeys::new(42u64);
    retired.retire();
    let initial = ArcSentJournal::default();
    let handshake = ArcSentJournal::default();
    let mut index = 0;
    assert_eq!(
        sender
            .burst(|sender, limit| {
                assert_eq!(retired.get(), Err(crate::keys::KeyRetired));
                index += 1;
                match index {
                    1 => sender.assemble_long_packet(
                        &keys.sealing,
                        long().initial(vec![]),
                        &initial,
                        limit,
                        [&mut PingFrame],
                    ),
                    2 => sender.assemble_long_packet(
                        &keys.sealing,
                        long().handshake(),
                        &handshake,
                        limit,
                        [&mut PingFrame],
                    ),
                    _ => Ok(None),
                }
            })
            .unwrap(),
        2
    );
    let mut sent = Vec::new();
    assert!(matches!(
        sender.poll_send_with(
            &mut cx(),
            &mut Vec::with_capacity(QuicProtocol::MAX_DATAGRAMS),
            |_, _, packets| {
                assert_eq!(packets.len(), 1);
                Poll::Ready(Ok(1))
            },
            |kind| write::epoch(kind) != Epoch::Initial,
            |packet| sent.push(packet.epoch())
        ),
        Poll::Ready(Ok(1))
    ));
    assert_eq!(sent, [Epoch::Handshake]);
    assert!(initial.on_acked(&ack(0), |_| {}).is_err());
    handshake.on_acked(&ack(0), |_| {}).unwrap();
}

#[tokio::test]
async fn sent_callback_can_acknowledge_and_retire_path() {
    let [(_client, transport, path), _peer] = crate::transport::pair(1);
    let mut sender = sender(&transport, &path);
    let keys = transport.data.keys.get().unwrap();
    let mut ping = Some(PingFrame);
    assert_eq!(
        sender
            .burst(|sender, constraints| {
                sender.assemble_1rtt_packet(
                    &keys,
                    header(),
                    &transport.data.sent_journal,
                    constraints,
                    [&mut ping],
                )
            })
            .unwrap(),
        1
    );
    assert!(matches!(
        sender.poll_send_with(
            &mut cx(),
            &mut Vec::with_capacity(QuicProtocol::MAX_DATAGRAMS),
            |_, _, packets| Poll::Ready(Ok(packets.len())),
            |_| true,
            |packet| {
                // These operations acquire journal/CC/state locks themselves.
                transport
                    .data
                    .sent_journal
                    .on_acked(&ack(packet.pn), |_| {})
                    .unwrap();
                path.validate();
                path.retire();
            },
        ),
        Poll::Ready(Ok(1))
    ));
    assert_eq!(path.state(), crate::path::PathState::Retired);
}

#[tokio::test]
async fn repeated_mediated_bursts_reuse_iovecs_and_wrap_each_datagram_once() {
    use qbase::{
        datagram::{Datagram, be_datagram},
        net::{addr::EndpointAddr, route::Pathway},
    };
    let [(_client, transport, path), _peer] = crate::transport::pair(1);
    let pathway = Pathway::new(
        EndpointAddr::direct("127.0.0.1:30001".parse().unwrap()),
        EndpointAddr::mediate(
            "127.0.0.1:30002".parse().unwrap(),
            "127.0.0.1:30003".parse().unwrap(),
        ),
    );
    let mut sender = Sender::new(
        pathway,
        path.cc.clone(),
        path.anti_amplifier.clone(),
        Some(transport.data.clone()),
    );
    let keys = transport.data.keys.get().unwrap();
    let mut packets = Vec::with_capacity(QuicProtocol::MAX_DATAGRAMS);
    let allocation = packets.as_ptr();
    let frames = sender.send_frames.as_ptr();
    for value in 0..3u32 {
        let mut once = false;
        sender
            .burst(|sender, constraints| {
                if once {
                    return Ok(None);
                }
                once = true;
                let frame = ReliableFrame::MaxData(MaxDataFrame::new(value.into()));
                sender.assemble_1rtt_packet(
                    &keys,
                    header(),
                    &transport.data.sent_journal,
                    constraints,
                    [&mut frame.clone()],
                )
            })
            .unwrap();
        let packet = sender.pending().next().unwrap();
        let expected = packet.bytes().to_vec();
        let pn = packet.pn;
        assert!(matches!(
            sender.poll_send_with(
                &mut cx(),
                &mut packets,
                |_, actual_pathway, packets| {
                    assert_eq!(actual_pathway, pathway);
                    let Datagram::Forward(decoded_pathway, payload) =
                        be_datagram(BytesMut::from(&packets[0][..])).unwrap()
                    else {
                        panic!()
                    };
                    assert_eq!(decoded_pathway, pathway);
                    assert_eq!(payload.into_raw().as_ref(), expected);
                    Poll::Ready(Ok(1))
                },
                |_| true,
                |_| {}
            ),
            Poll::Ready(Ok(1))
        ));
        assert!(packets.is_empty());
        assert_eq!(packets.as_ptr(), allocation);
        assert_eq!(sender.send_frames.as_ptr(), frames);
        transport
            .data
            .sent_journal
            .on_acked(&ack(pn), |_| {})
            .unwrap();
    }
}
