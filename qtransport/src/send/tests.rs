use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use qbase::{
    cid::ConnectionId,
    frame::{
        CryptoFrame, DatagramFrame, Frame, MaxDataFrame, PathChallengeFrame, PathResponseFrame,
        PingFrame, ReliableFrame,
    },
    packet::{LongHeaderBuilder, Packet as ReceivedPacket, PacketReader},
};

use super::*;
use crate::{keys::OpenPacket, transport::Transport};

fn sender(transport: &Transport, path: &Path) -> Sender {
    transport
        .data
        .send_wakers
        .replace(path.pathway, &path.send_waker);
    Sender::new(
        Arc::new(QuicProtocol::new()),
        path.pathway,
        path.cc.clone(),
        transport.flow.sender.clone(),
        path.anti_amplifier.clone(),
        path.send_waker.clone(),
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
    let ReceivedPacket::Data(packet) = PacketReader::new(BytesMut::from(bytes), 8)
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
    let [(_client, transport, path), (_server, peer, _)] = crate::tests::pair(1);
    let mut sender = sender(&transport, &path);
    let fixed = crate::tests::fixed_keys();
    let keys = transport.data.keys.try_get().unwrap().unwrap();
    let limit = Constraints {
        capacity: 1200,
        congestion: 1200,
        anti_amplification: 1200,
    };
    let initial = ArcSendJournal::default();
    let handshake = ArcSendJournal::default();
    let data = ArcSendJournal::default();
    let bytes = [Bytes::from_static(b"client hello")];
    let mut crypto = (
        CryptoFrame::new(0u32.into(), 12u32.into()),
        bytes.as_slice(),
    );
    let packet = sender
        .assemble_initial_packet(
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
        .assemble_handshake_packet(
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
        DatagramFrame::new(false, 5u32.into()),
        Bytes::from_static(b"hello"),
    );
    let zero = sender
        .assemble_0rtt_packet(
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
            .try_get()
            .unwrap()
            .unwrap()
            .open(decode(one.bytes()), |_| Ok(1), Duration::ZERO)
            .unwrap()
            .is_some()
    );
    // 0-RTT ACKs must not authorize a 1-RTT generation.
    let mut zero = zero;
    data.mark_sent(
        zero.pn,
        zero.in_flight,
        Duration::from_secs(1),
        Duration::from_secs(3),
    );
    zero.journal = None;
    assert!(data.acknowledge(&ack(0), |_| {}).unwrap().is_empty());
}

#[tokio::test]
async fn burst_submits_many_packets_and_preserves_partial_suffix_and_recovery() {
    let [(_client, transport, path), _peer] = crate::tests::pair(1);
    let keys = transport.data.keys.try_get().unwrap().unwrap();
    let recovered = Arc::new(AtomicUsize::new(0));
    let journal = ArcSendJournal::new({
        let recovered = recovered.clone();
        move |_| {
            recovered.fetch_add(1, Ordering::Relaxed);
        }
    });
    let mut sender = sender(&transport, &path);
    let mut remaining = 8;
    assert_eq!(
        sender
            .burst(|sender, limit| {
                if remaining == 0 {
                    return Ok(None);
                }
                let frame = ReliableFrame::MaxData(MaxDataFrame::new((remaining as u32).into()));
                let packet =
                    sender.assemble_1rtt_packet(&keys, header(), &journal, limit, [&mut &frame])?;
                if packet.is_some() {
                    remaining -= 1;
                }
                Ok(packet)
            })
            .unwrap(),
        8
    );
    let original = sender
        .pending()
        .map(|packet| packet.bytes().to_vec())
        .collect::<Vec<_>>();
    let mut committed = Vec::new();
    assert!(
        sender
            .poll_send_with(
                &mut cx(),
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
    journal.acknowledge(&ack(2), |_| {}).unwrap();
    assert!(journal.acknowledge(&ack(3), |_| {}).is_err());
    assert_eq!(
        sender
            .burst(|_, _| panic!("pending suffix must be sent first"))
            .unwrap(),
        5
    );
    assert!(matches!(
        sender.poll_send_with(
            &mut cx(),
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
    assert_eq!(recovered.load(Ordering::Relaxed), 5);
    // The successful prefix is neither canceled nor put back into the sources.
    journal.acknowledge(&ack(0), |_| {}).unwrap();
    assert!(sender.pending().next().is_none());
}

#[tokio::test]
async fn burst_debits_cumulative_credit_and_congestion_before_submission() {
    let [(_client, transport, path), _peer] = crate::tests::pair(1);
    let keys = transport.data.keys.try_get().unwrap().unwrap();
    let status = qcongestion::PathStatus::new(
        Arc::new(qcongestion::HandshakeStatus::new(true)),
        Arc::new(std::sync::atomic::AtomicU16::new(1200)),
    );
    let credit = Arc::new(AntiAmplifier::new(status));
    credit.on_received(800);
    let mut sender = sender(&transport, &path);
    sender.anti_amplifier = credit.clone();
    let quota = sender.congestion.send_quota().unwrap();
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
                &transport.data.send_journal,
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
        matches!(sender.poll_send_with(&mut cx(), |_, _, packets| Poll::Ready(Ok(packets.len())), |_| true, |_| {}), Poll::Ready(Ok(n)) if n == count)
    );
    assert_eq!(credit.balance(), 2400 - size);
}

#[tokio::test]
async fn burst_records_ack_and_path_intents_once_and_drop_returns_reliable_data() {
    let [(_client, transport, path), _peer] = crate::tests::pair(1);
    let keys = transport.data.keys.try_get().unwrap().unwrap();
    let recovered = Arc::new(AtomicUsize::new(0));
    let journal = ArcSendJournal::new({
        let recovered = recovered.clone();
        move |_| {
            recovered.fetch_add(1, Ordering::Relaxed);
        }
    });
    let mut sender = sender(&transport, &path);
    let challenge = PathChallengeFrame::random();
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
                        &mut ack(99),
                        &mut { challenge },
                        &mut PathResponseFrame::from(challenge),
                        &mut &frame,
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
    assert_eq!(recovered.load(Ordering::Relaxed), 3);
    for pn in 0..3 {
        assert!(journal.acknowledge(&ack(pn), |_| {}).is_err());
    }
}

#[tokio::test]
async fn retired_space_is_removed_without_discarding_other_spaces_in_the_batch() {
    let [(_client, transport, path), _peer] = crate::tests::pair(1);
    let mut sender = sender(&transport, &path);
    let keys = crate::tests::fixed_keys();
    let missing = crate::keys::ArcKeys::<u64>::new_pending();
    let initial = ArcSendJournal::default();
    let handshake = ArcSendJournal::default();
    let mut index = 0;
    assert_eq!(
        sender
            .burst(|sender, limit| {
                assert_eq!(missing.try_get(), Ok(None)); // no wait, other levels still make progress
                index += 1;
                match index {
                    1 => sender.assemble_initial_packet(
                        &keys.sealing,
                        long().initial(vec![]),
                        &initial,
                        limit,
                        [&mut PingFrame],
                    ),
                    2 => sender.assemble_handshake_packet(
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
    assert!(initial.acknowledge(&ack(0), |_| {}).is_err());
    handshake.acknowledge(&ack(0), |_| {}).unwrap();
}

#[tokio::test]
async fn idle_stream_sender_yields_pending_instead_of_spinning_on_returned_credit() {
    let [(client, transport, path), _peer] = crate::tests::pair(1);
    let (_, _writer) = client.open_uni_stream().await.unwrap().unwrap();
    let mut sender = sender(&transport, &path);
    let watchdog = std::thread::spawn({
        let transport = transport.clone();
        move || {
            std::thread::sleep(Duration::from_millis(50));
            transport
                .close(QuicError::with_default_fty(ErrorKind::Internal, "test watchdog").into());
        }
    });
    let mut running = Box::pin(sender.run(
        |sender, limit| {
            let Ok(Some(keys)) = transport.data.keys.try_get() else {
                return Ok(None);
            };
            crate::tests::sender::assemble_data(sender, limit, &keys, &transport, &path, false)
        },
        || transport.data.can_send(),
        |_| transport.data.can_send(),
        |packet| path.on_packet_sent(packet),
    ));
    assert!(futures::poll!(&mut running).is_pending());
    watchdog.join().unwrap();
    running.await.unwrap();
}

#[tokio::test]
async fn sent_callback_can_acknowledge_stop_sending_and_retire_path() {
    let [(_client, transport, path), _peer] = crate::tests::pair(1);
    let mut sender = sender(&transport, &path);
    let keys = transport.data.keys.try_get().unwrap().unwrap();
    let mut ping = Some(PingFrame);
    assert_eq!(
        sender
            .burst(|sender, constraints| {
                sender.assemble_1rtt_packet(
                    &keys,
                    header(),
                    &transport.data.send_journal,
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
            |_, _, packets| Poll::Ready(Ok(packets.len())),
            |_| true,
            |packet| {
                // These operations acquire journal/CC/state locks themselves.
                transport
                    .data
                    .send_journal
                    .acknowledge(&ack(packet.pn), |_| {})
                    .unwrap();
                path.validate();
                transport.data.stop_sending();
                path.retire();
            },
        ),
        Poll::Ready(Ok(1))
    ));
    assert!(!transport.data.can_send());
    assert_eq!(path.state(), crate::path::PathState::Retired);
}
