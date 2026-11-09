use std::sync::Arc;

use bytes::BytesMut;
use futures::FutureExt;
use qbase::{
    Epoch,
    error::ErrorKind,
    net::route::Link,
    packet::{DataHeader, Packet, PacketReader},
    token::{ArcTokenRegistry, handy::NoopTokenRegistry},
};
use qtransport::{
    keys::{ArcOneRttKeys, Seal},
    packet::CipherPacket,
    space::DataSpace,
};

#[path = "../support/crypto.rs"]
mod crypto;
#[allow(dead_code)]
#[path = "../support/tls.rs"]
mod material;

fn packet(keys: &ArcOneRttKeys, pn: u64, reserved: bool, payload: &[u8]) -> BytesMut {
    let mut bytes = BytesMut::zeroed(5 + payload.len() + 16);
    bytes[0] = if reserved { 0x4b } else { 0x43 };
    bytes[1..5].copy_from_slice(&(pn as u32).to_be_bytes());
    bytes[5..5 + payload.len()].copy_from_slice(payload);
    keys.sealing_keys().unwrap().seal(pn, &mut bytes, 1, 5, 16).unwrap();
    bytes
}

fn data(receiver: &super::DataFixture, keys: ArcOneRttKeys) -> Arc<DataSpace> {
    Arc::new(DataSpace::new(
        Default::default(),
        keys,
        receiver.spaces.data.streams.clone(),
        receiver.spaces.data.reliable_frames.clone(),
        0,
        receiver.paths.progress.facts(),
    ))
}

async fn receive(data: Arc<DataSpace>, paths: Arc<crate::Paths>, buffers: Vec<BytesMut>) {
    let (tx, rx) = tokio::sync::mpsc::channel(buffers.len());
    let link = Link::new("127.0.0.1:48001".parse().unwrap(), "127.0.0.1:48002".parse().unwrap());
    for bytes in buffers {
        let Packet::Data(packet) = PacketReader::new(bytes, 0).next().unwrap().unwrap() else {
            panic!()
        };
        let DataHeader::Short(header) = packet.header else {
            panic!()
        };
        tx.try_send((CipherPacket::new(header, packet.bytes, packet.offset), link.into(), link)).unwrap();
    }
    drop(tx);
    crate::receiving::receive_1rtt_pkt_and_deliver_frames(
        (rx, 0, None),
        data,
        paths,
        ArcTokenRegistry::with_sink("localhost".into(), Arc::new(NoopTokenRegistry)),
        crate::ArcHandshakeDone::new_client(),
    )
    .await;
}

#[tokio::test]
async fn reserved_bits_are_checked_only_after_authentication_and_empty_plaintext_is_rejected() {
    for empty in [false, true] {
        let [sender, receiver] = super::punch::pair();
        let data = receiver.spaces.data.clone();
        let paths = receiver.paths.clone();
        let pn = 0x10000;
        let valid = packet(&sender.spaces.data.keys, pn, !empty, if empty { b"" } else { b"\x01" });
        let mut forged = valid.clone();
        *forged.last_mut().unwrap() ^= 1;
        receive(data.clone(), paths.clone(), vec![forged]).await;
        assert!(paths.terminator.clone().now_or_never().is_none());
        assert_eq!(data.rcvd_journal.decode_pn(qbase::packet::PacketNumber::U16(1)), Ok(1));

        receive(data.clone(), paths.clone(), vec![valid]).await;
        let error = crate::common::observe_close(&paths.terminator).notified().unwrap();
        assert_eq!(error.kind(), ErrorKind::ProtocolViolation);
        assert_eq!(data.rcvd_journal.decode_pn(qbase::packet::PacketNumber::U16(1)), Ok(pn + 1));
        assert!(!data.rcvd_journal.covers_range(pn..=pn));
        paths.retire_all();
    }
}

#[tokio::test]
async fn authenticated_frame_failure_advances_decoding_without_acknowledging() {
    let [sender, receiver] = super::punch::pair();
    let data = receiver.spaces.data.clone();
    let paths = receiver.paths.clone();
    let pn = 0x10000;
    receive(data.clone(), paths.clone(), vec![packet(&sender.spaces.data.keys, pn, false, b"\xff")]).await;
    assert!(crate::common::observe_close(&paths.terminator).notified().is_some());
    assert_eq!(data.rcvd_journal.decode_pn(qbase::packet::PacketNumber::U16(1)), Ok(pn + 1));
    assert!(!data.rcvd_journal.covers_range(pn..=pn));
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn authentication_budget_spans_levels_paths_and_generations_and_stops_queued_crypto() {
    let [_, receiver] = super::punch::pair();
    let paths = receiver.paths.clone();
    // Two different encryption levels and paths contribute before Data is available.
    for epoch in [Epoch::Initial, Epoch::Handshake] {
        let keys = crate::common::initial_keys(false);
        let header = qbase::packet::LongHeaderBuilder::with_cid(Default::default(), Default::default());
        let journal = qrecovery::journal::ArcSentJournal::default();
        let mut ping = qbase::frame::PingFrame;
        let mut bytes = if epoch == Epoch::Initial {
            crate::common::seal(header.initial(vec![]), &keys.sealing, &journal, [&mut ping])
        } else {
            crate::common::seal(header.handshake(), &keys.sealing, &journal, [&mut ping])
        }
        .unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let Packet::Data(packet) = PacketReader::new(bytes, 0).next().unwrap().unwrap() else {
            panic!()
        };
        let space = Arc::new(qtransport::space::Space::new(
            epoch,
            Default::default(),
            qtransport::keys::ArcKeys::new(Arc::new(crate::common::initial_keys(true))),
            paths.progress.facts(),
        ));
        let link = Link::new("127.0.0.1:48001".parse().unwrap(), format!("127.0.0.1:{}", 49000 + epoch as u16).parse().unwrap());
        match packet.header {
            DataHeader::Long(qbase::packet::long::DataHeader::Initial(header)) => {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                tx.try_send((CipherPacket::new(header, packet.bytes, packet.offset), link.into(), link)).unwrap();
                drop(tx);
                crate::receiving::recv_ih_pkt_and_deliver_frames((rx, None), space, paths.clone()).await;
            }
            DataHeader::Long(qbase::packet::long::DataHeader::Handshake(header)) => {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                tx.try_send((CipherPacket::new(header, packet.bytes, packet.offset), link.into(), link)).unwrap();
                drop(tx);
                crate::receiving::recv_ih_pkt_and_deliver_frames((rx, None), space, paths.clone()).await;
            }
            _ => panic!(),
        }
    }
    let ([client, server], _) = material::handshake_with(crypto::provider());
    let sending = ArcOneRttKeys::from(client);
    let data = data(&receiver, server.into());
    let mut old_forgery = packet(&sending, 0, false, b"\x01");
    *old_forgery.last_mut().unwrap() ^= 1;
    sending.allow_update();
    sending.update().unwrap();
    let valid = packet(&sending, 1, false, b"\x01");
    let mut new_forgery = packet(&sending, 2, false, b"\x01");
    *new_forgery.last_mut().unwrap() ^= 1;
    let queued = packet(&sending, 3, false, b"\x01");
    let before = crypto::opened();
    let start = tokio::time::Instant::now();
    receive(data.clone(), paths.clone(), vec![old_forgery, valid, new_forgery, queued]).await;
    assert_eq!(crypto::opened() - before, 3, "the queued valid packet must never reach AEAD");
    assert_eq!(paths.terminator.clone().now_or_never().unwrap().kind(), ErrorKind::AeadLimitReached);
    assert_eq!(tokio::time::Instant::now(), start);
    assert!(data.rcvd_journal.covers_range(1..=1));
    assert!(!data.rcvd_journal.covers_range(2..=3));
    paths.retire_all();
}
