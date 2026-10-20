use qbase::packet::PacketNumber;
use qrecovery::journal::ArcRcvdJournal;

mod support {
    pub mod crypto;
    pub mod tls;
}
use std::{sync::Arc, time::Duration};

use qbase::{error::ErrorKind, packet::KeyPhaseBit};
use qtransport::keys::*;
use support::crypto;

fn ready() -> OneRttKeys {
    let ([client, _], _) = support::tls::handshake();
    let keys = ArcOneRttKeys::from(client);
    keys.get().unwrap()
}

fn reserved_generation(keys: &OneRttKeys) -> u64 {
    keys.reserve(Ok).unwrap().0
}

struct Packet {
    bytes: bytes::BytesMut,
    generation: Option<u64>,
}

impl Packet {
    fn into_buffer(self) -> bytes::BytesMut {
        self.bytes
    }
}

fn packet(pn: u64, keys: &OneRttKeys) -> Result<Packet, PacketError> {
    let (_, key) = keys.reserve(|_| Ok(()))?;
    let tag_len = key.tag_len();
    let mut bytes = bytes::BytesMut::zeroed(6 + tag_len);
    bytes[0] = 0x43;
    bytes[1..5].copy_from_slice(&(pn as u32).to_be_bytes());
    bytes[5] = 1; // PING
    let (generation, _) = key.seal(pn, &mut bytes, 1, 5, tag_len)?;
    Ok(Packet {
        bytes,
        generation: Some(generation),
    })
}

#[test]
fn snapshots_share_material_and_retirement() {
    let material = Arc::new(vec![1, 2, 3]);
    let keys = ArcKeys::new(material.clone());
    let other = keys.clone();
    let snapshot = keys.get().unwrap();
    assert!(Arc::ptr_eq(&snapshot, &material));
    assert!(Arc::ptr_eq(&other.get().unwrap(), &material));
    keys.retire();
    assert_eq!(keys.get(), Err(KeyRetired));
    assert_eq!(other.get(), Err(KeyRetired));
    assert_eq!(*snapshot, vec![1, 2, 3]);
}

#[test]
fn one_rtt_snapshots_share_updates_and_retirement() {
    let ([client, _], _) = support::tls::handshake();
    let keys = ArcOneRttKeys::from(client);
    let material = keys.get().unwrap();
    let snapshot = keys.clone().get().unwrap();
    material.allow_update();
    snapshot.update().unwrap();
    assert_eq!(packet(0, &material).unwrap().generation, Some(1));
    keys.retire();
    assert!(matches!(keys.get(), Err(KeyRetired)));
}

#[test]
fn seal_reports_the_phase_authenticated_in_the_header() {
    let (materials, _) = support::tls::handshake();
    let [sending, receiving] = materials.map(|material| {
        let keys = ArcOneRttKeys::from(material);
        keys.get().unwrap()
    });
    sending.allow_update();
    let journal = ArcRcvdJournal::with_capacity(0, None);
    for (generation, expected_phase) in [KeyPhaseBit::Zero, KeyPhaseBit::One, KeyPhaseBit::Zero]
        .into_iter()
        .enumerate()
    {
        let generation = generation as u64;
        if generation != 0 {
            sending.on_ack(generation - 1);
            sending.update().unwrap();
        }
        let pn = 100 + generation;
        let tag_len = sending.tag_len();
        let mut buffer = bytes::BytesMut::zeroed(6 + tag_len);
        buffer[0] = 0x43; // Short header, no CID, four-byte PN.
        (!expected_phase).imply(&mut buffer[0]);
        buffer[1..5].copy_from_slice(&(pn as u32).to_be_bytes());
        buffer[5] = 0x01; // PING
        let sealed = sending.seal(pn, &mut buffer, 1, 5, tag_len).unwrap();
        assert_eq!(sealed, (generation, expected_phase));

        let mut unprotected = buffer.clone();
        let (header, sample) = unprotected.split_at_mut(5);
        let (prefix, pn_bytes) = header.split_at_mut(1);
        let header_key = &receiving.headers.opening;
        header_key
            .unprotect(&sample[..header_key.sample_len()], &mut prefix[0], pn_bytes)
            .unwrap();
        assert_eq!(KeyPhaseBit::from(prefix[0]), sealed.1);

        let qbase::packet::Packet::Data(packet) = qbase::packet::PacketReader::new(buffer, 0)
            .next()
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        let (opened_pn, mut frames) = receiving
            .open(packet, |pn| journal.decode_pn(pn), Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(opened_pn, pn);
        assert!(matches!(
            frames.next().unwrap().unwrap().0,
            qbase::frame::Frame::Ping(_)
        ));
    }
}

#[test]
fn duplicate_packet_skips_aead() {
    let ([client, server], _) = support::tls::handshake_with(crypto::provider());
    let sending = ArcOneRttKeys::from(client);
    let receiving = ArcOneRttKeys::from(server).get().unwrap();
    let bytes = packet(0, &sending.get().unwrap()).unwrap().into_buffer();
    let qbase::packet::Packet::Data(packet) = qbase::packet::PacketReader::new(bytes, 0)
        .next()
        .unwrap()
        .unwrap()
    else {
        panic!()
    };
    let journal = ArcRcvdJournal::with_capacity(0, None);
    journal.on_rcvd_pn(0, true, Duration::ZERO);
    let before = crypto::opened();
    let opened = receiving
        .open(packet, |pn| journal.decode_pn(pn), Duration::from_secs(1))
        .unwrap();
    assert!(opened.is_none());
    assert_eq!(crypto::opened(), before);
}

#[test]
fn reserved_packet_keys_stay_bound_across_updates_and_reverse_encryption() {
    let ([client, server], _) = support::tls::handshake();
    let material = ArcOneRttKeys::from(client);
    let keys = material.get().unwrap();
    let peer = ArcOneRttKeys::from(server);
    let peer = peer.get().unwrap();
    let journal = ArcRcvdJournal::with_capacity(0, None);
    let open = |bytes: &[u8]| {
        let qbase::packet::Packet::Data(packet) =
            qbase::packet::PacketReader::new(bytes::BytesMut::from(bytes), 0)
                .next()
                .unwrap()
                .unwrap()
        else {
            panic!()
        };
        peer.open(packet, |pn| journal.decode_pn(pn), Duration::from_secs(1))
            .unwrap()
            .unwrap()
            .0
    };
    keys.allow_update();
    let records = qrecovery::journal::ArcSentJournal::default();
    let ((earlier, _), old) = keys
        .reserve(|_| records.next_pn().map_err(Into::into))
        .unwrap();
    keys.update().unwrap();
    let ((later, _), new) = keys
        .reserve(|_| records.next_pn().map_err(Into::into))
        .unwrap();
    assert_eq!((earlier, later), (0, 1));
    let mut bytes = [0; 22];
    bytes[0] = 0x43;
    bytes[1..5].copy_from_slice(&(later as u32).to_be_bytes());
    bytes[5] = 1;
    assert_eq!(
        new.seal(later, &mut bytes, 1, 5, 16).unwrap(),
        (1, KeyPhaseBit::One)
    );
    assert_eq!(open(&bytes), later);
    bytes.fill(0);
    bytes[0] = 0x43;
    bytes[1..5].copy_from_slice(&(earlier as u32).to_be_bytes());
    bytes[5] = 1;
    assert_eq!(
        old.seal(earlier, &mut bytes, 1, 5, 16).unwrap(),
        (0, KeyPhaseBit::Zero)
    );
    assert_eq!(open(&bytes), earlier);
}

#[test]
fn first_update_needs_permission_and_later_updates_need_current_generation_ack() {
    let keys = ready();
    assert!(keys.update().is_err());
    keys.on_ack(0);
    assert!(
        keys.update().is_err(),
        "an initial ACK does not confirm the handshake"
    );
    let keys = ready();
    keys.allow_update();
    keys.update().unwrap();
    assert!(
        keys.update().is_err(),
        "the new generation has not been acknowledged"
    );
    assert_eq!(packet(1, &keys).unwrap().generation, Some(1));
    keys.on_ack(0);
    assert!(
        keys.update().is_err(),
        "old generation's ACK does not authorize another update"
    );
}

#[tokio::test]
async fn key_updates_preserve_reordering_and_do_not_double_advance_sealing() {
    let ([client, server], _) = support::tls::handshake();
    let sending = ArcOneRttKeys::from(client);
    let sending = sending.get().unwrap();
    sending.allow_update();
    let receiving = ArcOneRttKeys::from(server);
    let receiving = receiving.get().unwrap();
    receiving.allow_update();
    let client = sending.clone();
    let server = receiving.clone();
    let client_journal = ArcRcvdJournal::with_capacity(0, None);
    let server_journal = ArcRcvdJournal::with_capacity(0, None);
    let open = |keys: &OneRttKeys, bytes, journal: &ArcRcvdJournal| {
        let qbase::packet::Packet::Data(packet) = qbase::packet::PacketReader::new(bytes, 0)
            .next()
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        keys.open(packet, |pn| journal.decode_pn(pn), Duration::from_secs(1))
            .unwrap()
            .map(|(pn, _)| pn)
    };
    for generation in 1..=3 {
        let old = packet(generation * 10 - 1, &sending).unwrap().into_buffer();
        sending.on_ack(generation - 1);
        sending.update().unwrap();
        // The second update is initiated by both endpoints at once.
        let server_generation = if generation == 2 {
            receiving.on_ack(1);
            receiving.update().unwrap();
            2
        } else {
            generation - 1
        };
        let low = packet(generation * 10, &sending).unwrap();
        let high = packet(generation * 10 + 1, &sending).unwrap();
        assert_eq!(high.generation, Some(generation));
        let mut forged = high.bytes.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(open(&server, forged, &server_journal), None);
        assert_eq!(reserved_generation(&receiving), server_generation);
        assert_eq!(
            open(&server, high.into_buffer(), &server_journal),
            Some(generation * 10 + 1)
        );
        assert_eq!(
            open(&server, low.into_buffer(), &server_journal),
            Some(generation * 10)
        );
        assert_eq!(
            open(&server, old, &server_journal),
            Some(generation * 10 - 1)
        );
        let response = packet(generation - 1, &receiving).unwrap();
        assert_eq!(response.generation, Some(generation));
        assert_eq!(
            open(&client, response.into_buffer(), &client_journal),
            Some(generation - 1)
        );
        assert_eq!(reserved_generation(&sending), generation);
        assert!(
            sending.update().is_err(),
            "a new-phase packet is not an ACK"
        );
        assert!(
            receiving.update().is_err(),
            "passive updates do not grant permission"
        );
    }
}

#[tokio::test]
async fn peer_can_update_again_while_local_update_is_disallowed() {
    let ([client, server], _) = support::tls::handshake();
    let sending = ArcOneRttKeys::from(client);
    let sending = sending.get().unwrap();
    sending.allow_update();
    let receiving = ArcOneRttKeys::from(server);
    let receiving = receiving.get().unwrap();
    receiving.allow_update();
    let client = sending.clone();
    let server = receiving.clone();
    let journal = ArcRcvdJournal::with_capacity(0, None);
    let open = |keys: &OneRttKeys, bytes| {
        let qbase::packet::Packet::Data(packet) = qbase::packet::PacketReader::new(bytes, 0)
            .next()
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        keys.open(packet, |pn| journal.decode_pn(pn), Duration::from_secs(1))
            .unwrap()
            .map(|(pn, _)| pn)
    };
    let oldest = packet(98, &sending).unwrap().into_buffer();
    assert_eq!(
        open(&server, packet(99, &sending).unwrap().into_buffer()),
        Some(99)
    );
    sending.update().unwrap();
    let delayed = packet(100, &sending).unwrap().into_buffer();
    assert_eq!(
        open(&server, packet(101, &sending).unwrap().into_buffer()),
        Some(101)
    );
    assert!(receiving.update().is_err());
    // The receiver replies under generation 1; ACK accounting confirms PN 101.
    let response = packet(7, &receiving).unwrap();
    assert_eq!(response.generation, Some(1));
    assert_eq!(open(&client, response.into_buffer()), Some(7));
    assert!(sending.update().is_err());
    sending.on_ack(1);
    sending.update().unwrap();
    let next = packet(102, &sending).unwrap();
    assert_eq!(next.generation, Some(2));
    let mut forged = next.bytes.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert_eq!(open(&server, forged), None);
    assert_eq!(reserved_generation(&receiving), 1);
    assert_eq!(open(&server, next.into_buffer()), Some(102));
    assert_eq!(reserved_generation(&receiving), 2);
    assert_eq!(open(&server, delayed), Some(100));
    // Generations 0 and 2 share phase 0; PN selects the retained generation 0 pair.
    assert_eq!(open(&server, oldest.clone()), Some(98));
    // Neither receiving a new generation nor ACKing a previous generation permits updating.
    receiving.on_ack(1);
    assert!(receiving.update().is_err());
    assert_eq!(packet(8, &receiving).unwrap().generation, Some(2));
    receiving.on_ack(2);
    receiving.update().unwrap();
    assert_eq!(
        open(&server, oldest),
        None,
        "the fourth pair evicts generation 0"
    );
}

#[tokio::test(start_paused = true)]
async fn local_update_keeps_old_opening_until_peer_uses_the_new_pair() {
    let ([client, server], _) = support::tls::handshake();
    let sending = ArcOneRttKeys::from(server);
    let sending = sending.get().unwrap();
    sending.allow_update();
    let receiving = ArcOneRttKeys::from(client);
    let receiving = receiving.get().unwrap();
    receiving.allow_update();
    let keys = receiving.clone();
    let journal = ArcRcvdJournal::with_capacity(0, None);
    let open = |bytes| {
        let qbase::packet::Packet::Data(packet) = qbase::packet::PacketReader::new(bytes, 0)
            .next()
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        keys.open(packet, |pn| journal.decode_pn(pn), Duration::from_secs(1))
            .unwrap()
            .map(|(pn, _)| pn)
    };
    let old = packet(0, &sending).unwrap().into_buffer();
    let late_old = packet(1, &sending).unwrap().into_buffer();
    receiving.update().unwrap();
    tokio::time::advance(Duration::from_secs(4)).await;
    assert_eq!(open(old), Some(0));
    sending.update().unwrap();
    assert_eq!(open(packet(2, &sending).unwrap().into_buffer()), Some(2));
    assert!(
        receiving.update().is_err(),
        "opening the tail does not grant permission"
    );
    assert_eq!(reserved_generation(&receiving), 1);
    tokio::time::advance(Duration::from_secs(3)).await;
    assert_eq!(open(late_old), None);
    assert_eq!(open(packet(3, &sending).unwrap().into_buffer()), Some(3));
}

fn limited_keys() -> OneRttKeys {
    let ([client, _], _) = support::tls::handshake_with(crypto::provider());
    ArcOneRttKeys::from(client).get().unwrap()
}

#[test]
fn failed_allocation_does_not_consume_the_last_aead_use() {
    let keys = limited_keys();
    for _ in 0..crypto::LIMIT - 1 {
        keys.reserve(|_| Ok(())).unwrap();
    }
    assert!(keys.reserve::<()>(|_| Err(PacketError::Layout)).is_err());
    keys.reserve(|_| Ok(())).unwrap();
    assert!(
        keys.reserve::<()>(|_| panic!("allocated beyond the AEAD limit"))
            .is_err()
    );
}

#[test]
fn confidentiality_limit_updates_when_permitted_and_fails_when_not() {
    let keys = limited_keys();
    for _ in 0..crypto::LIMIT {
        keys.reserve(|_| Ok(())).unwrap();
    }
    keys.allow_update();
    keys.on_ack(0);
    assert_eq!(packet(0, &keys).unwrap().generation, Some(1));
    for _ in 1..crypto::LIMIT {
        keys.reserve(|_| Ok(())).unwrap();
    }
    assert!(
        matches!(packet(1, &keys), Err(PacketError::Connection(error)) if error.kind() == ErrorKind::AeadLimitReached)
    );
}

#[test]
fn authentication_failures_enforce_the_integrity_limit() {
    let ([client, server], _) = support::tls::handshake_with(crypto::provider());
    let sending = ArcOneRttKeys::from(client).get().unwrap();
    let receiving = ArcOneRttKeys::from(server).get().unwrap();
    let mut forged = packet(0, &sending).unwrap().into_buffer();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let journal = ArcRcvdJournal::with_capacity(0, None);
    for attempt in 1..=crypto::LIMIT {
        let qbase::packet::Packet::Data(packet) =
            qbase::packet::PacketReader::new(forged.clone(), 0)
                .next()
                .unwrap()
                .unwrap()
        else {
            panic!()
        };
        let result = receiving.open(packet, |pn| journal.decode_pn(pn), Duration::from_secs(1));
        if attempt < crypto::LIMIT {
            assert!(result.unwrap().is_none());
        } else {
            assert!(matches!(result, Err(error) if error.kind() == ErrorKind::AeadLimitReached));
        }
    }
    assert_eq!(journal.decode_pn(PacketNumber::encode(0, 0)), Ok(0));
}
