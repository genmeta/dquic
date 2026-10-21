use qbase::packet::PacketNumber;
use qrecovery::journal::ArcRcvdJournal;

mod support {
    pub mod crypto;
    pub mod data;
    pub mod tls;
}
use std::{sync::Arc, time::Duration};

use qbase::{error::ErrorKind, packet::KeyPhaseBit};
use qtransport::keys::*;
use support::crypto;

fn ready() -> ArcOneRttKeys {
    let ([client, _], _) = support::tls::handshake();
    ArcOneRttKeys::from(client)
}

fn reserved_generation(keys: &ArcOneRttKeys) -> u64 {
    keys.get().unwrap().generation
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

fn packet(pn: u64, keys: &ArcOneRttKeys) -> Result<Packet, PacketError> {
    let key = keys.get()?;
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
fn one_rtt_handles_share_updates_and_retirement() {
    let ([client, _], _) = support::tls::handshake();
    let keys = ArcOneRttKeys::from(client);
    let other = keys.clone();
    let old = keys.get().unwrap();
    assert!(Arc::ptr_eq(&old, &other.get().unwrap()));
    keys.allow_update();
    other.update().unwrap();
    assert_eq!(old.generation, 0);
    assert_eq!(keys.get().unwrap().generation, 1);
    keys.retire();
    assert!(matches!(other.get(), Err(PacketError::Retired(KeyRetired))));
}

#[test]
fn seal_reports_the_phase_authenticated_in_the_header() {
    let (materials, _) = support::tls::handshake();
    let [sending, receiving] = materials.map(ArcOneRttKeys::from);
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
        let sealed = sending
            .get()
            .unwrap()
            .seal(pn, &mut buffer, 1, 5, tag_len)
            .unwrap();
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
    let receiving = ArcOneRttKeys::from(server);
    let bytes = packet(0, &sending).unwrap().into_buffer();
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
    let keys = material;
    let peer = ArcOneRttKeys::from(server);
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
    use qtransport::space::{Allocate, Keys};
    let mut data = support::data::data();
    Arc::get_mut(&mut data).unwrap().space.keys = keys.clone();
    let ((earlier, _), Keys::Short(old)) = data.pn_and_keys().unwrap().unwrap() else {
        unreachable!();
    };
    keys.update().unwrap();
    let ((later, _), Keys::Short(new)) = data.pn_and_keys().unwrap().unwrap() else {
        unreachable!();
    };
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
    sending.allow_update();
    let receiving = ArcOneRttKeys::from(server);
    receiving.allow_update();
    let client = sending.clone();
    let server = receiving.clone();
    let client_journal = ArcRcvdJournal::with_capacity(0, None);
    let server_journal = ArcRcvdJournal::with_capacity(0, None);
    let open = |keys: &ArcOneRttKeys, bytes, journal: &ArcRcvdJournal| {
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
    sending.allow_update();
    let receiving = ArcOneRttKeys::from(server);
    receiving.allow_update();
    let client = sending.clone();
    let server = receiving.clone();
    let journal = ArcRcvdJournal::with_capacity(0, None);
    let open = |keys: &ArcOneRttKeys, bytes| {
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
    sending.allow_update();
    let receiving = ArcOneRttKeys::from(client);
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

fn limited_keys() -> ArcOneRttKeys {
    let ([client, _], _) = support::tls::handshake_with(crypto::provider());
    ArcOneRttKeys::from(client)
}

#[test]
fn unused_keys_do_not_consume_the_last_aead_use() {
    let keys = limited_keys();
    for pn in 0..crypto::LIMIT - 1 {
        packet(pn, &keys).unwrap();
    }
    for _ in 0..crypto::LIMIT {
        drop(keys.get().unwrap());
    }
    packet(crypto::LIMIT - 1, &keys).unwrap();
    assert!(matches!(keys.get(), Err(PacketError::Connection(error))
        if error.kind() == ErrorKind::AeadLimitReached));
}

#[test]
fn confidentiality_limit_updates_when_permitted_and_fails_when_not() {
    let keys = limited_keys();
    for pn in 0..crypto::LIMIT {
        packet(pn, &keys).unwrap();
    }
    keys.allow_update();
    keys.on_ack(0);
    assert_eq!(packet(0, &keys).unwrap().generation, Some(1));
    for pn in 1..crypto::LIMIT {
        packet(pn, &keys).unwrap();
    }
    assert!(
        matches!(packet(1, &keys), Err(PacketError::Connection(error)) if error.kind() == ErrorKind::AeadLimitReached)
    );
}

#[test]
fn authentication_failures_enforce_the_integrity_limit() {
    let ([client, server], _) = support::tls::handshake_with(crypto::provider());
    let sending = ArcOneRttKeys::from(client);
    let receiving = ArcOneRttKeys::from(server);
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

#[test]
fn data_space_serializes_packet_numbers_with_key_generations() {
    use qtransport::space::{Allocate, Keys};

    let data = support::data::data();
    let start = std::sync::Barrier::new(4);
    let mut allocated = std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..4)
            .map(|_| {
                let data = &data;
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    (0..32)
                        .map(|_| {
                            // Model handshake/ACK permission arriving between allocations.
                            data.keys.allow_update();
                            let _ = data.keys.update();
                            let (pn, Keys::Short(keys)) = data.pn_and_keys().unwrap().unwrap()
                            else {
                                unreachable!();
                            };
                            (pn.0, keys.generation)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        tasks
            .into_iter()
            .flat_map(|task| task.join().unwrap())
            .collect::<Vec<_>>()
    });
    allocated.sort_unstable();
    for (expected, (pn, _)) in allocated.iter().enumerate() {
        assert_eq!(*pn, expected as u64);
    }
    assert!(allocated.windows(2).all(|pair| pair[0].1 <= pair[1].1));
    assert!(allocated.last().unwrap().1 > 0);
    data.keys.retire();
    assert!(data.pn_and_keys().unwrap().is_none());
    assert_eq!(
        data.sent_journal.next_pn().unwrap().0,
        allocated.len() as u64
    );
}

#[test]
fn concurrent_encryption_enforces_each_generations_limit() {
    let keys = limited_keys();
    // Select all handles before encryption so get() cannot enforce this limit.
    let fixed: Vec<_> = (0..crypto::LIMIT * 2)
        .map(|_| keys.get().unwrap())
        .collect();
    let start = std::sync::Barrier::new(fixed.len());
    let succeeded = std::thread::scope(|scope| {
        let tasks: Vec<_> = fixed
            .into_iter()
            .enumerate()
            .map(|(pn, key)| {
                let start = &start;
                scope.spawn(move || {
                    let mut bytes = [0; 22];
                    bytes[0] = 0x43;
                    bytes[1..5].copy_from_slice(&(pn as u32).to_be_bytes());
                    bytes[5] = 1;
                    start.wait();
                    match key.seal(pn as u64, &mut bytes, 1, 5, 16) {
                        Ok(_) => 1,
                        Err(PacketError::Connection(error))
                            if error.kind() == ErrorKind::AeadLimitReached =>
                        {
                            0
                        }
                        result => panic!("unexpected sealing result: {result:?}"),
                    }
                })
            })
            .collect();
        tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .sum::<u64>()
    });
    assert_eq!(succeeded, crypto::LIMIT);
    keys.allow_update();
    assert_eq!(
        packet(crypto::LIMIT * 2, &keys).unwrap().generation,
        Some(1)
    );
}
