//! Keys own readiness, retirement, and packet protection generations.
use std::{
    collections::VecDeque,
    future::Future,
    ops::RangeInclusive,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use qbase::{
    error::ErrorKind,
    frame::FrameReader,
    packet::{
        DataHeader, DataPacket, GetPacketNumberLength, GetType, InvalidPacketNumber, KeyPhaseBit,
        LongSpecificBits, PacketNumber, ShortSpecificBits, number::take_pn_len,
    },
    varint::VARINT_MAX,
};
use tokio::time::Instant;

use crate::{Error, send::packet::PacketError};

#[derive(Clone)]
pub enum KeyState<K> {
    Pending,
    Waiting(Waker),
    Ready(K),
    Retired,
}

impl<K> KeyState<K> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Option<&K>> {
        match self {
            Self::Ready(keys) => Poll::Ready(Some(keys)),
            Self::Retired => Poll::Ready(None),
            Self::Waiting(waker) if waker.will_wake(cx.waker()) => Poll::Pending,
            Self::Pending | Self::Waiting(_) => {
                *self = Self::Waiting(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl<K: Clone + Unpin> Future for KeyState<K> {
    type Output = Option<K>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().poll_ready(cx).map(|keys| keys.cloned())
    }
}

pub struct ArcKeys<K = Arc<qtls::BidirectionalKeys>>(Arc<Mutex<KeyState<K>>>);

impl<K: Clone> Future for ArcKeys<K> {
    type Output = Option<K>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0
            .lock()
            .unwrap()
            .poll_ready(cx)
            .map(|keys| keys.cloned())
    }
}

impl<K> Clone for ArcKeys<K> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<K> ArcKeys<K> {
    pub fn new_pending() -> Self {
        Self(Arc::new(Mutex::new(KeyState::Pending)))
    }

    pub fn install(&self, keys: K) -> Result<(), Error> {
        let mut state = self.0.lock().unwrap();
        if !matches!(*state, KeyState::Pending | KeyState::Waiting(_)) {
            return Err(crate::error(
                ErrorKind::Internal,
                "keys already installed or retired",
            ));
        }
        if let KeyState::Waiting(waker) = std::mem::replace(&mut *state, KeyState::Ready(keys)) {
            waker.wake();
        }
        Ok(())
    }

    pub fn retire(&self) {
        let mut state = self.0.lock().unwrap();
        if let KeyState::Waiting(waker) = std::mem::replace(&mut *state, KeyState::Retired) {
            waker.wake();
        }
    }
}

/// Header protection does not change during a 1-RTT key update.
pub struct HeaderKeys {
    pub opening: qtls::HeaderProtectionKey,
    pub sealing: qtls::HeaderProtectionKey,
}

#[derive(Clone)]
pub struct OneRttKeys {
    pub headers: Arc<HeaderKeys>,
    packets: Arc<Mutex<OneRttPacketKeys>>,
}

struct PacketKeys {
    generation: u64,
    /// Bounds of authenticated packet numbers, not the complete acceptable range.
    received: Option<RangeInclusive<u64>>,
    opening: qtls::PacketKey,
    sealing: qtls::PacketKey,
    expires: Option<Instant>,
}

struct OneRttPacketKeys {
    keys: VecDeque<PacketKeys>,
    next_secret: qtls::Secrets,
    sealed_count: u64,
    failed_opened: u64,
    can_update: bool,
}

impl OneRttPacketKeys {
    fn push(&mut self, keys: qtls::PacketKeys, next_secret: qtls::Secrets) -> Result<(), Error> {
        let generation = self
            .keys
            .back()
            .unwrap()
            .generation
            .checked_add(1)
            .ok_or_else(|| crate::error(ErrorKind::KeyUpdate, "key generation exhausted"))?;
        if self.keys.len() == 3 {
            self.keys.pop_front();
        }
        self.keys.push_back(PacketKeys {
            generation,
            received: None,
            opening: keys.opening,
            sealing: keys.sealing,
            expires: None,
        });
        self.next_secret = next_secret;
        self.sealed_count = 0;
        self.can_update = false;
        Ok(())
    }

    fn update(&mut self) -> Result<(), Error> {
        if !self.can_update {
            return Err(crate::error(
                ErrorKind::KeyUpdate,
                "local key update is not permitted",
            ));
        }
        let mut next_secret = self.next_secret.clone();
        let keys = next_secret.next_packet_keys();
        self.push(keys, next_secret)
    }

    fn encrypt(
        &mut self,
        pn: u64,
        header: &mut [u8],
        body: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(u64, KeyPhaseBit), PacketError> {
        let nearing_limit = self.sealed_count
            >= self
                .keys
                .back()
                .unwrap()
                .sealing
                .confidentiality_limit()
                .saturating_sub(1);
        if nearing_limit && self.can_update {
            self.update()?;
        }
        let keys = self.keys.back().unwrap();
        if self.sealed_count >= keys.sealing.confidentiality_limit() {
            return Err(crate::error(
                ErrorKind::AeadLimitReached,
                "packet protection confidentiality limit",
            )
            .into());
        }
        self.sealed_count += 1;
        if keys.sealing.tag_len() != tag.len() {
            return Err(PacketError::Layout);
        }
        let phase = KeyPhaseBit::from(keys.generation & 1 != 0);
        let mut specific_bits = ShortSpecificBits::from(header[0]);
        specific_bits.set_key_phase(phase);
        header[0] = *specific_bits;
        keys.sealing.seal(pn, header, body, tag)?;
        Ok((keys.generation, phase))
    }

    fn decrypt(
        &mut self,
        pn: u64,
        phase: KeyPhaseBit,
        header: &[u8],
        body: &mut [u8],
        pto: Duration,
    ) -> Result<Option<usize>, Error> {
        let now = Instant::now();
        while self
            .keys
            .front()
            .unwrap()
            .expires
            .is_some_and(|until| now >= until)
        {
            self.keys.pop_front();
        }
        // The latest observed generation starting at or before PN determines its lower bound.
        let mut index = self
            .keys
            .iter()
            .rposition(|keys| {
                keys.received
                    .as_ref()
                    .is_some_and(|range| pn >= *range.start())
            })
            .unwrap_or(0);
        let keys = &self.keys[index];
        if phase != KeyPhaseBit::from(keys.generation & 1 != 0) {
            if keys
                .received
                .as_ref()
                .is_some_and(|range| pn <= *range.end())
            {
                return Ok(None);
            }
            index += 1;
        }
        // A peer update is tentative: neither the queue nor the secret advances on forgery.
        let candidate = (index == self.keys.len()).then(|| {
            let mut next_secret = self.next_secret.clone();
            (next_secret.next_packet_keys(), next_secret)
        });
        let opening = match &candidate {
            Some((keys, _)) => &keys.opening,
            None => &self.keys[index].opening,
        };
        let plain_len = match opening.open(pn, header, body) {
            Ok(plain) => plain.len(),
            Err(_) => {
                self.failed_opened += 1;
                if self.failed_opened >= opening.integrity_limit() {
                    return Err(crate::error(
                        ErrorKind::AeadLimitReached,
                        "packet protection integrity limit",
                    ));
                }
                return Ok(None);
            }
        };
        if let Some((keys, next_secret)) = candidate {
            self.push(keys, next_secret)?;
            index = self.keys.len() - 1;
        }
        // Local updates retain older opening keys until a newer peer generation authenticates.
        for older in self.keys.iter_mut().take(index) {
            older.expires.get_or_insert(now + pto.saturating_mul(3));
        }
        let received = &mut self.keys[index].received;
        *received = Some(match received {
            Some(range) => (*range.start()).min(pn)..=(*range.end()).max(pn),
            None => pn..=pn,
        });
        Ok(Some(plain_len))
    }
}

#[derive(Clone)]
pub struct ArcOneRttKeys(ArcKeys<OneRttKeys>);

impl ArcOneRttKeys {
    pub fn new_pending() -> Self {
        Self(ArcKeys::new_pending())
    }

    pub fn install(&self, keys: qtls::OneRttKeyMaterial) -> Result<(), Error> {
        let mut packets = VecDeque::with_capacity(3);
        packets.push_back(PacketKeys {
            generation: 0,
            received: None,
            opening: keys.packet.opening,
            sealing: keys.packet.sealing,
            expires: None,
        });
        self.0.install(OneRttKeys {
            headers: Arc::new(HeaderKeys {
                opening: keys.opening_header,
                sealing: keys.sealing_header,
            }),
            packets: Arc::new(Mutex::new(OneRttPacketKeys {
                keys: packets,
                next_secret: keys.next_secret,
                sealed_count: 0,
                failed_opened: 0,
                can_update: false,
            })),
        })
    }

    pub fn retire(&self) {
        self.0.retire();
    }
}

impl Future for ArcOneRttKeys {
    type Output = Option<OneRttKeys>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().0).poll(cx)
    }
}

impl OneRttKeys {
    /// Allow the first local update when qconn confirms the handshake.
    /// Later updates are authorized by ACKs for the current sending generation.
    pub fn allow_update(&self) {
        self.packets.lock().unwrap().can_update = true;
    }

    /// Consume the permission and immediately advance sending keys.
    pub fn update(&self) -> Result<(), Error> {
        self.packets.lock().unwrap().update()
    }

    pub(crate) fn on_ack(&self, generation: u64) {
        let mut packets = self.packets.lock().unwrap();
        if generation != 0 && packets.keys.back().unwrap().generation == generation {
            packets.can_update = true;
        }
    }

    /// Keep key updates serialized with one nonblocking socket submission.
    pub(crate) fn with_generation<R>(
        &self,
        generation: u64,
        submit: impl FnOnce() -> R,
    ) -> Option<R> {
        let packets = self.packets.lock().unwrap();
        (packets.keys.back().unwrap().generation == generation).then(submit)
    }

    pub fn tag_len(&self) -> usize {
        self.packets
            .lock()
            .unwrap()
            .keys
            .back()
            .unwrap()
            .sealing
            .tag_len()
    }
}

/// Remove packet protection and decode its packet number.
pub trait OpenPacket {
    /// PTO determines old 1-RTT key retention; fixed directional keys ignore it.
    fn open(
        &self,
        packet: DataPacket,
        decode_pn: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
        pto: Duration,
    ) -> Result<Option<(u64, FrameReader)>, Error>;
}

/// Protect an assembled packet in place.
pub trait SealPacket {
    /// Fixed keys return (); 1-RTT keys return the sending generation and Key Phase.
    type Output;

    /// Protect a packet with a four-byte PN and a reserved authentication tag.
    fn seal(
        &self,
        pn: u64,
        buffer: &mut [u8],
        pn_offset: usize,
        body_offset: usize,
        tag_len: usize,
    ) -> Result<Self::Output, PacketError>;
}

impl OpenPacket for qtls::DirectionalKeys {
    fn open(
        &self,
        packet: DataPacket,
        decode_pn: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
        _pto: Duration,
    ) -> Result<Option<(u64, FrameReader)>, Error> {
        open_with(packet, &self.header, decode_pn, |pn, _, header, body| {
            Ok(self
                .packet
                .open(pn, header, body)
                .ok()
                .map(|plain| plain.len()))
        })
    }
}

impl SealPacket for qtls::DirectionalKeys {
    type Output = ();

    fn seal(
        &self,
        pn: u64,
        buffer: &mut [u8],
        pn_offset: usize,
        body_offset: usize,
        tag_len: usize,
    ) -> Result<Self::Output, PacketError> {
        let tag_offset = buffer.len() - tag_len;
        let (header, body_tag) = buffer.split_at_mut(body_offset);
        let (body, tag) = body_tag.split_at_mut(tag_offset - body_offset);
        self.packet.seal(pn, header, body, tag)?;
        let (prefix, pn_bytes) = header.split_at_mut(pn_offset);
        self.header.protect(
            &body_tag[..self.header.sample_len()],
            &mut prefix[0],
            pn_bytes,
        )?;
        Ok(())
    }
}

impl SealPacket for OneRttKeys {
    type Output = (u64, KeyPhaseBit);

    /// Protect an assembled packet in place, including its reserved authentication tag.
    /// Offsets delimit a four-byte PN and plaintext; the body/tag must supply an HP sample.
    /// Returns the sending generation and the Key Phase written before AEAD protection.
    fn seal(
        &self,
        pn: u64,
        buffer: &mut [u8],
        pn_offset: usize,
        body_offset: usize,
        tag_len: usize,
    ) -> Result<Self::Output, PacketError> {
        let tag_offset = buffer.len() - tag_len;
        let (header, body_tag) = buffer.split_at_mut(body_offset);
        let (body, tag) = body_tag.split_at_mut(tag_offset - body_offset);
        let mut packets = self.packets.lock().unwrap();
        let (generation, phase) = packets.encrypt(pn, header, body, tag)?;
        let (prefix, pn_bytes) = header.split_at_mut(pn_offset);
        let header_key = &self.headers.sealing;
        header_key.protect(
            &body_tag[..header_key.sample_len()],
            &mut prefix[0],
            pn_bytes,
        )?;
        Ok((generation, phase))
    }
}

impl OpenPacket for OneRttKeys {
    fn open(
        &self,
        packet: DataPacket,
        decode_pn: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
        pto: Duration,
    ) -> Result<Option<(u64, FrameReader)>, Error> {
        open_with(
            packet,
            &self.headers.opening,
            decode_pn,
            |pn, first, header, body| {
                self.packets.lock().unwrap().decrypt(
                    pn,
                    ShortSpecificBits::from(first).key_phase(),
                    header,
                    body,
                    pto,
                )
            },
        )
    }
}

/// Shared header removal, PN decoding and authenticated payload extraction.
fn open_with(
    mut packet: DataPacket,
    header_key: &qtls::HeaderProtectionKey,
    decode_pn: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
    mut decrypt: impl FnMut(u64, u8, &[u8], &mut [u8]) -> Result<Option<usize>, Error>,
) -> Result<Option<(u64, FrameReader)>, Error> {
    let kind = packet.get_type();
    let sample_start = packet.offset.saturating_add(4);
    if packet.offset == 0
        || sample_start.saturating_add(header_key.sample_len()) > packet.bytes.len()
    {
        return Ok(None);
    }
    let (header_pn, sample) = packet.bytes.split_at_mut(sample_start);
    let (prefix, pn_bytes) = header_pn.split_at_mut(packet.offset);
    if header_key
        .unprotect(&sample[..header_key.sample_len()], &mut prefix[0], pn_bytes)
        .is_err()
    {
        return Ok(None);
    }
    let first = packet.bytes[0];
    let pn_len = (first & 3) + 1;
    let (_, encoded) = take_pn_len(pn_len)(&packet.bytes[packet.offset..])
        .map_err(|_| crate::error(ErrorKind::Internal, "invalid packet-number layout"))?;
    let Ok(pn) = decode_pn(encoded) else {
        return Ok(None);
    };
    if pn > VARINT_MAX {
        return Ok(None);
    }
    let body_offset = packet.offset + pn_len as usize;
    let (header, body) = packet.bytes.split_at_mut(body_offset);
    let Some(plain_len) = decrypt(pn, first, header, body)? else {
        return Ok(None);
    };
    // Reserved bits are only a protocol error after authentication.
    match packet.header {
        DataHeader::Short(_) => ShortSpecificBits::from(first).pn_len(),
        DataHeader::Long(_) => LongSpecificBits::from(first).pn_len(),
    }
    .map_err(qbase::error::QuicError::from)?;
    let payload = packet
        .bytes
        .freeze()
        .slice(body_offset..body_offset + plain_len);
    if payload.is_empty() {
        return Err(crate::error(
            ErrorKind::ProtocolViolation,
            "empty packet payload",
        ));
    }
    Ok(Some((pn, FrameReader::new(payload, kind))))
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;
    use qbase::{
        cid::ConnectionId,
        frame::PingFrame,
        packet::{OneRttHeader, PacketNumber},
    };
    use qrecovery::journal::ArcRcvdJournal;

    use super::*;
    use crate::send::{constraints::Constraints, packet::OneRttPacket};

    fn ready() -> OneRttKeys {
        let ([client, _], _) = crate::tests::handshake();
        let keys = ArcOneRttKeys::new_pending();
        keys.install(client).unwrap();
        keys.now_or_never().unwrap().unwrap()
    }
    fn packet(pn: u64) -> OneRttPacket {
        let mut packet = OneRttPacket::new(
            bytes::BytesMut::zeroed(1200),
            OneRttHeader::new(Default::default(), ConnectionId::default()),
            pn,
            16,
        )
        .unwrap();
        packet
            .assemble(
                &mut Constraints {
                    capacity: 1200,
                    congestion: 1200,
                    anti_amplification: 1200,
                },
                [&mut PingFrame],
            )
            .unwrap();
        packet
    }

    #[tokio::test]
    async fn one_rtt_wait_yields_shared_material_and_reports_retirement() {
        let keys = ArcOneRttKeys::new_pending();
        let mut waiting = keys.clone();
        assert!(futures::poll!(&mut waiting).is_pending());
        let ([client, _], _) = crate::tests::handshake();
        keys.install(client).unwrap();
        let material = waiting.await.unwrap();
        let shared = keys.clone().await.unwrap();
        material.allow_update();
        shared.update().unwrap();
        assert_eq!(packet(0).seal(&material).unwrap().generation, 1);
        keys.retire();
        assert!(keys.await.is_none());
    }

    #[test]
    fn seal_reports_the_phase_authenticated_in_the_header() {
        let (materials, _) = crate::tests::handshake();
        let [sending, receiving] = materials.map(|material| {
            let keys = ArcOneRttKeys::new_pending();
            keys.install(material).unwrap();
            keys.now_or_never().unwrap().unwrap()
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
        let ([client, server], _) = crate::tests::handshake();
        let sending = ArcOneRttKeys::new_pending();
        sending.install(client).unwrap();
        let bytes = packet(0)
            .seal(&sending.now_or_never().unwrap().unwrap())
            .unwrap()
            .bytes;
        let qbase::packet::Packet::Data(packet) = qbase::packet::PacketReader::new(bytes, 0)
            .next()
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        let journal = ArcRcvdJournal::with_capacity(0, None);
        journal.on_rcvd_pn(0, true, Duration::ZERO);
        let mut called = 0;
        let opened = open_with(
            packet,
            &server.opening_header,
            |pn| journal.decode_pn(pn),
            |pn, _, header, body| {
                called += 1;
                Ok(server
                    .packet
                    .opening
                    .open(pn, header, body)
                    .ok()
                    .map(|plain| plain.len()))
            },
        )
        .unwrap();
        assert!(opened.is_none());
        assert_eq!(called, 0);
    }

    #[test]
    fn packets_can_be_sealed_out_of_allocation_order() {
        let keys = ready();
        let records = crate::send::records::SentPackets::default();
        let earlier = packet(records.next_pn().unwrap());
        let later = packet(records.next_pn().unwrap());
        let later = later.seal(&keys).unwrap();
        let earlier = earlier.seal(&keys).unwrap();
        assert!(earlier.pn < later.pn);
        assert_eq!(earlier.generation, later.generation);
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
        assert_eq!(
            keys.with_generation(0, || panic!("submitted an old key phase")),
            None
        );
        assert_eq!(keys.with_generation(1, || ()), Some(()));
        assert_eq!(packet(1).seal(&keys).unwrap().generation, 1);
        keys.on_ack(0);
        assert!(
            keys.update().is_err(),
            "old generation's ACK does not authorize another update"
        );
    }

    #[tokio::test]
    async fn key_updates_preserve_reordering_and_do_not_double_advance_sealing() {
        let ([client, server], _) = crate::tests::handshake();
        let sending = ArcOneRttKeys::new_pending();
        sending.install(client).unwrap();
        let sending = sending.await.unwrap();
        sending.allow_update();
        let receiving = ArcOneRttKeys::new_pending();
        receiving.install(server).unwrap();
        let receiving = receiving.await.unwrap();
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
            let old = packet(generation * 10 - 1).seal(&sending).unwrap().bytes;
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
            let low = packet(generation * 10).seal(&sending).unwrap();
            let high = packet(generation * 10 + 1).seal(&sending).unwrap();
            assert_eq!(high.generation, generation);
            let mut forged = high.bytes.clone();
            *forged.last_mut().unwrap() ^= 1;
            assert_eq!(open(&server, forged, &server_journal), None);
            assert_eq!(
                receiving.with_generation(server_generation, || ()),
                Some(())
            );
            assert_eq!(
                open(&server, high.bytes, &server_journal),
                Some(generation * 10 + 1)
            );
            assert_eq!(
                open(&server, low.bytes, &server_journal),
                Some(generation * 10)
            );
            assert_eq!(
                open(&server, old, &server_journal),
                Some(generation * 10 - 1)
            );
            let response = packet(generation - 1).seal(&receiving).unwrap();
            assert_eq!(response.generation, generation);
            assert_eq!(
                open(&client, response.bytes, &client_journal),
                Some(generation - 1)
            );
            assert_eq!(sending.with_generation(generation, || ()), Some(()));
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
        let ([client, server], _) = crate::tests::handshake();
        let sending = ArcOneRttKeys::new_pending();
        sending.install(client).unwrap();
        let sending = sending.await.unwrap();
        sending.allow_update();
        let receiving = ArcOneRttKeys::new_pending();
        receiving.install(server).unwrap();
        let receiving = receiving.await.unwrap();
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
        let oldest = packet(98).seal(&sending).unwrap().bytes;
        assert_eq!(
            open(&server, packet(99).seal(&sending).unwrap().bytes),
            Some(99)
        );
        sending.update().unwrap();
        let delayed = packet(100).seal(&sending).unwrap().bytes;
        assert_eq!(
            open(&server, packet(101).seal(&sending).unwrap().bytes),
            Some(101)
        );
        assert!(receiving.update().is_err());
        // The receiver replies under generation 1; ACK accounting confirms PN 101.
        let response = packet(7).seal(&receiving).unwrap();
        assert_eq!(response.generation, 1);
        assert_eq!(open(&client, response.bytes), Some(7));
        assert!(sending.update().is_err());
        sending.on_ack(1);
        sending.update().unwrap();
        let next = packet(102).seal(&sending).unwrap();
        assert_eq!(next.generation, 2);
        let mut forged = next.bytes.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(open(&server, forged), None);
        assert_eq!(receiving.with_generation(1, || ()), Some(()));
        assert_eq!(open(&server, next.bytes), Some(102));
        assert_eq!(receiving.with_generation(2, || ()), Some(()));
        assert_eq!(open(&server, delayed), Some(100));
        // Generations 0 and 2 share phase 0; PN selects the retained generation 0 pair.
        assert_eq!(open(&server, oldest.clone()), Some(98));
        // Neither receiving a new generation nor ACKing a previous generation permits updating.
        receiving.on_ack(1);
        assert!(receiving.update().is_err());
        assert_eq!(packet(8).seal(&receiving).unwrap().generation, 2);
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
        let ([client, server], _) = crate::tests::handshake();
        let sending = ArcOneRttKeys::new_pending();
        sending.install(server).unwrap();
        let sending = sending.await.unwrap();
        sending.allow_update();
        let receiving = ArcOneRttKeys::new_pending();
        receiving.install(client).unwrap();
        let receiving = receiving.await.unwrap();
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
        let old = packet(0).seal(&sending).unwrap().bytes;
        let late_old = packet(1).seal(&sending).unwrap().bytes;
        receiving.update().unwrap();
        tokio::time::advance(Duration::from_secs(4)).await;
        assert_eq!(open(old), Some(0));
        sending.update().unwrap();
        assert_eq!(open(packet(2).seal(&sending).unwrap().bytes), Some(2));
        assert!(
            receiving.update().is_err(),
            "opening the tail does not grant permission"
        );
        assert_eq!(receiving.with_generation(1, || ()), Some(()));
        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(open(late_old), None);
        assert_eq!(open(packet(3).seal(&sending).unwrap().bytes), Some(3));
    }

    #[test]
    fn confidentiality_limit_updates_when_permitted_and_fails_when_not() {
        let keys = ready();
        keys.allow_update();
        keys.on_ack(0);
        {
            let mut packets = keys.packets.lock().unwrap();
            packets.sealed_count = packets.keys.back().unwrap().sealing.confidentiality_limit();
        }
        assert_eq!(packet(0).seal(&keys).unwrap().generation, 1);
        {
            let mut packets = keys.packets.lock().unwrap();
            packets.sealed_count = packets.keys.back().unwrap().sealing.confidentiality_limit();
        }
        assert!(
            matches!(packet(1).seal(&keys), Err(PacketError::Connection(error)) if error.kind() == ErrorKind::AeadLimitReached)
        );
    }

    #[test]
    fn authentication_failures_enforce_the_integrity_limit() {
        let ([client, server], _) = crate::tests::handshake();
        let sending = ArcOneRttKeys::new_pending();
        sending.install(client).unwrap();
        let sending = sending.now_or_never().unwrap().unwrap();
        let receiving = ArcOneRttKeys::new_pending();
        receiving.install(server).unwrap();
        let receiving = receiving.now_or_never().unwrap().unwrap();
        {
            let mut packets = receiving.packets.lock().unwrap();
            packets.failed_opened = packets.keys.back().unwrap().opening.integrity_limit() - 1;
        }
        let mut forged = packet(0).seal(&sending).unwrap().bytes;
        let last = forged.len() - 1;
        forged[last] ^= 1;
        let qbase::packet::Packet::Data(packet) = qbase::packet::PacketReader::new(forged, 0)
            .next()
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        let journal = ArcRcvdJournal::with_capacity(0, None);
        assert!(
            matches!(receiving.open(packet, |pn| journal.decode_pn(pn), Duration::from_secs(1)), Err(error) if error.kind() == ErrorKind::AeadLimitReached)
        );
        assert_eq!(journal.decode_pn(PacketNumber::encode(0, 0)), Ok(0));
    }

    #[tokio::test]
    async fn retirement_wakes_a_pending_key_wait_and_cannot_be_reinstalled() {
        let keys = ArcKeys::<()>::new_pending();
        let waiting = keys.clone();
        let task = tokio::spawn(waiting);
        tokio::task::yield_now().await;
        keys.retire();
        assert_eq!(task.await.unwrap(), None);
        assert!(keys.install(()).is_err());
    }

    #[test]
    fn key_state_future_preserves_ready_material_and_reports_retirement() {
        let material = Arc::new(vec![1, 2, 3]);
        let mut state = KeyState::Pending;
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(Pin::new(&mut state).poll(&mut cx).is_pending());
        assert!(Pin::new(&mut state).poll(&mut cx).is_pending());
        state = KeyState::Ready(material.clone());
        for _ in 0..2 {
            let Poll::Ready(Some(keys)) = Pin::new(&mut state).poll(&mut cx) else {
                panic!()
            };
            assert!(Arc::ptr_eq(&material, &keys));
        }
        state = KeyState::Retired;
        assert_eq!(Pin::new(&mut state).poll(&mut cx), Poll::Ready(None));
    }

    #[tokio::test]
    async fn installing_keys_wakes_the_future_and_keeps_the_shared_material() {
        let keys = ArcKeys::new_pending();
        let mut waiting = keys.clone();
        let (entered, pending) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            assert!(futures::poll!(&mut waiting).is_pending());
            entered.send(()).unwrap();
            waiting.await
        });
        pending.await.unwrap();
        let material = Arc::new(vec![1, 2, 3]);
        keys.install(material.clone()).unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(Arc::ptr_eq(&received, &material));
        assert!(Arc::ptr_eq(&keys.clone().await.unwrap(), &material));
        keys.retire();
        assert_eq!(keys.await, None);
    }

    #[tokio::test]
    async fn sealing_waits_until_pending_socket_submission_finishes() {
        let [(_client, transport, path), _] = crate::tests::pair(1);
        let keys = transport.data.keys.clone().await.unwrap();
        let mut sender = crate::send::Sender::new(keys.clone(), transport, path).unwrap();
        sender.heartbeat();
        assert!(sender.prepare().unwrap());
        let (start, started) = std::sync::mpsc::channel();
        let (sealed, completed) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            started.recv().unwrap();
            packet(1).seal(&keys).unwrap();
            sealed.send(()).unwrap();
        });
        assert!(matches!(
            sender.poll_send_with(
                &mut Context::from_waker(futures::task::noop_waker_ref()),
                |_, _, bytes| {
                    start.send(()).unwrap();
                    assert!(matches!(
                        completed.recv_timeout(Duration::from_millis(30)),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    ));
                    Poll::Ready(Ok(bytes.len()))
                },
            ),
            Poll::Ready(Ok(true))
        ));
        completed.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
    }
}
