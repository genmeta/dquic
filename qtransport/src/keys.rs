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
    error::{ErrorKind, QuicError},
    frame::FrameReader,
    packet::{
        DataHeader, DataPacket, GetPacketNumberLength, GetType, InvalidPacketNumber, KeyPhaseBit,
        LongSpecificBits, PacketNumber, ShortSpecificBits, number::take_pn_len,
    },
    varint::VARINT_MAX,
};
use tokio::time::Instant;

use crate::{Error, send::write::PacketError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("keys retired")]
pub struct KeyRetired;

#[derive(Clone)]
pub enum KeyState<K> {
    Pending,
    Waiting(Waker),
    Ready(K),
    Retired,
}

impl<K> KeyState<K> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<&K, KeyRetired>> {
        match self {
            Self::Ready(keys) => Poll::Ready(Ok(keys)),
            Self::Retired => Poll::Ready(Err(KeyRetired)),
            Self::Waiting(waker) if waker.will_wake(cx.waker()) => Poll::Pending,
            Self::Pending | Self::Waiting(_) => {
                *self = Self::Waiting(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl<K: Clone + Unpin> Future for KeyState<K> {
    type Output = Result<K, KeyRetired>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().poll_ready(cx).map(|keys| keys.cloned())
    }
}

pub struct ArcKeys<K = Arc<qtls::BidirectionalKeys>>(Arc<Mutex<KeyState<K>>>);

impl<K: Clone> Future for ArcKeys<K> {
    type Output = Result<K, KeyRetired>;

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

impl<K: Clone> ArcKeys<K> {
    /// Snapshot material without registering a waiter; distinguish pending from retired.
    pub fn try_get(&self) -> Result<Option<K>, KeyRetired> {
        match &*self.0.lock().unwrap() {
            KeyState::Ready(keys) => Ok(Some(keys.clone())),
            KeyState::Pending | KeyState::Waiting(_) => Ok(None),
            KeyState::Retired => Err(KeyRetired),
        }
    }
}

impl<K> ArcKeys<K> {
    pub fn new_pending() -> Self {
        Self(Arc::new(Mutex::new(KeyState::Pending)))
    }

    pub fn install(&self, keys: K) -> Result<(), Error> {
        let mut state = self.0.lock().unwrap();
        if !matches!(*state, KeyState::Pending | KeyState::Waiting(_)) {
            return Err(QuicError::with_default_fty(
                ErrorKind::Internal,
                "keys already installed or retired",
            )
            .into());
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

/// A fixed sending generation, reserved together with its packet number.
/// No key-manager lock is held while encrypting or submitting the packet.
pub(crate) struct OneRttSealingKey {
    headers: Arc<HeaderKeys>,
    packet: qtls::PacketKey,
    generation: u64,
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
            .ok_or_else(|| {
                QuicError::with_default_fty(ErrorKind::KeyUpdate, "key generation exhausted")
            })?;
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
            return Err(QuicError::with_default_fty(
                ErrorKind::KeyUpdate,
                "local key update is not permitted",
            )
            .into());
        }
        let mut next_secret = self.next_secret.clone();
        let keys = next_secret.next_packet_keys();
        self.push(keys, next_secret)
    }

    fn prepare_sealing(&mut self) -> Result<(), PacketError> {
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
            return Err(Error::from(QuicError::with_default_fty(
                ErrorKind::AeadLimitReached,
                "packet protection confidentiality limit",
            ))
            .into());
        }
        Ok(())
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
                    return Err(QuicError::with_default_fty(
                        ErrorKind::AeadLimitReached,
                        "packet protection integrity limit",
                    )
                    .into());
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
    pub fn try_get(&self) -> Result<Option<OneRttKeys>, KeyRetired> {
        self.0.try_get()
    }

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
    type Output = Result<OneRttKeys, KeyRetired>;

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

    pub fn on_ack(&self, generation: u64) {
        let mut packets = self.packets.lock().unwrap();
        if generation != 0 && packets.keys.back().unwrap().generation == generation {
            packets.can_update = true;
        }
    }

    /// Allocate the PN while the generation is fixed, then reserve one AEAD use.
    /// The returned key remains valid across later local and peer key updates.
    pub(crate) fn reserve<T>(
        &self,
        allocate: impl FnOnce(u64) -> Result<T, PacketError>,
    ) -> Result<(T, OneRttSealingKey), PacketError> {
        let mut packets = self.packets.lock().unwrap();
        packets.prepare_sealing()?;
        let keys = packets.keys.back().unwrap();
        let allocated = allocate(keys.generation)?;
        let sealing = OneRttSealingKey {
            headers: self.headers.clone(),
            packet: keys.sealing.clone(),
            generation: keys.generation,
        };
        packets.sealed_count += 1;
        Ok((allocated, sealing))
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

    /// Protect the PN in pn_offset..body_offset and a reserved authentication tag.
    /// The caller supplies enough ciphertext/tag for a sample starting at pn_offset + 4.
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
        let sample_offset = 4 - pn_bytes.len();
        self.header.protect(
            &body_tag[sample_offset..sample_offset + self.header.sample_len()],
            &mut prefix[0],
            pn_bytes,
        )?;
        Ok(())
    }
}

impl SealPacket for OneRttKeys {
    type Output = (u64, KeyPhaseBit);

    fn seal(
        &self,
        pn: u64,
        buffer: &mut [u8],
        pn_offset: usize,
        body_offset: usize,
        tag_len: usize,
    ) -> Result<Self::Output, PacketError> {
        let (_, key) = self.reserve(|_| Ok(()))?;
        key.seal(pn, buffer, pn_offset, body_offset, tag_len)
    }
}

impl SealPacket for OneRttSealingKey {
    type Output = (u64, KeyPhaseBit);

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
        let phase = KeyPhaseBit::from(self.generation & 1 != 0);
        let mut specific_bits = ShortSpecificBits::from(header[0]);
        specific_bits.set_key_phase(phase);
        header[0] = *specific_bits;
        self.packet.seal(pn, header, body, tag)?;
        let (prefix, pn_bytes) = header.split_at_mut(pn_offset);
        let header_key = &self.headers.sealing;
        let sample_offset = 4 - pn_bytes.len();
        header_key.protect(
            &body_tag[sample_offset..sample_offset + header_key.sample_len()],
            &mut prefix[0],
            pn_bytes,
        )?;
        Ok((self.generation, phase))
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
    let (_, encoded) = take_pn_len(pn_len)(&packet.bytes[packet.offset..]).map_err(|_| {
        QuicError::with_default_fty(ErrorKind::Internal, "invalid packet-number layout")
    })?;
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
        return Err(QuicError::with_default_fty(
            ErrorKind::ProtocolViolation,
            "empty packet payload",
        )
        .into());
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
    use crate::send::{constraints::Constraints, write::Packet};

    fn ready() -> OneRttKeys {
        let ([client, _], _) = crate::tests::handshake();
        let keys = ArcOneRttKeys::new_pending();
        keys.install(client).unwrap();
        keys.now_or_never().unwrap().unwrap()
    }
    fn packet(
        pn: u64,
        keys: &OneRttKeys,
    ) -> Result<crate::send::write::PendingPacket, PacketError> {
        let mut packet = Packet::new(
            bytes::BytesMut::zeroed(1200),
            OneRttHeader::new(Default::default(), ConnectionId::default()),
            16,
        )?;
        let mut frames = Vec::new();
        packet.assemble(
            &Constraints {
                capacity: 1200,
                congestion: 1200,
                anti_amplification: 1200,
            },
            &mut frames,
            [&mut PingFrame],
        )?;
        crate::tests::seal_packet(
            packet,
            keys,
            &crate::send::records::ArcSendJournal::starting_at(pn),
            &mut frames,
        )
    }

    #[test]
    fn try_get_never_replaces_the_receive_waiter() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Wake(AtomicUsize);
        impl futures::task::ArcWake for Wake {
            fn wake_by_ref(this: &Arc<Self>) {
                this.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let keys = ArcKeys::<u64>::new_pending();
        assert_eq!(keys.try_get(), Ok(None));
        let mut receiving = keys.clone();
        let wake = Arc::new(Wake(AtomicUsize::new(0)));
        let waker = futures::task::waker(wake.clone());
        assert!(
            Pin::new(&mut receiving)
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        assert_eq!(keys.try_get(), Ok(None));
        assert_eq!(keys.try_get(), Ok(None));
        keys.install(42).unwrap();
        assert_eq!(wake.0.load(Ordering::Relaxed), 1);
        assert_eq!(keys.try_get(), Ok(Some(42)));
        assert_eq!(
            Pin::new(&mut receiving).poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Ok(42))
        );
        keys.retire();
        assert_eq!(keys.try_get(), Err(KeyRetired));
        assert_eq!(
            Pin::new(&mut receiving).poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Err(KeyRetired))
        );
    }

    #[tokio::test]
    async fn one_rtt_wait_yields_shared_material_and_reports_retirement() {
        let keys = ArcOneRttKeys::new_pending();
        assert!(matches!(keys.try_get(), Ok(None)));
        let mut waiting = keys.clone();
        assert!(futures::poll!(&mut waiting).is_pending());
        assert!(matches!(keys.try_get(), Ok(None)));
        let ([client, _], _) = crate::tests::handshake();
        keys.install(client).unwrap();
        let material = waiting.await.unwrap();
        let snapshot = keys.try_get().unwrap().unwrap();
        assert!(Arc::ptr_eq(&snapshot.packets, &material.packets));
        let shared = keys.clone().await.unwrap();
        material.allow_update();
        shared.update().unwrap();
        assert_eq!(packet(0, &material).unwrap().generation, Some(1));
        keys.retire();
        assert!(matches!(keys.try_get(), Err(KeyRetired)));
        assert!(matches!(keys.await, Err(KeyRetired)));
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
        let bytes = packet(0, &sending.now_or_never().unwrap().unwrap())
            .unwrap()
            .into_buffer();
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
    fn reserved_packet_keys_stay_bound_across_updates_and_reverse_encryption() {
        let ([client, server], _) = crate::tests::handshake();
        let material = ArcOneRttKeys::new_pending();
        material.install(client).unwrap();
        let keys = material.now_or_never().unwrap().unwrap();
        let peer = ArcOneRttKeys::new_pending();
        peer.install(server).unwrap();
        let peer = peer.now_or_never().unwrap().unwrap();
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
        let records = crate::send::records::ArcSendJournal::default();
        let ((earlier, _), old) = keys
            .reserve(|generation| records.record_pending(generation, &mut Vec::new()))
            .unwrap();
        keys.update().unwrap();
        let ((later, _), new) = keys
            .reserve(|generation| records.record_pending(generation, &mut Vec::new()))
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
            let mut forged = high.datagram.msg.clone();
            *forged.last_mut().unwrap() ^= 1;
            assert_eq!(open(&server, forged, &server_journal), None);
            assert_eq!(
                receiving
                    .packets
                    .lock()
                    .unwrap()
                    .keys
                    .back()
                    .unwrap()
                    .generation,
                server_generation
            );
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
            assert_eq!(
                sending
                    .packets
                    .lock()
                    .unwrap()
                    .keys
                    .back()
                    .unwrap()
                    .generation,
                generation
            );
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
        let mut forged = next.datagram.msg.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(open(&server, forged), None);
        assert_eq!(
            receiving
                .packets
                .lock()
                .unwrap()
                .keys
                .back()
                .unwrap()
                .generation,
            1
        );
        assert_eq!(open(&server, next.into_buffer()), Some(102));
        assert_eq!(
            receiving
                .packets
                .lock()
                .unwrap()
                .keys
                .back()
                .unwrap()
                .generation,
            2
        );
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
        assert_eq!(
            receiving
                .packets
                .lock()
                .unwrap()
                .keys
                .back()
                .unwrap()
                .generation,
            1
        );
        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(open(late_old), None);
        assert_eq!(open(packet(3, &sending).unwrap().into_buffer()), Some(3));
    }

    #[test]
    fn failed_allocation_does_not_consume_the_last_aead_use() {
        let keys = ready();
        let limit = keys
            .packets
            .lock()
            .unwrap()
            .keys
            .back()
            .unwrap()
            .sealing
            .confidentiality_limit();
        keys.packets.lock().unwrap().sealed_count = limit - 1;
        assert!(
            keys.reserve::<()>(|_| Err(PacketError::Blocked(qbase::net::tx::Signals::TRANSPORT)))
                .is_err()
        );
        keys.reserve(|_| Ok(())).unwrap();
        assert_eq!(keys.packets.lock().unwrap().sealed_count, limit);
        assert!(
            keys.reserve::<()>(|_| panic!("allocated beyond the AEAD limit"))
                .is_err()
        );
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
        assert_eq!(packet(0, &keys).unwrap().generation, Some(1));
        {
            let mut packets = keys.packets.lock().unwrap();
            packets.sealed_count = packets.keys.back().unwrap().sealing.confidentiality_limit();
        }
        assert!(
            matches!(packet(1, &keys), Err(PacketError::Connection(error)) if error.kind() == ErrorKind::AeadLimitReached)
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
        let mut forged = packet(0, &sending).unwrap().into_buffer();
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
        assert_eq!(task.await.unwrap(), Err(KeyRetired));
        assert_eq!(keys.try_get(), Err(KeyRetired));
        assert!(keys.install(()).is_err());
    }

    #[tokio::test]
    async fn retiring_pending_one_rtt_keys_wakes_the_waiter_with_key_retired() {
        let keys = ArcOneRttKeys::new_pending();
        let mut waiting = keys.clone();
        let (entered, pending) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            assert!(futures::poll!(&mut waiting).is_pending());
            entered.send(()).unwrap();
            waiting.await
        });
        pending.await.unwrap();
        keys.retire();
        assert!(matches!(keys.try_get(), Err(KeyRetired)));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap(),
            Err(KeyRetired)
        ));
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
            let Poll::Ready(Ok(keys)) = Pin::new(&mut state).poll(&mut cx) else {
                panic!()
            };
            assert!(Arc::ptr_eq(&material, &keys));
        }
        state = KeyState::Retired;
        assert_eq!(
            Pin::new(&mut state).poll(&mut cx),
            Poll::Ready(Err(KeyRetired))
        );
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
        assert_eq!(keys.await, Err(KeyRetired));
    }

    #[tokio::test]
    async fn sealing_does_not_wait_for_socket_submission() {
        let [(_client, transport, path), _] = crate::tests::pair(1);
        let keys = transport.data.keys.clone().await.unwrap();
        let mut sender = crate::tests::Sender::new(keys.clone(), transport, path).unwrap();
        sender.heartbeat();
        assert!(sender.prepare().unwrap());
        let (start, started) = std::sync::mpsc::channel();
        let (sealed, completed) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            started.recv().unwrap();
            packet(1, &keys).unwrap();
            sealed.send(()).unwrap();
        });
        assert!(matches!(
            sender.poll_send_with(
                &mut Context::from_waker(futures::task::noop_waker_ref()),
                |_, _, bytes| {
                    start.send(()).unwrap();
                    completed.recv_timeout(Duration::from_secs(1)).unwrap();
                    Poll::Ready(Ok(bytes.len()))
                },
            ),
            Poll::Ready(Ok(true))
        ));
        worker.join().unwrap();
    }
}
