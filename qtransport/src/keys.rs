//! Keys own retirement and packet protection generations.
use std::{
    collections::VecDeque,
    ops::RangeInclusive,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
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

use crate::Error;

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error(transparent)]
    Retired(#[from] KeyRetired),
    #[error(transparent)]
    Connection(#[from] crate::Error),
    #[error("invalid packet layout or capacity")]
    Layout,
    #[error(transparent)]
    Crypto(#[from] qtls::CryptoError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("keys retired")]
pub struct KeyRetired;

pub struct ArcKeys<K = Arc<qtls::BidirectionalKeys>>(Arc<Mutex<Result<K, KeyRetired>>>);

impl<K> Clone for ArcKeys<K> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<K: Clone> ArcKeys<K> {
    pub fn get(&self) -> Result<K, KeyRetired> {
        self.0.lock().unwrap().clone()
    }
}

impl<K> ArcKeys<K> {
    pub fn new(keys: K) -> Self {
        Self(Arc::new(Mutex::new(Ok(keys))))
    }

    pub fn retire(&self) {
        *self.0.lock().unwrap() = Err(KeyRetired);
    }
}

impl From<qtls::InstalledKeys> for ArcKeys {
    fn from(keys: qtls::InstalledKeys) -> Self {
        let qtls::InstalledKeys::Handshake(keys) = keys else {
            unreachable!("expected TLS Handshake keys");
        };
        Self::new(Arc::new(keys))
    }
}

/// Header protection does not change during a 1-RTT key update.
pub struct HeaderKeys {
    pub opening: qtls::HeaderProtectionKey,
    pub sealing: qtls::HeaderProtectionKey,
}

#[derive(Clone)]
pub struct ArcOneRttKeys {
    pub headers: Arc<HeaderKeys>,
    packets: Arc<Mutex<OneRttPacketKeys>>,
}

/// Bidirectional packet protection for one fixed generation.
pub struct OneRttKeys {
    pub headers: Arc<HeaderKeys>,
    pub opening: qtls::PacketKey,
    pub sealing: qtls::PacketKey,
    pub generation: u64,
    sealed_count: AtomicU64,
}

struct PacketKeys {
    keys: Arc<OneRttKeys>,
    /// Bounds of authenticated packet numbers, not the complete acceptable range.
    received: Option<RangeInclusive<u64>>,
    expires: Option<Instant>,
}

struct OneRttPacketKeys {
    keys: VecDeque<PacketKeys>,
    next_secret: qtls::Secrets,
    retired: bool,
    failed_opened: u64,
    can_update: bool,
}

impl OneRttPacketKeys {
    fn push(&mut self, keys: qtls::PacketKeys, next_secret: qtls::Secrets) -> Result<(), Error> {
        let generation = self
            .keys
            .back()
            .unwrap()
            .keys
            .generation
            .checked_add(1)
            .ok_or_else(|| {
                QuicError::with_default_fty(ErrorKind::KeyUpdate, "key generation exhausted")
            })?;
        if self.keys.len() == 3 {
            self.keys.pop_front();
        }
        self.keys.push_back(PacketKeys {
            keys: Arc::new(OneRttKeys {
                headers: self.keys.back().unwrap().keys.headers.clone(),
                opening: keys.opening,
                sealing: keys.sealing,
                generation,
                sealed_count: AtomicU64::new(0),
            }),
            received: None,
            expires: None,
        });
        self.next_secret = next_secret;
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
        let keys = &self.keys.back().unwrap().keys;
        let nearing_limit = keys.sealed_count.load(Ordering::Relaxed)
            >= keys.sealing.confidentiality_limit().saturating_sub(1);
        if nearing_limit && self.can_update {
            self.update()?;
        }
        let keys = &self.keys.back().unwrap().keys;
        if keys.sealed_count.load(Ordering::Relaxed) >= keys.sealing.confidentiality_limit() {
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
        if self.retired {
            return Ok(None);
        }
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
        if phase != KeyPhaseBit::from(keys.keys.generation & 1 != 0) {
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
            None => &self.keys[index].keys.opening,
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

impl From<qtls::OneRttKeyMaterial> for ArcOneRttKeys {
    fn from(keys: qtls::OneRttKeyMaterial) -> Self {
        let headers = Arc::new(HeaderKeys {
            opening: keys.opening_header,
            sealing: keys.sealing_header,
        });
        let mut packets = VecDeque::with_capacity(3);
        packets.push_back(PacketKeys {
            keys: Arc::new(OneRttKeys {
                headers: headers.clone(),
                opening: keys.packet.opening,
                sealing: keys.packet.sealing,
                generation: 0,
                sealed_count: AtomicU64::new(0),
            }),
            received: None,
            expires: None,
        });
        Self {
            headers,
            packets: Arc::new(Mutex::new(OneRttPacketKeys {
                keys: packets,
                next_secret: keys.next_secret,
                retired: false,
                failed_opened: 0,
                can_update: false,
            })),
        }
    }
}

impl From<qtls::InstalledKeys> for ArcOneRttKeys {
    fn from(keys: qtls::InstalledKeys) -> Self {
        let qtls::InstalledKeys::OneRtt(keys) = keys else {
            unreachable!("expected TLS 1-RTT keys");
        };
        Self::from(keys)
    }
}

impl ArcOneRttKeys {
    pub fn open_packet<H>(
        &self,
        packet: crate::packet::CipherPacket<H>,
        decode_pn: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
        pto: Duration,
    ) -> Result<Option<crate::packet::PlainPacket<H>>, Error>
    where
        H: crate::packet::LogPacketHeader,
    {
        packet.decrypt_short_packet(
            &self.headers.opening,
            decode_pn,
            |pn, phase, header, body| {
                self.packets
                    .lock()
                    .unwrap()
                    .decrypt(pn, phase, header, body, pto)
            },
        )
    }

    /// Allow the first local update when qconnection confirms the handshake.
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
        if generation != 0 && packets.keys.back().unwrap().keys.generation == generation {
            packets.can_update = true;
        }
    }

    /// Select a fixed generation. The caller serializes this with PN allocation.
    pub fn get(&self) -> Result<Arc<OneRttKeys>, PacketError> {
        let mut packets = self.packets.lock().unwrap();
        if packets.retired {
            return Err(KeyRetired.into());
        }
        packets.prepare_sealing()?;
        Ok(packets.keys.back().unwrap().keys.clone())
    }

    pub fn retire(&self) {
        self.packets.lock().unwrap().retired = true;
    }

    pub fn is_retired(&self) -> bool {
        self.packets.lock().unwrap().retired
    }

    pub fn tag_len(&self) -> usize {
        self.packets
            .lock()
            .unwrap()
            .keys
            .back()
            .unwrap()
            .keys
            .sealing
            .tag_len()
    }
}

/// Remove packet protection and decode its packet number.
pub trait Open {
    /// PTO determines old 1-RTT key retention; fixed directional keys ignore it.
    fn open(
        &self,
        packet: DataPacket,
        decode_pn: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
        pto: Duration,
    ) -> Result<Option<(u64, FrameReader)>, Error>;
}

/// Protect an assembled packet in place.
pub trait Seal {
    /// Fixed keys return (); 1-RTT keys return the sending generation and Key Phase.
    type Output;

    fn tag_len(&self) -> usize;

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

impl Open for qtls::DirectionalKeys {
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

impl Seal for qtls::DirectionalKeys {
    type Output = ();

    fn tag_len(&self) -> usize {
        self.packet.tag_len()
    }

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

impl Seal for OneRttKeys {
    type Output = (u64, KeyPhaseBit);

    fn tag_len(&self) -> usize {
        self.sealing.tag_len()
    }

    fn seal(
        &self,
        pn: u64,
        buffer: &mut [u8],
        pn_offset: usize,
        body_offset: usize,
        tag_len: usize,
    ) -> Result<Self::Output, PacketError> {
        // fetch_update supports the workspace's Rust 1.88 minimum version.
        #[allow(deprecated)]
        self.sealed_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < self.sealing.confidentiality_limit()).then(|| count + 1)
            })
            .map_err(|_| {
                Error::from(QuicError::with_default_fty(
                    ErrorKind::AeadLimitReached,
                    "packet protection confidentiality limit",
                ))
            })?;
        let tag_offset = buffer.len() - tag_len;
        let (header, body_tag) = buffer.split_at_mut(body_offset);
        let (body, tag) = body_tag.split_at_mut(tag_offset - body_offset);
        let phase = KeyPhaseBit::from(self.generation & 1 != 0);
        let mut specific_bits = ShortSpecificBits::from(header[0]);
        specific_bits.set_key_phase(phase);
        header[0] = *specific_bits;
        self.sealing.seal(pn, header, body, tag)?;
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

impl Open for ArcOneRttKeys {
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
