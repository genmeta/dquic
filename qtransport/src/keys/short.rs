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
    packet::{DataPacket, InvalidPacketNumber, KeyPhaseBit, PacketNumber, ShortSpecificBits},
};
use tokio::time::Instant;

use super::{Open, PacketError, Seal, open_with};
use crate::Error;

/// Header protection does not change during a 1-RTT key update.
struct HeaderKeys {
    opening: qtls::HeaderProtectionKey,
    sealing: qtls::HeaderProtectionKey,
}

#[derive(Clone)]
pub struct ArcOneRttKeys {
    headers: Arc<HeaderKeys>,
    packets: Arc<Mutex<PacketKeyRing>>,
}

/// Complete packet protection keys for one fixed 1-RTT generation.
#[derive(Clone)]
pub struct ArcKeys {
    headers: Arc<HeaderKeys>,
    packets: Arc<PacketKeys>,
}

/// Bidirectional packet protection for one fixed generation.
pub struct PacketKeys {
    opening: qtls::PacketKey,
    sealing: qtls::PacketKey,
    generation: u64,
    sealed_count: AtomicU64,
}

struct PacketKeyState {
    keys: Arc<PacketKeys>,
    /// Bounds of authenticated packet numbers, not the complete acceptable range.
    received: Option<RangeInclusive<u64>>,
    expires: Option<Instant>,
}

struct PacketKeyRing {
    keys: VecDeque<PacketKeyState>,
    next_secret: qtls::Secrets,
    failed_opened: u64,
    can_update: bool,
}

impl PacketKeyRing {
    fn push(&mut self, keys: qtls::PacketKeys, next_secret: qtls::Secrets) -> Result<(), Error> {
        let generation = self
            .keys
            .back()
            .unwrap()
            .keys
            .generation
            .checked_add(1)
            .ok_or_else(|| QuicError::with_default_fty(ErrorKind::KeyUpdate, "key generation exhausted"))?;
        if self.keys.len() == 3 {
            self.keys.pop_front();
        }
        self.keys.push_back(PacketKeyState {
            keys: Arc::new(PacketKeys { opening: keys.opening, sealing: keys.sealing, generation, sealed_count: AtomicU64::new(0) }),
            received: None,
            expires: None,
        });
        self.next_secret = next_secret;
        self.can_update = false;
        Ok(())
    }

    fn update(&mut self) -> Result<(), Error> {
        if !self.can_update {
            return Err(QuicError::with_default_fty(ErrorKind::KeyUpdate, "local key update is not permitted").into());
        }
        let mut next_secret = self.next_secret.clone();
        let keys = next_secret.next_packet_keys();
        self.push(keys, next_secret)
    }

    fn prepare_sealing(&mut self) -> Result<(), PacketError> {
        let keys = &self.keys.back().unwrap().keys;
        let nearing_limit = keys.sealed_count.load(Ordering::Relaxed) >= keys.sealing.confidentiality_limit().saturating_sub(1);
        if nearing_limit && self.can_update {
            self.update()?;
        }
        let keys = &self.keys.back().unwrap().keys;
        if keys.sealed_count.load(Ordering::Relaxed) >= keys.sealing.confidentiality_limit() {
            return Err(
                Error::from(QuicError::with_default_fty(ErrorKind::AeadLimitReached, "packet protection confidentiality limit")).into()
            );
        }
        Ok(())
    }

    fn decrypt(&mut self, pn: u64, phase: KeyPhaseBit, header: &[u8], body: &mut [u8], pto: Duration) -> Result<Option<usize>, Error> {
        let now = Instant::now();
        while self.keys.front().unwrap().expires.is_some_and(|until| now >= until) {
            self.keys.pop_front();
        }
        // The latest observed generation starting at or before PN determines its lower bound.
        let mut index = self.keys.iter().rposition(|keys| keys.received.as_ref().is_some_and(|range| pn >= *range.start())).unwrap_or(0);
        let keys = &self.keys[index];
        if phase != KeyPhaseBit::from(keys.keys.generation & 1 != 0) {
            if keys.received.as_ref().is_some_and(|range| pn <= *range.end()) {
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
                    return Err(QuicError::with_default_fty(ErrorKind::AeadLimitReached, "packet protection integrity limit").into());
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
        let headers = Arc::new(HeaderKeys { opening: keys.opening_header, sealing: keys.sealing_header });
        let mut packets = VecDeque::with_capacity(3);
        packets.push_back(PacketKeyState {
            keys: Arc::new(PacketKeys {
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
            packets: Arc::new(Mutex::new(PacketKeyRing {
                keys: packets,
                next_secret: keys.next_secret,
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
        packet.decrypt_short_packet(&self.headers.opening, decode_pn, |pn, phase, header, body| {
            self.packets.lock().unwrap().decrypt(pn, phase, header, body, pto)
        })
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
    pub fn get(&self) -> Result<ArcKeys, PacketError> {
        let mut packets = self.packets.lock().unwrap();
        packets.prepare_sealing()?;
        Ok(ArcKeys { headers: self.headers.clone(), packets: packets.keys.back().unwrap().keys.clone() })
    }

    pub fn tag_len(&self) -> usize {
        self.packets.lock().unwrap().keys.back().unwrap().keys.sealing.tag_len()
    }
}

impl Seal for ArcKeys {
    type Output = (u64, KeyPhaseBit);

    fn tag_len(&self) -> usize {
        self.packets.sealing.tag_len()
    }

    fn seal(&self, pn: u64, buffer: &mut [u8], pn_offset: usize, body_offset: usize, tag_len: usize) -> Result<Self::Output, PacketError> {
        let keys = &self.packets;
        // fetch_update supports the workspace's Rust 1.88 minimum version.
        #[allow(deprecated)]
        keys.sealed_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| (count < keys.sealing.confidentiality_limit()).then(|| count + 1))
            .map_err(|_| {
                Error::from(QuicError::with_default_fty(ErrorKind::AeadLimitReached, "packet protection confidentiality limit"))
            })?;
        let tag_offset = buffer.len() - tag_len;
        let (header, body_tag) = buffer.split_at_mut(body_offset);
        let (body, tag) = body_tag.split_at_mut(tag_offset - body_offset);
        let phase = KeyPhaseBit::from(keys.generation & 1 != 0);
        let mut specific_bits = ShortSpecificBits::from(header[0]);
        specific_bits.set_key_phase(phase);
        header[0] = *specific_bits;
        keys.sealing.seal(pn, header, body, tag)?;
        let (prefix, pn_bytes) = header.split_at_mut(pn_offset);
        let header_key = &self.headers.sealing;
        let sample_offset = 4 - pn_bytes.len();
        header_key.protect(&body_tag[sample_offset..sample_offset + header_key.sample_len()], &mut prefix[0], pn_bytes)?;
        Ok((keys.generation, phase))
    }
}

impl Open for ArcOneRttKeys {
    fn open(
        &self,
        packet: DataPacket,
        decode_pn: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
        pto: Duration,
    ) -> Result<Option<(u64, FrameReader)>, Error> {
        open_with(packet, &self.headers.opening, decode_pn, |pn, first, header, body| {
            self.packets.lock().unwrap().decrypt(pn, ShortSpecificBits::from(first).key_phase(), header, body, pto)
        })
    }
}
