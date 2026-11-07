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
    packet::{KeyPhaseBit, ShortSpecificBits},
};
use tokio::time::Instant;

use super::{Open, PacketError, Seal, open, seal};
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
    next: Option<(Arc<PacketKeys>, qtls::Secrets)>,
    can_update: bool,
}

impl PacketKeyRing {
    fn next(&mut self) -> Result<Arc<PacketKeys>, Error> {
        if let Some((keys, _)) = &self.next {
            return Ok(keys.clone());
        }
        let generation = self
            .keys
            .back()
            .unwrap()
            .keys
            .generation
            .checked_add(1)
            .ok_or_else(|| QuicError::with_default_fty(ErrorKind::KeyUpdate, "key generation exhausted"))?;
        let mut secret = self.next_secret.clone();
        let keys = secret.next_packet_keys();
        let keys = Arc::new(PacketKeys { opening: keys.opening, sealing: keys.sealing, generation, sealed_count: AtomicU64::new(0) });
        self.next = Some((keys.clone(), secret));
        Ok(keys)
    }

    fn push_next(&mut self) {
        let (keys, secret) = self.next.take().unwrap();
        if self.keys.len() == 3 {
            self.keys.pop_front();
        }
        self.keys.push_back(PacketKeyState { keys, received: None, expires: None });
        self.next_secret = secret;
        self.can_update = false;
    }

    fn update(&mut self) -> Result<(), Error> {
        if !self.can_update {
            return Err(QuicError::with_default_fty(ErrorKind::KeyUpdate, "local key update is not permitted").into());
        }
        self.next()?;
        self.push_next();
        Ok(())
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

    fn opening(&mut self, pn: u64, phase: KeyPhaseBit) -> Result<Option<Arc<PacketKeys>>, Error> {
        let now = Instant::now();
        while self.keys.len() > 1 && self.keys.front().unwrap().expires.is_some_and(|until| now >= until) {
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
        if index == self.keys.len() {
            self.next().map(Some)
        } else {
            let state = &self.keys[index];
            // PTO can shrink between updates, so expiry is not necessarily in queue order.
            Ok((!state.expires.is_some_and(|until| now >= until)).then(|| state.keys.clone()))
        }
    }

    fn on_opened(&mut self, pn: u64, keys: &Arc<PacketKeys>, pto: Duration) {
        // A concurrent local update may already have installed this same candidate.
        if self.next.as_ref().is_some_and(|(next, _)| Arc::ptr_eq(next, keys)) {
            self.push_next();
        }
        let Some(index) = self.keys.iter().position(|state| Arc::ptr_eq(&state.keys, keys)) else {
            // A selected operation can finish after eviction, without restoring old keys.
            return;
        };
        let now = Instant::now();
        for older in self.keys.iter_mut().take(index) {
            older.expires.get_or_insert(now + pto.saturating_mul(3));
        }
        let received = &mut self.keys[index].received;
        *received = Some(match received {
            Some(range) => (*range.start()).min(pn)..=(*range.end()).max(pn),
            None => pn..=pn,
        });
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
            packets: Arc::new(Mutex::new(PacketKeyRing { keys: packets, next_secret: keys.next_secret, next: None, can_update: false })),
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
    /// Header protection is fixed for the lifetime of the Data space.
    pub fn opening_header(&self) -> &qtls::HeaderProtectionKey {
        &self.headers.opening
    }

    /// Select opening keys without advancing the authenticated generation.
    pub fn opening_packet(&self, pn: u64, phase: KeyPhaseBit) -> Result<Option<ArcKeys>, PacketError> {
        Ok(self.packets.lock().unwrap().opening(pn, phase)?.map(|packets| ArcKeys { headers: self.headers.clone(), packets }))
    }

    /// Commit a selected generation only after successful authentication.
    pub fn on_opened(&self, pn: u64, keys: &ArcKeys, pto: Duration) -> Result<(), PacketError> {
        if !Arc::ptr_eq(&self.headers, &keys.headers) {
            return Err(PacketError::Layout);
        }
        self.packets.lock().unwrap().on_opened(pn, &keys.packets, pto);
        Ok(())
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
    pub fn sealing_keys(&self) -> Result<ArcKeys, PacketError> {
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
        if tag_len != self.tag_len() {
            return Err(PacketError::Layout);
        }
        let pn_len = body_offset.checked_sub(pn_offset).ok_or(PacketError::Layout)?;
        let first = buffer.first_mut().ok_or(PacketError::Layout)?;
        let phase = KeyPhaseBit::from(keys.generation & 1 != 0);
        let mut specific_bits = ShortSpecificBits::from(*first);
        specific_bits.set_key_phase(phase);
        *first = *specific_bits;
        seal::body(&keys.sealing, pn, buffer, body_offset)?;
        seal::header(&self.headers.sealing, buffer, pn_offset, pn_len)?;
        Ok((keys.generation, phase))
    }
}

impl Open for ArcKeys {
    fn integrity_limit(&self) -> u64 {
        self.packets.opening.integrity_limit()
    }

    fn open(&self, pn: u64, buffer: &mut [u8], body_offset: usize) -> Result<usize, PacketError> {
        open::body(&self.packets.opening, pn, buffer, body_offset)
    }
}
