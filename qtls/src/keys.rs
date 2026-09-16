use std::sync::Arc;

use rustls::quic;

use crate::CryptoError;

pub struct HeaderProtectionKey(Box<dyn quic::HeaderProtectionKey>);

impl HeaderProtectionKey {
    pub(crate) fn new(key: Box<dyn quic::HeaderProtectionKey>) -> Self {
        Self(key)
    }

    pub fn sample_len(&self) -> usize {
        self.0.sample_len()
    }

    pub fn protect(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.0
            .encrypt_in_place(sample, first, packet_number)
            .map_err(|_| CryptoError::OperationFailed)
    }

    pub fn unprotect(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.0
            .decrypt_in_place(sample, first, packet_number)
            .map_err(|_| CryptoError::OperationFailed)
    }
}

#[derive(Clone)]
pub struct PacketKey(Arc<dyn quic::PacketKey>);

impl PacketKey {
    pub(crate) fn new(key: Box<dyn quic::PacketKey>) -> Self {
        Self(Arc::from(key))
    }

    pub fn tag_len(&self) -> usize {
        self.0.tag_len()
    }

    pub fn confidentiality_limit(&self) -> u64 {
        self.0.confidentiality_limit()
    }

    pub fn integrity_limit(&self) -> u64 {
        self.0.integrity_limit()
    }

    pub fn seal(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
        tag_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let expected = self.tag_len();
        if tag_out.len() != expected {
            return Err(CryptoError::InvalidTagLength {
                expected,
                actual: tag_out.len(),
            });
        }
        let tag = self
            .0
            .encrypt_in_place(packet_number, header, payload)
            .map_err(|_| CryptoError::OperationFailed)?;
        tag_out.copy_from_slice(tag.as_ref());
        Ok(())
    }

    pub fn open<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload_and_tag: &'a mut [u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        let plaintext_len = self
            .0
            .decrypt_in_place(packet_number, header, payload_and_tag)
            .map_err(|_| CryptoError::OperationFailed)?
            .len();
        Ok(&mut payload_and_tag[..plaintext_len])
    }
}

pub struct DirectionalKeys {
    pub header: HeaderProtectionKey,
    pub packet: PacketKey,
}

impl From<quic::DirectionalKeys> for DirectionalKeys {
    fn from(keys: quic::DirectionalKeys) -> Self {
        Self {
            header: HeaderProtectionKey::new(keys.header),
            packet: PacketKey::new(keys.packet),
        }
    }
}

pub struct BidirectionalKeys {
    pub opening: DirectionalKeys,
    pub sealing: DirectionalKeys,
}

impl From<quic::Keys> for BidirectionalKeys {
    fn from(keys: quic::Keys) -> Self {
        Self {
            opening: keys.remote.into(),
            sealing: keys.local.into(),
        }
    }
}

/// Packet protection keys for both directions of one generation.
pub struct PacketKeys {
    pub opening: PacketKey,
    pub sealing: PacketKey,
}

/// Secrets used to derive the next pair of packet protection keys.
#[derive(Clone)]
pub struct Secrets(Box<quic::Secrets>);

impl Secrets {
    pub fn next_packet_keys(&mut self) -> PacketKeys {
        let keys = self.0.next_packet_keys();
        PacketKeys {
            opening: PacketKey::new(keys.remote),
            sealing: PacketKey::new(keys.local),
        }
    }
}

pub struct OneRttKeyMaterial {
    pub opening_header: HeaderProtectionKey,
    pub sealing_header: HeaderProtectionKey,
    pub packet: PacketKeys,
    pub next_secret: Secrets,
}

impl OneRttKeyMaterial {
    pub(crate) fn new(keys: quic::Keys, next: quic::Secrets) -> Self {
        Self {
            opening_header: HeaderProtectionKey::new(keys.remote.header),
            sealing_header: HeaderProtectionKey::new(keys.local.header),
            packet: PacketKeys {
                opening: PacketKey::new(keys.remote.packet),
                sealing: PacketKey::new(keys.local.packet),
            },
            next_secret: Secrets(Box::new(next)),
        }
    }
}
