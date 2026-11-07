use std::sync::{Arc, Mutex};

use super::{KeyRetired, Open, PacketError, Seal, open, seal};

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

impl Open for qtls::DirectionalKeys {
    fn integrity_limit(&self) -> u64 {
        self.packet.integrity_limit()
    }

    fn open(&self, pn: u64, buffer: &mut [u8], body_offset: usize) -> Result<usize, PacketError> {
        open::body(&self.packet, pn, buffer, body_offset)
    }
}

impl Seal for qtls::DirectionalKeys {
    type Output = ();

    fn tag_len(&self) -> usize {
        self.packet.tag_len()
    }

    fn seal(&self, pn: u64, buffer: &mut [u8], pn_offset: usize, body_offset: usize, tag_len: usize) -> Result<Self::Output, PacketError> {
        if tag_len != self.tag_len() {
            return Err(PacketError::Layout);
        }
        let pn_len = body_offset.checked_sub(pn_offset).ok_or(PacketError::Layout)?;
        seal::body(&self.packet, pn, buffer, body_offset)?;
        seal::header(&self.header, buffer, pn_offset, pn_len)
    }
}
