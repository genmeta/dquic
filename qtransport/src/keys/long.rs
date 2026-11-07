use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use qbase::{
    frame::FrameReader,
    packet::{DataPacket, InvalidPacketNumber, PacketNumber},
};

use super::{KeyRetired, Open, PacketError, Seal, open_with};
use crate::Error;

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
    fn open(
        &self,
        packet: DataPacket,
        decode_pn: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
        _pto: Duration,
    ) -> Result<Option<(u64, FrameReader)>, Error> {
        open_with(packet, &self.header, decode_pn, |pn, _, header, body| {
            Ok(self.packet.open(pn, header, body).ok().map(|plain| plain.len()))
        })
    }
}

impl Seal for qtls::DirectionalKeys {
    type Output = ();

    fn tag_len(&self) -> usize {
        self.packet.tag_len()
    }

    fn seal(&self, pn: u64, buffer: &mut [u8], pn_offset: usize, body_offset: usize, tag_len: usize) -> Result<Self::Output, PacketError> {
        let tag_offset = buffer.len() - tag_len;
        let (header, body_tag) = buffer.split_at_mut(body_offset);
        let (body, tag) = body_tag.split_at_mut(tag_offset - body_offset);
        self.packet.seal(pn, header, body, tag)?;
        let (prefix, pn_bytes) = header.split_at_mut(pn_offset);
        let sample_offset = 4 - pn_bytes.len();
        self.header.protect(&body_tag[sample_offset..sample_offset + self.header.sample_len()], &mut prefix[0], pn_bytes)?;
        Ok(())
    }
}
