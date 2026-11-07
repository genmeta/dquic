//! Keys own retirement and packet protection generations.
use std::{sync::Arc, time::Duration};

use qbase::{
    error::{ErrorKind, QuicError},
    frame::FrameReader,
    packet::{
        DataHeader, DataPacket, GetPacketNumberLength, GetType, InvalidPacketNumber, LongSpecificBits, PacketNumber, ShortSpecificBits,
        number::take_pn_len,
    },
    varint::VARINT_MAX,
};

use crate::Error;

mod long;
pub mod short;

pub use long::ArcKeys;
pub use short::{ArcOneRttKeys, PacketKeys};

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
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
    fn seal(&self, pn: u64, buffer: &mut [u8], pn_offset: usize, body_offset: usize, tag_len: usize) -> Result<Self::Output, PacketError>;
}

impl<K: Seal + ?Sized> Seal for &K {
    type Output = K::Output;

    fn tag_len(&self) -> usize {
        (**self).tag_len()
    }

    fn seal(&self, pn: u64, buffer: &mut [u8], pn_offset: usize, body_offset: usize, tag_len: usize) -> Result<Self::Output, PacketError> {
        (**self).seal(pn, buffer, pn_offset, body_offset, tag_len)
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
    if packet.offset == 0 || sample_start.saturating_add(header_key.sample_len()) > packet.bytes.len() {
        return Ok(None);
    }
    let (header_pn, sample) = packet.bytes.split_at_mut(sample_start);
    let (prefix, pn_bytes) = header_pn.split_at_mut(packet.offset);
    if header_key.unprotect(&sample[..header_key.sample_len()], &mut prefix[0], pn_bytes).is_err() {
        return Ok(None);
    }
    let first = packet.bytes[0];
    let pn_len = (first & 3) + 1;
    let (_, encoded) = take_pn_len(pn_len)(&packet.bytes[packet.offset..])
        .map_err(|_| QuicError::with_default_fty(ErrorKind::Internal, "invalid packet-number layout"))?;
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
    let payload = packet.bytes.freeze().slice(body_offset..body_offset + plain_len);
    if payload.is_empty() {
        return Err(QuicError::with_default_fty(ErrorKind::ProtocolViolation, "empty packet payload").into());
    }
    Ok(Some((pn, FrameReader::new(payload, kind))))
}

pub enum Keys {
    Long(Arc<qtls::BidirectionalKeys>),
    Short(short::ArcKeys),
}

impl Seal for Keys {
    type Output = Option<u64>;

    fn tag_len(&self) -> usize {
        match self {
            Self::Long(keys) => keys.sealing.tag_len(),
            Self::Short(keys) => keys.tag_len(),
        }
    }

    fn seal(&self, pn: u64, bytes: &mut [u8], pn_offset: usize, body_offset: usize, tag_len: usize) -> Result<Self::Output, PacketError> {
        match self {
            Self::Long(keys) => keys.sealing.seal(pn, bytes, pn_offset, body_offset, tag_len).map(|()| None),
            Self::Short(keys) => keys.seal(pn, bytes, pn_offset, body_offset, tag_len).map(|(generation, _)| Some(generation)),
        }
    }
}
