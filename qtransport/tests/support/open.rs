//! Test-side receive orchestration built solely from the staged public APIs.
#![allow(dead_code)]
use std::time::Duration;

use qbase::{
    error::{ErrorKind, QuicError},
    frame::FrameReader,
    packet::{DataPacket, GetPacketNumberLength, GetType, InvalidPacketNumber, LongSpecificBits, PacketNumber, ShortSpecificBits},
};
use qtransport::{
    Error,
    keys::{ArcOneRttKeys, Open, PacketError, open},
    packet::{CipherPacket, LogPacketHeader, PlainPacket},
};

fn key_error(error: PacketError) -> Error {
    match error {
        PacketError::Connection(error) => error,
        error => QuicError::with_default_fty(ErrorKind::Internal, error.to_string()).into(),
    }
}

pub trait PacketOpen<H> {
    fn open_long(
        self,
        keys: &qtls::DirectionalKeys,
        decode: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
    ) -> Option<Result<PlainPacket<H>, QuicError>>;
}

impl<H: LogPacketHeader> PacketOpen<H> for CipherPacket<H> {
    fn open_long(
        self,
        keys: &qtls::DirectionalKeys,
        decode: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
    ) -> Option<Result<PlainPacket<H>, QuicError>> {
        let (header, mut buffer, offset) = self.split();
        let encoded = open::header(&keys.header, &mut buffer, offset).ok()?;
        let pn = decode(encoded).ok()?;
        let len = keys.open(pn, &mut buffer, offset + encoded.size()).ok()?;
        if let Err(error) = LongSpecificBits::from(buffer[0]).pn_len() {
            return Some(Err(error.into()));
        }
        if len == 0 {
            return Some(Err(QuicError::with_default_fty(ErrorKind::ProtocolViolation, "empty packet payload")));
        }
        Some(Ok(PlainPacket::new(header, pn, encoded, buffer.freeze(), offset, len)))
    }
}

pub trait ShortOpen {
    fn open_packet<H: LogPacketHeader>(
        &self,
        packet: CipherPacket<H>,
        decode: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
        pto: Duration,
    ) -> Result<Option<PlainPacket<H>>, Error>;
}

impl ShortOpen for ArcOneRttKeys {
    fn open_packet<H: LogPacketHeader>(
        &self,
        packet: CipherPacket<H>,
        decode: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
        pto: Duration,
    ) -> Result<Option<PlainPacket<H>>, Error> {
        let (header, mut buffer, offset) = packet.split();
        let Ok(encoded) = open::header(self.opening_header(), &mut buffer, offset) else {
            return Ok(None);
        };
        let Ok(pn) = decode(encoded) else {
            return Ok(None);
        };
        let bits = ShortSpecificBits::from(buffer[0]);
        let Some(keys) = self.opening_packet(pn, bits.key_phase()).map_err(key_error)? else {
            return Ok(None);
        };
        let len = match keys.open(pn, &mut buffer, offset + encoded.size()) {
            Ok(len) => len,
            Err(PacketError::AuthenticationFailed | PacketError::Layout) => return Ok(None),
            Err(error) => return Err(key_error(error)),
        };
        self.on_opened(pn, &keys, pto).map_err(key_error)?;
        bits.pn_len().map_err(QuicError::from)?;
        if len == 0 {
            return Err(QuicError::with_default_fty(ErrorKind::ProtocolViolation, "empty packet payload").into());
        }
        Ok(Some(PlainPacket::new(header, pn, encoded, buffer.freeze(), offset, len)))
    }
}

pub trait DataOpen {
    fn open_data(
        &self,
        packet: DataPacket,
        decode: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
        pto: Duration,
    ) -> Result<Option<(u64, FrameReader)>, Error>;
}

impl DataOpen for ArcOneRttKeys {
    fn open_data(
        &self,
        packet: DataPacket,
        decode: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
        pto: Duration,
    ) -> Result<Option<(u64, FrameReader)>, Error> {
        let mut packet = packet;
        let Ok(encoded) = open::header(self.opening_header(), &mut packet.bytes, packet.offset) else {
            return Ok(None);
        };
        let Ok(pn) = decode(encoded) else {
            return Ok(None);
        };
        let bits = ShortSpecificBits::from(packet.bytes[0]);
        let Some(keys) = self.opening_packet(pn, bits.key_phase()).map_err(key_error)? else {
            return Ok(None);
        };
        let body_offset = packet.offset + encoded.size();
        let len = match keys.open(pn, &mut packet.bytes, body_offset) {
            Ok(len) => len,
            Err(PacketError::AuthenticationFailed | PacketError::Layout) => return Ok(None),
            Err(error) => return Err(key_error(error)),
        };
        self.on_opened(pn, &keys, pto).map_err(key_error)?;
        bits.pn_len().map_err(QuicError::from)?;
        if len == 0 {
            return Err(QuicError::with_default_fty(ErrorKind::ProtocolViolation, "empty packet payload").into());
        }
        let kind = packet.get_type();
        Ok(Some((pn, FrameReader::new(packet.bytes.freeze().slice(body_offset..body_offset + len), kind))))
    }
}

impl DataOpen for qtls::DirectionalKeys {
    fn open_data(
        &self,
        packet: DataPacket,
        decode: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
        _pto: Duration,
    ) -> Result<Option<(u64, FrameReader)>, Error> {
        let mut packet = packet;
        let Ok(encoded) = open::header(&self.header, &mut packet.bytes, packet.offset) else {
            return Ok(None);
        };
        let Ok(pn) = decode(encoded) else {
            return Ok(None);
        };
        let body_offset = packet.offset + encoded.size();
        let len = match self.open(pn, &mut packet.bytes, body_offset) {
            Ok(len) => len,
            Err(PacketError::AuthenticationFailed | PacketError::Layout) => return Ok(None),
            Err(error) => return Err(key_error(error)),
        };
        LongSpecificBits::from(packet.bytes[0]).pn_len().map_err(QuicError::from)?;
        if len == 0 {
            return Err(QuicError::with_default_fty(ErrorKind::ProtocolViolation, "empty packet payload").into());
        }
        let kind = packet.get_type();
        Ok(Some((pn, FrameReader::new(packet.bytes.freeze().slice(body_offset..body_offset + len), kind))))
    }
}
