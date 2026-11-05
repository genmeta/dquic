use std::task::{Context, Poll};

use bytes::BufMut;
use qbase::{
    error::{Error, ErrorKind, QuicError},
    frame::{Frame, GuaranteedFrame, PaddingFrame},
    packet::{
        DataHeader, GetType, HeaderSize, LongSpecificBits, PacketNumber, ShortSpecificBits, Type,
        assemble::{Assemble, Constraints, Metadata, Package, PacketBuffer},
    },
};

use crate::{keys::Seal, space::Keys};

/// One packet's header, fixed sending keys and encoding state. Bytes stay in the datagram.
pub struct Packet<K = Keys> {
    pub header: DataHeader,
    pub pn: (u64, PacketNumber),
    pub meta: Metadata,
    keys: K,
    cursor: usize,
    finished: bool,
}

impl<K: Seal> Packet<K> {
    pub fn new(header: DataHeader, pn: (u64, PacketNumber), keys: K) -> Self {
        let meta = Metadata {
            pn: pn.0,
            ..Metadata::new(header.get_type())
        };
        Self {
            header,
            pn,
            meta,
            keys,
            cursor: 0,
            finished: false,
        }
    }

    pub fn assemble<B: BufMut>(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &mut B,
        limits: &mut Constraints,
        frames: &mut Vec<GuaranteedFrame>,
        sources: &mut [&mut dyn Package<B>],
    ) -> Poll<Result<usize, Error>> {
        if self.finished {
            return Poll::Ready(Ok(0));
        }
        let tag = self.keys.tag_len();
        let max_size = limits.max_size.saturating_sub(limits.overhead);
        let validation_size = if limits.credit.saturating_sub(limits.overhead) >= max_size {
            max_size
        } else {
            0
        };
        let mut buffer = PacketBuffer::new(
            bytes,
            limits,
            frames,
            self.header.get_type(),
            self.cursor,
            tag,
        );
        buffer.meta = self.meta;
        buffer.scope(validation_size);
        if self.cursor == 0 && !buffer.begin(&self.header, self.pn.1, None) {
            return Poll::Ready(Ok(0));
        }
        let result = buffer.assemble(cx, sources);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            let padding = (buffer.pn_offset() + 4 + 16).saturating_sub(buffer.written() + tag);
            if padding > buffer.remaining_mut() {
                return Poll::Ready(Err(layout_error()));
            }
            if padding > 0 {
                buffer.put_bytes(0, padding);
                buffer.meta.record(&Frame::Padding(PaddingFrame));
            }
        }
        self.cursor = buffer.written();
        self.meta = buffer.meta;
        self.finished = buffer.is_finished();
        let required = buffer.min_size();
        limits.min_size = required.saturating_add(limits.overhead);
        result.map(|result| result.map(|n| if n > 0 { self.len() } else { 0 }))
    }

    pub fn len(&self) -> usize {
        if self.meta.nframes == 0 {
            0
        } else {
            self.cursor + self.keys.tag_len()
        }
    }

    pub fn padding(&mut self, bytes: &mut [u8], amount: usize) -> Result<usize, Error> {
        if self.len().saturating_add(amount) > bytes.len() {
            return Err(layout_error());
        }
        if amount > 0 {
            bytes[self.cursor..self.cursor + amount].fill(0);
            self.cursor += amount;
            self.meta.record(&Frame::Padding(PaddingFrame));
        }
        Ok(amount)
    }

    pub fn seal(&mut self, bytes: &mut [u8]) -> Result<K::Output, Error> {
        let long = matches!(self.header.get_type(), Type::Long(_));
        let pn_offset = self.header.size() + if long { 2 } else { 0 };
        if self.meta.nframes == 0 || bytes.len() != self.len() || bytes.len() < pn_offset + 4 + 16 {
            return Err(layout_error());
        }
        bytes[0] |= if long {
            *LongSpecificBits::from_pn(&self.pn.1)
        } else {
            *ShortSpecificBits::from_pn(&self.pn.1)
        };
        if long {
            let length = bytes.len() - pn_offset;
            if length >= 16384 {
                return Err(layout_error());
            }
            (&mut bytes[pn_offset - 2..pn_offset]).put_u16(0x4000 | length as u16);
        }
        let generation = self
            .keys
            .seal(
                self.pn.0,
                bytes,
                pn_offset,
                pn_offset + self.pn.1.size(),
                self.keys.tag_len(),
            )
            .map_err(packet_error)?;
        self.meta.pktlen = bytes.len();
        Ok(generation)
    }
}

fn layout_error() -> Error {
    QuicError::with_default_fty(ErrorKind::Internal, "invalid packet layout or send limits").into()
}

fn packet_error(error: crate::keys::PacketError) -> Error {
    match error {
        crate::keys::PacketError::Connection(error) => error,
        error => QuicError::with_default_fty(ErrorKind::Internal, error.to_string()).into(),
    }
}
