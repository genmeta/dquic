use std::{
    io::Cursor,
    task::{Context, Poll},
};

use bytes::BufMut;
use qbase::{
    frame::{Frame, GuaranteedFrame, PaddingFrame},
    packet::{
        DataHeader, GetType, HeaderSize, LongSpecificBits, PacketContent, PacketNumber, ShortSpecificBits, Type,
        assemble::{Assemble, Metadata, Package, PacketBuffer},
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
        let meta = Metadata { pn: pn.0, ..Metadata::new(header.get_type()) };
        Self { header, pn, meta, keys, cursor: 0, finished: false }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assemble<'b>(
        &mut self,
        cx: &mut Context<'_>,
        datagram: &'b mut Cursor<&mut [u8]>,
        credit: usize,
        packet_content: PacketContent,
        frames: &mut Vec<GuaranteedFrame>,
        sources: &mut [&mut dyn Package<&'b mut [u8]>],
    ) -> Poll<(usize, usize)> {
        if self.finished {
            return Poll::Ready((0, 0));
        }
        let tag = self.keys.tag_len();
        let offset = datagram.position() as usize;
        let mut bytes = &mut datagram.get_mut()[offset + self.cursor..];
        let mut buffer = PacketBuffer::new(&mut bytes, credit, frames, self.header.get_type(), self.cursor, tag);
        buffer.meta = self.meta;
        buffer.scope(1200usize.saturating_sub(offset));
        if self.cursor == 0 && !buffer.begin(&self.header, self.pn.1) {
            return Poll::Ready((0, 0));
        }
        // Source owners handle connection errors; this packet has no content to send.
        let result = buffer.assemble(cx, packet_content, sources).map(|result| result.unwrap_or(0));
        if matches!(result, Poll::Ready(n) if n > 0) {
            let required = buffer.pn_offset() + 4 + 16;
            let padding = required.saturating_sub(buffer.written() + tag);
            assert!(padding <= buffer.remaining_mut(), "packet padding exceeds write window");
            if padding > 0 {
                buffer.put_bytes(0, padding);
                buffer.meta.record(&Frame::Padding(PaddingFrame));
            }
        }
        let min_size = buffer.min_size();
        self.cursor = buffer.written();
        self.meta = buffer.meta;
        self.finished = buffer.is_finished();
        result.map(|n| {
            if n > 0 {
                (self.len(), min_size)
            } else {
                (0, 0)
            }
        })
    }

    // Encoded wire size; Packet does not expose a collection API.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        if self.meta.nframes == 0 {
            0
        } else {
            self.cursor + self.keys.tag_len()
        }
    }

    pub fn padding(&mut self, bytes: &mut [u8], amount: usize) -> usize {
        assert!(self.len().saturating_add(amount) <= bytes.len(), "packet padding exceeds write window");
        if amount > 0 {
            bytes[self.cursor..self.cursor + amount].fill(0);
            self.cursor += amount;
            self.meta.record(&Frame::Padding(PaddingFrame));
        }
        amount
    }

    pub fn seal(&mut self, bytes: &mut [u8]) -> K::Output {
        let long = matches!(self.header.get_type(), Type::Long(_));
        let pn_offset = self.header.size() + if long { 2 } else { 0 };
        assert!(self.meta.nframes > 0 && bytes.len() == self.len() && bytes.len() >= pn_offset + 4 + 16, "invalid packet layout");
        bytes[0] |= if long {
            *LongSpecificBits::from_pn(&self.pn.1)
        } else {
            *ShortSpecificBits::from_pn(&self.pn.1)
        };
        if long {
            let length = bytes.len() - pn_offset;
            assert!(length < 16384, "packet length exceeds reserved length field");
            (&mut bytes[pn_offset - 2..pn_offset]).put_u16(0x4000 | length as u16);
        }
        let generation =
            self.keys.seal(self.pn.0, bytes, pn_offset, pn_offset + self.pn.1.size(), self.keys.tag_len()).expect("auto update keys");
        self.meta.pktlen = bytes.len();
        generation
    }
}
