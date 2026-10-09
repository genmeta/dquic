use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use qbase::{
    error::{Error, ErrorKind, QuicError},
    frame::{Frame, FrameType, GuaranteedFrame, PaddingFrame},
    packet::{
        GetType, HeaderSize, LongSpecificBits, PacketNumber, ShortSpecificBits, Type,
        WritePacketNumber,
        assemble::{Assemble, Constraints, Limit, Metadata, Package, PacketBuffer},
        header::io::WriteHeader,
    },
};

use crate::keys::Seal;

/// Header and PN are encoded at construction. The cursor counts packet bytes.
pub struct Packet<'a, H, B> {
    frames: &'a mut Vec<GuaranteedFrame>,
    pub header: H,
    pub pn: (u64, PacketNumber),
    pub buffer: B,
    cursor: usize,
    pub meta: Metadata,
    finished: bool,
}

impl<'a, H: HeaderSize + GetType, B: BufMut + WriteHeader<H>> Packet<'a, H, B> {
    pub fn new(
        header: H,
        pn: (u64, PacketNumber),
        mut buffer: B,
        frames: &'a mut Vec<GuaranteedFrame>,
    ) -> Result<Self, Error> {
        let cursor = header.size()
            + if matches!(header.get_type(), Type::Long(_)) {
                2
            } else {
                0
            }
            + pn.1.size();
        if buffer.remaining_mut() < cursor {
            return Err(layout_error());
        }
        buffer.put_header(&header);
        if matches!(header.get_type(), Type::Long(_)) {
            buffer.put_u16(0);
        }
        buffer.put_packet_number(pn.1);
        let meta = Metadata {
            pn: pn.0,
            ..Metadata::new(header.get_type())
        };
        Ok(Self {
            frames,
            header,
            pn,
            buffer,
            cursor,
            meta,
            finished: false,
        })
    }
}

impl<H: GetType, B: BufMut> Assemble for Packet<'_, H, B> {
    type Buffer = B;
    fn assemble(
        &mut self,
        cx: &mut Context<'_>,
        sources: &mut [&mut dyn Package<B>],
    ) -> Poll<Result<usize, Error>> {
        if self.finished {
            return Poll::Ready(Ok(0));
        }
        let mut limits = Constraints {
            flow_ctrl: usize::MAX,
            send_quota: usize::MAX,
            credit: usize::MAX,
            min_size: 0,
            max_size: self.cursor.saturating_add(self.buffer.remaining_mut()),
            ..Default::default()
        };
        let mut buffer = PacketBuffer::new(
            &mut self.buffer,
            &mut limits,
            self.frames,
            self.header.get_type(),
            self.cursor,
            0,
        );
        buffer.meta = self.meta;
        let result = buffer.assemble(cx, sources);
        self.finished = buffer.is_finished();
        self.cursor = buffer.written();
        self.meta = buffer.meta;
        result
    }
}

/// Protection and send limits decorate packet encoding, without owning frame records.
pub struct Envelope<'a, H, B, K> {
    pub packet: Packet<'a, H, B>,
    pub keys: &'a K,
    pub limits: &'a mut Constraints,
}

impl<H: GetType + HeaderSize, B: BufMut, K: Seal> Assemble for Envelope<'_, H, B, K> {
    type Buffer = B;
    fn assemble(
        &mut self,
        cx: &mut Context<'_>,
        sources: &mut [&mut dyn Package<B>],
    ) -> Poll<Result<usize, Error>> {
        if self.packet.finished {
            return Poll::Ready(Ok(0));
        }
        let start = self.packet.meta.nframes;
        let tag_len = self.keys.tag_len();
        let pn_offset = self.packet.cursor - self.packet.pn.1.size();
        self.limits.min_size = self
            .limits
            .min_size
            .max(pn_offset + 4 + 16 + self.limits.overhead);
        let mut buffer = PacketBuffer::new(
            &mut self.packet.buffer,
            self.limits,
            self.packet.frames,
            self.packet.header.get_type(),
            self.packet.cursor,
            tag_len,
        );
        buffer.meta = self.packet.meta;
        let result = buffer.assemble(cx, sources);
        self.packet.finished = buffer.is_finished();
        self.packet.cursor = buffer.written();
        self.packet.meta = buffer.meta;
        match result {
            Poll::Ready(Ok(n)) if n > 0 => {}
            _ => return result,
        }
        let padding = buffer.min_size().saturating_sub(buffer.written() + tag_len);
        if padding > 0 {
            let mut buffer = PacketBuffer::new(
                &mut self.packet.buffer,
                self.limits,
                self.packet.frames,
                self.packet.header.get_type(),
                self.packet.cursor,
                tag_len,
            );
            buffer.meta = self.packet.meta;
            buffer.for_frame(FrameType::Padding);
            if padding > buffer.remaining_mut() {
                return Poll::Ready(Err(layout_error()));
            }
            buffer.put_bytes(0, padding);
            buffer.record(Frame::Padding(PaddingFrame));
            self.packet.cursor = buffer.written();
            self.packet.meta = buffer.meta;
        }
        let size = self.packet.cursor + tag_len;
        self.limits
            .take(if self.packet.meta.in_flight { size } else { 0 }, size);
        Poll::Ready(Ok(self.packet.meta.nframes - start))
    }
}

fn protect<H: HeaderSize + GetType, K: Seal>(
    header: &H,
    pn: (u64, PacketNumber),
    keys: &K,
    bytes: &mut [u8],
    cursor: usize,
) -> Result<K::Output, Error> {
    let tag_len = keys.tag_len();
    let pn_offset = header.size()
        + if matches!(header.get_type(), Type::Long(_)) {
            2
        } else {
            0
        };
    let body_offset = pn_offset + pn.1.size();
    if cursor <= body_offset || bytes.len() != cursor + tag_len {
        return Err(layout_error());
    }
    bytes[0] |= if matches!(header.get_type(), Type::Long(_)) {
        *LongSpecificBits::from_pn(&pn.1)
    } else {
        *ShortSpecificBits::from_pn(&pn.1)
    };
    if matches!(header.get_type(), Type::Long(_)) {
        let length = bytes.len() - pn_offset;
        if length >= 16384 {
            return Err(layout_error());
        }
        (&mut bytes[pn_offset - 2..pn_offset]).put_u16(0x4000 | length as u16);
    }
    keys.seal(pn.0, bytes, pn_offset, body_offset, tag_len)
        .map_err(packet_error)
}

// BufMut alone does not provide a view of bytes already written. These buffers do.
macro_rules! seal_buffer {
    ($($buffer:ty),* $(,)?) => {$ (
        impl<H: HeaderSize + GetType, K: Seal> Envelope<'_, H, $buffer, K> {
            pub fn seal(&mut self) -> Result<K::Output, Error> {
                if self.packet.buffer.len() != self.packet.cursor { return Err(layout_error()); }
                self.packet.buffer.put_bytes(0, self.keys.tag_len());
                let sealed = protect(&self.packet.header, self.packet.pn, self.keys, self.packet.buffer.as_mut(), self.packet.cursor)?;
                self.packet.meta.pktlen = self.packet.buffer.len();
                Ok(sealed)
            }
        }
    )*};
}
seal_buffer!(BytesMut, &mut BytesMut, Vec<u8>, &mut Vec<u8>);

fn layout_error() -> Error {
    QuicError::with_default_fty(ErrorKind::Internal, "invalid packet layout or send limits").into()
}

fn packet_error(error: crate::keys::PacketError) -> Error {
    match error {
        crate::keys::PacketError::Connection(error) => error,
        error => QuicError::with_default_fty(ErrorKind::Internal, error.to_string()).into(),
    }
}
