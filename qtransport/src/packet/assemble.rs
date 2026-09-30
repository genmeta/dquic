use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use qbase::{
    error::{Error, ErrorKind, QuicError},
    frame::{Frame, FrameType, PaddingFrame},
    packet::{
        GetType, HeaderSize, LongSpecificBits, PacketNumber, ShortSpecificBits, Type,
        WritePacketNumber,
        assemble::{Assemble, ConstraintBuffer, Constraints, Limit, Package, in_flight},
        header::io::WriteHeader,
    },
};

use crate::keys::SealPacket;

/// Header and PN are encoded at construction. The cursor counts packet bytes.
pub struct Packet<H, B> {
    pub header: H,
    pub pn: (u64, PacketNumber),
    pub buffer: B,
    cursor: usize,
}

impl<H: HeaderSize + GetType, B: BufMut + WriteHeader<H>> Packet<H, B> {
    pub fn new(header: H, pn: (u64, PacketNumber), mut buffer: B) -> Result<Self, Error> {
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
        Ok(Self {
            header,
            pn,
            buffer,
            cursor,
        })
    }
}

impl<H: GetType, B: BufMut> Packet<H, B> {
    fn assemble_with<const N: usize>(
        &mut self,
        cx: &mut Context<'_>,
        sources: [&mut dyn Package<B>; N],
        frames: &mut Vec<Frame>,
        limits: &mut dyn Limit,
        tag_len: usize,
    ) -> Poll<Result<usize, Error>> {
        let start = frames.len();
        let mut buffer = ConstraintBuffer::new(
            &mut self.buffer,
            limits,
            self.header.get_type(),
            self.cursor,
            tag_len,
        );
        let mut result = Poll::Pending;
        for source in sources {
            match source.poll_dump(cx, &mut buffer, frames) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => result = Poll::Ready(Ok(0)),
                Poll::Pending => {}
            }
            if buffer.limits.max_size() == 0
                || frames[start..]
                    .iter()
                    .any(|frame| matches!(frame, Frame::Close(_)))
            {
                break;
            }
        }
        self.cursor = buffer.written();
        if frames.len() != start {
            Poll::Ready(Ok(frames.len() - start))
        } else {
            result
        }
    }
}

impl<H: GetType, B: BufMut, const N: usize> Assemble<N> for Packet<H, B> {
    type Buffer = B;
    fn assemble(
        &mut self,
        cx: &mut Context<'_>,
        sources: [&mut dyn Package<B>; N],
        frames: &mut Vec<Frame>,
    ) -> Poll<Result<usize, Error>> {
        let mut limits = Constraints {
            flow_ctrl: usize::MAX,
            send_quota: usize::MAX,
            credit: usize::MAX,
            min_size: 0,
            max_size: self.cursor.saturating_add(self.buffer.remaining_mut()),
            ..Default::default()
        };
        self.assemble_with(cx, sources, frames, &mut limits, 0)
    }
}

/// Protection and send limits decorate packet encoding, without owning frame records.
pub struct SendingPacket<'a, H, B, K> {
    pub packet: Packet<H, B>,
    pub keys: &'a K,
    pub limits: &'a mut Constraints,
}

impl<H: GetType + HeaderSize, B: BufMut, K: SealPacket, const N: usize> Assemble<N>
    for SendingPacket<'_, H, B, K>
{
    type Buffer = B;
    fn assemble(
        &mut self,
        cx: &mut Context<'_>,
        sources: [&mut dyn Package<B>; N],
        frames: &mut Vec<Frame>,
    ) -> Poll<Result<usize, Error>> {
        let start = frames.len();
        let tag_len = self.keys.tag_len();
        let pn_offset = self.packet.cursor - self.packet.pn.1.size();
        self.limits.min_size = self
            .limits
            .min_size
            .max(pn_offset + 4 + 16 + self.limits.overhead);
        let result = self
            .packet
            .assemble_with(cx, sources, frames, self.limits, tag_len);
        match result {
            Poll::Ready(Ok(n)) if n > 0 => {}
            _ => return result,
        }
        let padding = self
            .limits
            .min_size()
            .saturating_sub(self.packet.cursor + tag_len);
        if padding > 0 {
            let mut buffer = ConstraintBuffer::new(
                &mut self.packet.buffer,
                self.limits,
                self.packet.header.get_type(),
                self.packet.cursor,
                tag_len,
            );
            buffer.for_frame(FrameType::Padding, frames);
            if padding > buffer.remaining_mut() {
                return Poll::Ready(Err(layout_error()));
            }
            buffer.put_bytes(0, padding);
            self.packet.cursor = buffer.written();
            frames.push(Frame::Padding(PaddingFrame));
        }
        let size = self.packet.cursor + tag_len;
        self.limits
            .take(if in_flight(&frames[start..]) { size } else { 0 }, size);
        Poll::Ready(Ok(frames.len() - start))
    }
}

fn protect<H: HeaderSize + GetType, K: SealPacket>(
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
        impl<H: HeaderSize + GetType, K: SealPacket> SendingPacket<'_, H, $buffer, K> {
            pub fn seal(&mut self) -> Result<K::Output, Error> {
                if self.packet.buffer.len() != self.packet.cursor { return Err(layout_error()); }
                self.packet.buffer.put_bytes(0, self.keys.tag_len());
                protect(&self.packet.header, self.packet.pn, self.keys, self.packet.buffer.as_mut(), self.packet.cursor)
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
