use bytes::{BufMut, Bytes, BytesMut, buf::UninitSlice};
use qbase::{
    Epoch,
    frame::{
        self, AckFrame, ConnectionCloseFrame, CryptoFrame, EncodeSize, Frame, FrameFeature,
        FrameType, GetFrameType, PingFrame, ReliableFrame, StreamFrame, io::WriteFrame,
    },
    net::tx::Signals,
    packet::{
        GetType, HeaderSize, OneRttHeader, Package, PacketContent, Type, header::io::WriteHeader,
    },
    util::{ContinuousData, WriteData},
};

use super::constraints::Constraints;

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("packet assembly blocked: {0:?}")]
    Blocked(Signals),
    #[error("packet permission, number or generation is obsolete")]
    Stale,
    #[error(transparent)]
    Connection(#[from] crate::Error),
    #[error("frame {0:?} is not allowed in this packet")]
    IllegalFrame(FrameType),
    #[error("invalid packet layout or capacity")]
    Layout,
    #[error(transparent)]
    Crypto(#[from] qtls::CryptoError),
}

/// A sealed packet keeps its original frame ownership until socket completion.
/// It contains no borrowed source, journal lock, or buffer reference.
pub struct PendingPacket {
    pub(crate) bytes: BytesMut,
    pub pn: u64,
    pub epoch: Epoch,
    pub generation: u64,
    pub content: PacketContent,
    pub in_flight: bool,
    pub ack: Option<u64>,
    pub frames: Vec<Frame<()>>,
}

impl PendingPacket {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Call only when no bytes of this packet reached the socket. An uncertain
    /// socket outcome burns the PN and retains congestion accounting instead.
    pub fn abort(self, constraints: &mut Constraints) -> Vec<Frame<()>> {
        constraints.capacity += self.bytes.len();
        constraints.anti_amplification += self.bytes.len();
        if self.in_flight {
            constraints.congestion += self.bytes.len();
        }
        self.frames
    }
}

pub struct OneRttPacket {
    buffer: BytesMut,
    pn: u64,
    pn_offset: usize,
    body_offset: usize,
    cursor: usize,
    packet_type: Type,
    tag_len: usize,
    limit: usize,
    source_start: usize,
    source_end: usize,
    flight_limit: usize,
    reserved: usize,
    reserved_flight: usize,
    content: PacketContent,
    in_flight: bool,
    ack: Option<u64>,
    frames: Vec<Frame<()>>,
    illegal: Option<FrameType>,
}

impl OneRttPacket {
    pub fn frames(&self) -> &[Frame<()>] {
        &self.frames
    }

    pub fn new(
        mut buffer: BytesMut,
        header: OneRttHeader,
        pn: u64,
        tag_len: usize,
    ) -> Result<Self, PacketError> {
        let packet_type = header.get_type();
        let long = matches!(packet_type, Type::Long(_));
        let pn_offset = header.size() + if long { 2 } else { 0 };
        let body_offset = pn_offset + 4;
        let limit = buffer
            .len()
            .checked_sub(tag_len)
            .ok_or(PacketError::Layout)?;
        if body_offset >= limit || pn > qbase::varint::VARINT_MAX || (long && buffer.len() >= 16384)
        {
            return Err(PacketError::Layout);
        }
        let mut writer = &mut buffer[..];
        writer.put_header(&header);
        if long {
            writer.put_u16(0);
        }
        writer.put_u32(pn as u32);
        buffer[0] |= 3; // A four-byte PN also supplies a full HP sample with the tag.
        Ok(Self {
            buffer,
            pn,
            pn_offset,
            body_offset,
            cursor: body_offset,
            packet_type,
            tag_len,
            limit,
            source_start: body_offset,
            source_end: limit,
            flight_limit: 0,
            reserved: 0,
            reserved_flight: 0,
            content: PacketContent::default(),
            in_flight: false,
            ack: None,
            frames: Vec::new(),
            illegal: None,
        })
    }

    pub fn assemble<const N: usize>(
        &mut self,
        constraints: &mut Constraints,
        sources: [&mut dyn Package<Self>; N],
    ) -> Result<PacketContent, PacketError> {
        let tag = self.tag_len;
        self.limit = self
            .buffer
            .len()
            .min(
                self.reserved
                    .saturating_add(constraints.capacity.min(constraints.anti_amplification)),
            )
            .saturating_sub(tag);
        self.flight_limit = self.reserved_flight.saturating_add(constraints.congestion);
        let start = self.cursor;
        let mut blocked = Signals::empty();
        for (index, source) in sources.into_iter().enumerate() {
            // Bound earlier queues; permit one larger frame to avoid starvation.
            // The last source uses all remaining capacity.
            self.source_start = self.cursor;
            self.source_end = if index + 1 == N {
                self.limit
            } else {
                self.cursor.saturating_add(512).min(self.limit)
            };
            match source.dump(self) {
                Ok(_) => {}
                Err(signals) => blocked |= signals,
            }
            if self.illegal.is_some() {
                break;
            }
        }
        let size = if self.cursor == self.body_offset {
            0
        } else {
            self.cursor + tag
        };
        let flight = if self.in_flight { size } else { 0 };
        constraints.capacity -= size.saturating_sub(self.reserved);
        constraints.anti_amplification -= size.saturating_sub(self.reserved);
        constraints.congestion -= flight.saturating_sub(self.reserved_flight);
        self.reserved = size;
        self.reserved_flight = flight;
        if let Some(frame) = self.illegal {
            return Err(PacketError::IllegalFrame(frame));
        }
        if self.cursor == start {
            return Err(PacketError::Blocked(blocked));
        }
        Ok(self.content)
    }

    fn write<D: ContinuousData>(&mut self, frame: &Frame<D>) -> Result<PacketContent, Signals>
    where
        for<'a, 'b> &'a mut &'b mut [u8]: WriteData<D>,
    {
        let frame_type = frame.frame_type();
        if !frame.belongs_to(self.packet_type) {
            self.illegal = Some(frame_type);
            return Err(Signals::empty());
        }
        let data_len = match frame {
            Frame::Crypto(_, data) | Frame::Stream(_, data) | Frame::Datagram(_, data) => {
                data.len()
            }
            _ => 0,
        };
        let length = frame.encoding_size().saturating_add(data_len);
        let end = self.cursor.saturating_add(length);
        let content = PacketContent::from(frame_type);
        let in_flight =
            self.in_flight || content.is_ack_eliciting() || matches!(frame, Frame::Padding(_));
        if (end > self.source_end && self.cursor != self.source_start)
            || end > self.limit
            || (in_flight && end + self.tag_len > self.flight_limit)
        {
            return Err(Signals::CONGESTION);
        }
        let mut writer = &mut self.buffer[self.cursor..end];
        writer.put_frame(frame);
        assert!(
            writer.is_empty(),
            "frame encoder must match its declared size"
        );
        self.cursor = end;
        self.content += content;
        self.in_flight = in_flight;
        match frame {
            Frame::Ack(ack) => self.ack = Some(ack.largest()),
            Frame::Crypto(frame, _) => self.frames.push(Frame::Crypto(*frame, ())),
            Frame::Stream(frame, _) => self.frames.push(Frame::Stream(*frame, ())),
            Frame::PathChallenge(frame) => self.frames.push(Frame::PathChallenge(*frame)),
            Frame::PathResponse(frame) => self.frames.push(Frame::PathResponse(*frame)),
            frame => {
                if let Ok(reliable) = ReliableFrame::try_from(frame) {
                    self.frames.push(reliable.into());
                }
            }
        }
        Ok(content)
    }

    /// Padding is part of the plaintext and consumes congestion/AA credit.
    pub fn pad_to(
        &mut self,
        length: usize,
        constraints: &mut Constraints,
    ) -> Result<(), PacketError> {
        let size = self.cursor + self.tag_len;
        if length <= size {
            return Ok(());
        }
        if self.cursor == self.body_offset
            || length > self.buffer.len()
            || length - size > constraints.capacity.min(constraints.anti_amplification)
            || length.saturating_sub(self.reserved_flight) > constraints.congestion
        {
            return Err(PacketError::Blocked(Signals::CONGESTION));
        }
        self.buffer[self.cursor..length - self.tag_len].fill(0);
        constraints.capacity -= length - size;
        constraints.anti_amplification -= length - size;
        constraints.congestion -= length - self.reserved_flight;
        self.cursor = length - self.tag_len;
        self.reserved = length;
        self.reserved_flight = length;
        self.in_flight = true;
        self.content += PacketContent::from(FrameType::Padding);
        Ok(())
    }

    /// Return unsent frame descriptors to their owning sources. This also
    /// refunds the local reservation; no packet number is made reusable.
    pub fn abort(mut self, constraints: &mut Constraints) -> Vec<Frame<()>> {
        constraints.capacity += self.reserved;
        constraints.anti_amplification += self.reserved;
        constraints.congestion += self.reserved_flight;
        std::mem::take(&mut self.frames)
    }

    pub fn seal(mut self, keys: &crate::keys::ArcOneRttKeys) -> Result<PendingPacket, PacketError> {
        if self.cursor == self.body_offset || self.illegal.is_some() {
            return Err(PacketError::Layout);
        }
        keys.seal(self.pn, |header_key, packet_key, generation| {
            if packet_key.tag_len() != self.tag_len {
                return Err(PacketError::Layout);
            }
            if generation % 2 != 0 {
                self.buffer[0] |= 4;
            }
            let total = self.cursor + self.tag_len;
            let (header, body_tag) = self.buffer[..total].split_at_mut(self.body_offset);
            let (body, tag) = body_tag.split_at_mut(self.cursor - self.body_offset);
            packet_key.seal(self.pn, header, body, tag)?;
            let (header_pn, sample) = self.buffer[..total].split_at_mut(self.body_offset);
            let (prefix, pn_bytes) = header_pn.split_at_mut(self.pn_offset);
            header_key.protect(&sample[..header_key.sample_len()], &mut prefix[0], pn_bytes)?;
            self.buffer.truncate(total);
            Ok(PendingPacket {
                bytes: self.buffer,
                pn: self.pn,
                epoch: Epoch::Data,
                generation,
                content: self.content,
                in_flight: self.in_flight,
                ack: self.ack,
                frames: self.frames,
            })
        })
    }
}

// STREAM sources also write raw pre-padding. Leave room for an explicit
// STREAM length even when qrecovery selected a length-omitting encoding.
// Only the checked frame adapter may consume these eight reserved bytes.
unsafe impl BufMut for OneRttPacket {
    fn remaining_mut(&self) -> usize {
        self.source_end
            .min(self.limit)
            .min(self.flight_limit.saturating_sub(self.tag_len))
            .saturating_sub(self.cursor)
            .saturating_sub(8)
    }
    unsafe fn advance_mut(&mut self, count: usize) {
        assert!(count <= self.remaining_mut());
        assert!(
            self.buffer[self.cursor..self.cursor + count]
                .iter()
                .all(|byte| *byte == 0),
            "raw packet writes are reserved for STREAM pre-padding"
        );
        self.cursor += count;
        if count != 0 {
            self.in_flight = true;
            self.content += PacketContent::from(FrameType::Padding);
        }
    }
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        let end = self.cursor + self.remaining_mut();
        UninitSlice::new(&mut self.buffer[self.cursor..end])
    }
}

impl Package<OneRttPacket> for (CryptoFrame, &[Bytes]) {
    fn dump(&mut self, packet: &mut OneRttPacket) -> Result<PacketContent, Signals> {
        packet.write(&Frame::Crypto(self.0, self.1))
    }
}
impl Package<OneRttPacket> for AckFrame {
    fn dump(&mut self, packet: &mut OneRttPacket) -> Result<PacketContent, Signals> {
        packet.write(&Frame::<()>::Ack(self.clone()))
    }
}
impl Package<OneRttPacket> for PingFrame {
    fn dump(&mut self, packet: &mut OneRttPacket) -> Result<PacketContent, Signals> {
        packet.write(&Frame::<()>::Ping(*self))
    }
}
impl Package<OneRttPacket> for ConnectionCloseFrame {
    fn dump(&mut self, packet: &mut OneRttPacket) -> Result<PacketContent, Signals> {
        packet.write(&Frame::<()>::Close(self.clone()))
    }
}
impl Package<OneRttPacket> for (StreamFrame, &[Bytes]) {
    fn dump(&mut self, packet: &mut OneRttPacket) -> Result<PacketContent, Signals> {
        let mut frame = self.0;
        frame.set_len_bit(frame::Len::Explicit);
        packet.write(&Frame::Stream(frame, self.1))
    }
}
impl Package<OneRttPacket> for &ReliableFrame {
    fn dump(&mut self, packet: &mut OneRttPacket) -> Result<PacketContent, Signals> {
        packet.write(&Frame::<()>::from((*self).clone()))
    }
}
impl Package<OneRttPacket> for frame::PathChallengeFrame {
    fn dump(&mut self, packet: &mut OneRttPacket) -> Result<PacketContent, Signals> {
        packet.write(&Frame::<()>::PathChallenge(*self))
    }
}
impl Package<OneRttPacket> for frame::PathResponseFrame {
    fn dump(&mut self, packet: &mut OneRttPacket) -> Result<PacketContent, Signals> {
        packet.write(&Frame::<()>::PathResponse(*self))
    }
}
