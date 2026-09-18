use bytes::{Buf, BufMut, Bytes, BytesMut, buf::UninitSlice};
use qbase::{
    frame::{
        self, AckFrame, ConnectionCloseFrame, CryptoFrame, EncodeSize, Frame, FrameType,
        GetFrameType, PingFrame, ReliableFrame, StreamFrame, io::WriteFrame,
    },
    net::tx::Signals,
    packet::{
        HeaderSize, OneRttHeader, Package, PacketContent, PacketNumber, ShortSpecificBits,
        WritePacketNumber, header::io::WriteHeader,
    },
    util::{Buffer, WriteData},
};

use super::{constraints::Constraints, records::ArcSendJournal};
use crate::keys::SealPacket;

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("packet assembly blocked: {0:?}")]
    Blocked(Signals),
    #[error(transparent)]
    Connection(#[from] crate::Error),
    #[error("invalid packet layout or capacity")]
    Layout,
    #[error(transparent)]
    Crypto(#[from] qtls::CryptoError),
}

/// Sealed bytes and submission metadata; recovery frames belong to ArcSendJournal.
/// It contains no borrowed source, journal lock, or buffer reference.
pub struct PendingPacket {
    pub(crate) bytes: BytesMut,
    pub pn: u64,
    pub generation: u64,
    pub content: PacketContent,
    pub in_flight: bool,
    pub largest_acked: Option<u64>,
}

impl PendingPacket {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Packet encoding state and its owned buffer.
pub struct OneRttPacket {
    buffer: BytesMut,
    padded_to: usize,
    body_offset: usize,
    cursor: usize,
    tag_len: usize,
    content: PacketContent,
    in_flight: bool,
    largest_acked: Option<u64>,
}

impl OneRttPacket {
    /// Assemble frames with four bytes reserved for the eventual packet number.
    pub fn new(
        mut buffer: BytesMut,
        header: OneRttHeader,
        tag_len: usize,
    ) -> Result<Self, PacketError> {
        let body_offset = header.size() + 4;
        let limit = buffer
            .len()
            .checked_sub(tag_len)
            .ok_or(PacketError::Layout)?;
        if body_offset >= limit {
            return Err(PacketError::Layout);
        }
        let mut writer = &mut buffer[..];
        writer.put_header(&header);
        writer.put_packet_number(PacketNumber::U32(0));
        Ok(Self {
            buffer,
            padded_to: 0,
            body_offset,
            cursor: body_offset,
            tag_len,
            content: PacketContent::default(),
            in_flight: false,
            largest_acked: None,
        })
    }

    pub fn assemble<'a, const N: usize>(
        &'a mut self,
        constraints: &'a Constraints,
        records: &'a mut Vec<Frame<()>>,
        sources: [&mut dyn Package<PacketWriter<'a>>; N],
    ) -> Result<PacketContent, PacketError> {
        let start = self.cursor;
        let mut writer = PacketWriter::new(self, constraints, records);
        let mut blocked = Signals::empty();
        for source in sources {
            match source.dump(&mut writer) {
                Ok(_) => {}
                Err(signals) => blocked |= signals,
            }
        }
        if writer.packet.cursor == start {
            return Err(PacketError::Blocked(blocked));
        }
        Ok(writer.packet.content)
    }

    /// Padding makes the entire packet count toward the congestion limit.
    pub fn pad_to(&mut self, length: usize, constraints: &Constraints) -> Result<(), PacketError> {
        let size = self.cursor + self.tag_len;
        // The actual PN may reclaim two bytes of headroom. A requested length
        // above that minimum can require padding even if it fits the current layout.
        if length <= size.saturating_sub(2) {
            self.padded_to = self.padded_to.max(length);
            return Ok(());
        }
        if self.cursor == self.body_offset
            || length > self.buffer.len()
            || length > constraints.capacity.min(constraints.anti_amplification)
            || length > constraints.congestion
        {
            return Err(PacketError::Blocked(Signals::CONGESTION));
        }
        if length > size {
            self.buffer[self.cursor..length - self.tag_len].fill(0);
            self.cursor = length - self.tag_len;
            self.in_flight = true;
            self.content += PacketContent::from(FrameType::Padding);
        }
        self.padded_to = self.padded_to.max(length);
        Ok(())
    }

    pub(crate) fn into_buffer(self) -> BytesMut {
        self.buffer
    }

    /// Allocate PN and its immutable sealing key only after frames are assembled.
    pub fn seal(
        mut self,
        keys: &crate::keys::OneRttKeys,
        journal: &ArcSendJournal,
        records: &mut Vec<Frame<()>>,
    ) -> Result<PendingPacket, PacketError> {
        if self.cursor == self.body_offset {
            return Err(PacketError::Layout);
        }
        let ((pn, encoded_pn), key) =
            keys.reserve(|generation| journal.record_pending(generation, records))?;
        let pn_offset = self.body_offset - 4;
        let shift = 4 - encoded_pn.size();
        // Move only the short header; the frame bytes stay at their original offsets.
        self.buffer.copy_within(..pn_offset, shift);
        self.buffer[shift] |= *ShortSpecificBits::from_pn(&encoded_pn);
        (&mut self.buffer[pn_offset + shift..self.body_offset]).put_packet_number(encoded_pn);
        let total = (self.cursor + self.tag_len).max(self.padded_to + shift);
        if total > self.cursor + self.tag_len {
            self.in_flight = true;
            self.content += PacketContent::from(FrameType::Padding);
        }
        self.buffer.resize(total, 0);
        self.buffer[self.cursor..total - self.tag_len].fill(0);
        let result = key.seal(
            pn,
            &mut self.buffer[shift..],
            pn_offset,
            self.body_offset - shift,
            self.tag_len,
        );
        let (generation, _) = match result {
            Ok(sealed) => sealed,
            Err(error) => {
                journal.cancel_pending(pn, records);
                return Err(error);
            }
        };
        self.buffer.advance(shift);
        Ok(PendingPacket {
            bytes: self.buffer,
            pn,
            generation,
            content: self.content,
            in_flight: self.in_flight,
            largest_acked: self.largest_acked,
        })
    }
}

/// A packet write target with borrowed limits and reusable recovery records.
pub struct PacketWriter<'a> {
    packet: &'a mut OneRttPacket,
    constraints: &'a Constraints,
    records: &'a mut Vec<Frame<()>>,
}

impl<'a> PacketWriter<'a> {
    pub fn new(
        packet: &'a mut OneRttPacket,
        constraints: &'a Constraints,
        records: &'a mut Vec<Frame<()>>,
    ) -> Self {
        Self {
            packet,
            constraints,
            records,
        }
    }

    fn write<D: Buffer>(&mut self, frame: &Frame<D>) -> Result<PacketContent, Signals>
    where
        for<'b, 'c> &'b mut &'c mut [u8]: WriteData<D>,
    {
        let packet = &mut self.packet;
        let constraints = self.constraints;
        let frame_type = frame.frame_type();
        let data_len = match frame {
            Frame::Crypto(_, data) | Frame::Stream(_, data) | Frame::Datagram(_, data) => {
                data.len()
            }
            _ => 0,
        };
        let length = frame.encoding_size().saturating_add(data_len);
        let end = packet.cursor.saturating_add(length);
        // PacketNumber::encode uses at least two bytes. Budget HP padding for that
        // shortest encoding before allocating the PN (the remaining two bytes are headroom).
        let padded_end = end.max((packet.body_offset + 18).saturating_sub(packet.tag_len));
        let content = PacketContent::from(frame_type);
        let in_flight = packet.in_flight
            || content.is_ack_eliciting()
            || matches!(frame, Frame::Padding(_))
            || padded_end != end;
        let size = padded_end + packet.tag_len;
        if size
            > packet
                .buffer
                .len()
                .min(constraints.capacity)
                .min(constraints.anti_amplification)
            || (in_flight && size > constraints.congestion)
        {
            return Err(Signals::CONGESTION);
        }
        let mut writer = &mut packet.buffer[packet.cursor..end];
        writer.put_frame(frame);
        assert!(
            writer.is_empty(),
            "frame encoder must match its declared size"
        );
        packet.buffer[end..padded_end].fill(0);
        packet.cursor = padded_end;
        packet.content += content;
        packet.in_flight = in_flight;
        match frame {
            Frame::Ack(ack) => packet.largest_acked = Some(ack.largest()),
            Frame::Crypto(frame, _) => self.records.push(Frame::Crypto(*frame, ())),
            Frame::Stream(frame, _) => self.records.push(Frame::Stream(*frame, ())),
            Frame::PathChallenge(frame) => self.records.push(Frame::PathChallenge(*frame)),
            Frame::PathResponse(frame) => self.records.push(Frame::PathResponse(*frame)),
            frame => {
                if let Ok(reliable) = ReliableFrame::try_from(frame) {
                    self.records.push(reliable.into());
                }
            }
        }
        Ok(content)
    }
}

// Raw writes are STREAM pre-padding; data sources see the constrained capacity.
unsafe impl BufMut for PacketWriter<'_> {
    fn remaining_mut(&self) -> usize {
        // Sources may omit STREAM's length; reserve room to encode it explicitly.
        self.packet
            .buffer
            .len()
            .min(self.constraints.capacity)
            .min(self.constraints.anti_amplification)
            .min(self.constraints.congestion)
            .saturating_sub(self.packet.cursor + self.packet.tag_len)
            .saturating_sub(qbase::varint::VarInt::MAX_SIZE)
    }
    unsafe fn advance_mut(&mut self, count: usize) {
        assert!(count <= self.remaining_mut());
        assert!(
            self.packet.buffer[self.packet.cursor..self.packet.cursor + count]
                .iter()
                .all(|byte| *byte == 0),
            "raw packet writes are reserved for STREAM pre-padding"
        );
        self.packet.cursor += count;
        if count != 0 {
            self.packet.in_flight = true;
            self.packet.content += PacketContent::from(FrameType::Padding);
        }
    }
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        let end = self.packet.cursor + self.remaining_mut();
        UninitSlice::new(&mut self.packet.buffer[self.packet.cursor..end])
    }
}

impl Package<PacketWriter<'_>> for (CryptoFrame, &[Bytes]) {
    fn dump(&mut self, packet: &mut PacketWriter<'_>) -> Result<PacketContent, Signals> {
        packet.write(&Frame::Crypto(self.0, self.1))
    }
}
impl Package<PacketWriter<'_>> for AckFrame {
    fn dump(&mut self, packet: &mut PacketWriter<'_>) -> Result<PacketContent, Signals> {
        packet.write(&Frame::<()>::Ack(self.clone()))
    }
}
impl Package<PacketWriter<'_>> for PingFrame {
    fn dump(&mut self, packet: &mut PacketWriter<'_>) -> Result<PacketContent, Signals> {
        packet.write(&Frame::<()>::Ping(*self))
    }
}
impl Package<PacketWriter<'_>> for ConnectionCloseFrame {
    fn dump(&mut self, packet: &mut PacketWriter<'_>) -> Result<PacketContent, Signals> {
        packet.write(&Frame::<()>::Close(self.clone()))
    }
}
impl Package<PacketWriter<'_>> for (StreamFrame, &[Bytes]) {
    fn dump(&mut self, packet: &mut PacketWriter<'_>) -> Result<PacketContent, Signals> {
        let mut frame = self.0;
        frame.set_len_bit(frame::Len::Explicit);
        packet.write(&Frame::Stream(frame, self.1))
    }
}
impl Package<PacketWriter<'_>> for &ReliableFrame {
    fn dump(&mut self, packet: &mut PacketWriter<'_>) -> Result<PacketContent, Signals> {
        packet.write(&Frame::<()>::from((*self).clone()))
    }
}
impl Package<PacketWriter<'_>> for frame::PathChallengeFrame {
    fn dump(&mut self, packet: &mut PacketWriter<'_>) -> Result<PacketContent, Signals> {
        packet.write(&Frame::<()>::PathChallenge(*self))
    }
}
impl Package<PacketWriter<'_>> for frame::PathResponseFrame {
    fn dump(&mut self, packet: &mut PacketWriter<'_>) -> Result<PacketContent, Signals> {
        packet.write(&Frame::<()>::PathResponse(*self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_sealing_abandons_pn_and_returns_recovery_frames() {
        let [(_client, transport, _path), _peer] = crate::tests::pair(1);
        let keys = crate::tests::keys(&transport);
        let journal = ArcSendJournal::default();
        let mut packet = OneRttPacket::new(
            BytesMut::zeroed(1200),
            OneRttHeader::new(Default::default(), Default::default()),
            keys.tag_len() - 1,
        )
        .unwrap();
        let mut frames = Vec::new();
        let frame = ReliableFrame::MaxData(frame::MaxDataFrame::new(42u32.into()));
        packet
            .assemble(
                &Constraints {
                    capacity: 1200,
                    congestion: 1200,
                    anti_amplification: 1200,
                },
                &mut frames,
                [&mut &frame],
            )
            .unwrap();
        assert!(packet.seal(&keys, &journal, &mut frames).is_err());
        assert!(matches!(frames.as_slice(), [Frame::MaxData(f)] if f.max_data() == 42));
        let ack = AckFrame::new(0u32.into(), 0u32.into(), 0u32.into(), vec![], None);
        assert!(
            journal
                .acknowledge(&ack, |_| panic!("failed packet acknowledged"))
                .is_err()
        );
        assert_eq!(journal.record_pending(0, &mut frames).unwrap().0, 1);
    }

    #[test]
    fn padding_requested_before_pn_allocation_obeys_congestion() {
        let mut packet = OneRttPacket::new(
            BytesMut::zeroed(1200),
            OneRttHeader::new(Default::default(), Default::default()),
            16,
        )
        .unwrap();
        let constraints = Constraints {
            capacity: 1200,
            congestion: 0,
            anti_amplification: 1200,
        };
        let mut frames = Vec::new();
        let mut ack = AckFrame::new(0u32.into(), 0u32.into(), 0u32.into(), vec![], None);
        packet
            .assemble(&constraints, &mut frames, [&mut ack])
            .unwrap();
        // Finalizing a two-byte PN shortens this packet by two bytes. Keeping this
        // requested length would introduce PADDING and must require congestion credit.
        let length = packet.cursor + packet.tag_len;
        assert!(packet.pad_to(length, &constraints).is_err());
    }
}
