use bytes::{Buf, BufMut, Bytes, BytesMut, buf::UninitSlice};
use qbase::{
    frame::{
        self, AckFrame, ConnectionCloseFrame, CryptoFrame, DatagramFrame, EncodeSize, Frame,
        FrameFeature, FrameType, GetFrameType, PathChallengeFrame, PathResponseFrame, PingFrame,
        ReliableFrame, StreamFrame, io::WriteFrame,
    },
    net::tx::Signals,
    packet::{
        GetType, HeaderSize, KeyPhaseBit, LongSpecificBits, Package, PacketContent, PacketNumber,
        ShortSpecificBits, Type, WritePacketNumber, header::io::WriteHeader,
    },
    util::{Buffer, WriteData},
};

use super::{constraints::Constraints, records::ArcSendJournal};
use crate::{GuaranteedFrame, keys::SealPacket};

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
pub struct Datagram {
    pub msg: BytesMut,
}

pub struct PendingPacket {
    pub datagram: Datagram,
    pub packet_type: Type,
    pub challenge: Option<PathChallengeFrame>,
    pub response: Option<PathResponseFrame>,
    pub(super) journal: Option<ArcSendJournal>,
    pub pn: u64,
    pub generation: Option<u64>,
    pub content: PacketContent,
    pub in_flight: bool,
    pub largest_acked: Option<u64>,
}

impl PendingPacket {
    pub fn bytes(&self) -> &[u8] {
        &self.datagram.msg
    }

    pub fn epoch(&self) -> qbase::Epoch {
        epoch(self.packet_type)
    }

    pub(crate) fn into_buffer(mut self) -> BytesMut {
        std::mem::take(&mut self.datagram.msg)
    }
}

impl Drop for PendingPacket {
    fn drop(&mut self) {
        if let Some(journal) = &self.journal {
            journal.cancel(self.pn);
        }
    }
}

/// Packet encoding state and its owned buffer.
pub struct Packet {
    datagram: Datagram,
    packet_type: Type,
    challenge: Option<PathChallengeFrame>,
    response: Option<PathResponseFrame>,
    padded_to: usize,
    body_offset: usize,
    cursor: usize,
    tag_len: usize,
    content: PacketContent,
    in_flight: bool,
    largest_acked: Option<u64>,
}

impl Packet {
    /// Assemble frames with four bytes reserved for the eventual packet number.
    pub fn new<H: HeaderSize + GetType>(
        mut buffer: BytesMut,
        header: H,
        tag_len: usize,
    ) -> Result<Self, PacketError>
    where
        for<'b> &'b mut [u8]: WriteHeader<H>,
    {
        let packet_type = header.get_type();
        let length_size = if matches!(packet_type, Type::Long(_)) {
            2
        } else {
            0
        };
        let body_offset = header.size() + length_size + 4;
        let limit = buffer
            .len()
            .checked_sub(tag_len)
            .ok_or(PacketError::Layout)?;
        if body_offset >= limit {
            return Err(PacketError::Layout);
        }
        let mut writer = &mut buffer[..];
        writer.put_header(&header);
        if length_size != 0 {
            writer.put_u16(0);
        }
        writer.put_packet_number(PacketNumber::U32(0));
        Ok(Self {
            datagram: Datagram { msg: buffer },
            packet_type,
            challenge: None,
            response: None,
            padded_to: 0,
            body_offset,
            cursor: body_offset,
            tag_len,
            content: PacketContent::default(),
            in_flight: false,
            largest_acked: None,
        })
    }

    pub fn datagram(&self) -> &Datagram {
        &self.datagram
    }

    pub(crate) fn has_path_frames(&self) -> bool {
        self.challenge.is_some() || self.response.is_some()
    }

    pub fn assemble<const N: usize>(
        &mut self,
        constraints: &Constraints,
        records: &mut Vec<GuaranteedFrame>,
        sources: [&mut dyn for<'a> Package<PacketWriter<'a>>; N],
    ) -> Result<PacketContent, PacketError> {
        self.assemble_pending(constraints, records, sources, &[])
    }

    pub(crate) fn assemble_pending<const N: usize>(
        &mut self,
        constraints: &Constraints,
        records: &mut Vec<GuaranteedFrame>,
        sources: [&mut dyn for<'a> Package<PacketWriter<'a>>; N],
        pending: &[PendingPacket],
    ) -> Result<PacketContent, PacketError> {
        let start = self.cursor;
        let mut writer = PacketWriter::new(self, constraints, records);
        writer.pending = pending;
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
            || length > self.datagram.msg.len()
            || length > constraints.capacity.min(constraints.anti_amplification)
            || length > constraints.congestion
        {
            return Err(PacketError::Blocked(Signals::CONGESTION));
        }
        if length > size {
            self.datagram.msg[self.cursor..length - self.tag_len].fill(0);
            self.cursor = length - self.tag_len;
            self.in_flight = true;
            self.content += PacketContent::from(FrameType::Padding);
        }
        self.padded_to = self.padded_to.max(length);
        Ok(())
    }

    pub(crate) fn into_buffer(self) -> BytesMut {
        self.datagram.msg
    }

    /// Seal with the key already reserved together with this packet number.
    /// The caller owns journal registration and cancellation on failure.
    pub fn seal(
        self,
        key: &impl SealPacket<Output = (u64, KeyPhaseBit)>,
        pn: u64,
        encoded_pn: PacketNumber,
    ) -> Result<PendingPacket, PacketError> {
        let (mut packet, (generation, _)) = self.protect(key, pn, encoded_pn)?;
        packet.generation = Some(generation);
        Ok(packet)
    }

    pub fn seal_long(
        self,
        keys: &qtls::DirectionalKeys,
        pn: u64,
        encoded_pn: PacketNumber,
    ) -> Result<PendingPacket, PacketError> {
        self.protect(keys, pn, encoded_pn)
            .map(|(packet, ())| packet)
    }

    fn protect<K: SealPacket>(
        mut self,
        key: &K,
        pn: u64,
        encoded_pn: PacketNumber,
    ) -> Result<(PendingPacket, K::Output), PacketError> {
        let pn_offset = self.body_offset - 4;
        let shift = 4 - encoded_pn.size();
        self.datagram.msg.copy_within(..pn_offset, shift);
        self.datagram.msg[shift] |= if matches!(self.packet_type, Type::Long(_)) {
            *LongSpecificBits::from_pn(&encoded_pn)
        } else {
            *ShortSpecificBits::from_pn(&encoded_pn)
        };
        (&mut self.datagram.msg[pn_offset + shift..self.body_offset]).put_packet_number(encoded_pn);
        let total = (self.cursor + self.tag_len).max(self.padded_to + shift);
        if total > self.cursor + self.tag_len {
            self.in_flight = true;
            self.content += PacketContent::from(FrameType::Padding);
        }
        self.datagram.msg.resize(total, 0);
        self.datagram.msg[self.cursor..total - self.tag_len].fill(0);
        if matches!(self.packet_type, Type::Long(_)) {
            let length = total - self.body_offset + encoded_pn.size();
            (&mut self.datagram.msg[pn_offset + shift - 2..pn_offset + shift])
                .put_u16(0x4000 | length as u16);
        }
        let sealed = key.seal(
            pn,
            &mut self.datagram.msg[shift..],
            pn_offset,
            self.body_offset - shift,
            self.tag_len,
        )?;
        self.datagram.msg.advance(shift);
        Ok((
            PendingPacket {
                datagram: self.datagram,
                packet_type: self.packet_type,
                challenge: self.challenge,
                response: self.response,
                journal: None,
                pn,
                generation: None,
                content: self.content,
                in_flight: self.in_flight,
                largest_acked: self.largest_acked,
            },
            sealed,
        ))
    }
}

/// A packet write target with borrowed limits and reusable recovery records.
pub struct PacketWriter<'a> {
    packet: &'a mut Packet,
    constraints: &'a Constraints,
    records: &'a mut Vec<GuaranteedFrame>,
    pending: &'a [PendingPacket],
}

impl<'a> PacketWriter<'a> {
    pub fn new(
        packet: &'a mut Packet,
        constraints: &'a Constraints,
        records: &'a mut Vec<GuaranteedFrame>,
    ) -> Self {
        Self {
            packet,
            constraints,
            records,
            pending: &[],
        }
    }

    /// The datagram being assembled, including its encoded header and frame bytes.
    pub fn datagram(&self) -> &Datagram {
        &self.packet.datagram
    }

    fn write<D: Buffer>(&mut self, frame: &Frame<D>) -> Result<PacketContent, Signals>
    where
        for<'b, 'c> &'b mut &'c mut [u8]: WriteData<D>,
    {
        let packet = &mut self.packet;
        let constraints = self.constraints;
        let frame_type = frame.frame_type();
        let duplicate = self.pending.iter().any(|sent| match frame {
            Frame::Ack(ack) => {
                sent.epoch() == epoch(packet.packet_type)
                    && sent.largest_acked.is_some_and(|pn| pn >= ack.largest())
            }
            Frame::PathChallenge(frame) => sent.challenge == Some(*frame),
            Frame::PathResponse(frame) => sent.response == Some(*frame),
            _ => false,
        });
        if duplicate {
            return Err(Signals::TRANSPORT);
        }
        if !frame_type.belongs_to(packet.packet_type) {
            return Err(Signals::TRANSPORT);
        }
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
                .datagram
                .msg
                .len()
                .min(constraints.capacity)
                .min(constraints.anti_amplification)
            || (in_flight && size > constraints.congestion)
        {
            return Err(Signals::CONGESTION);
        }
        let mut writer = &mut packet.datagram.msg[packet.cursor..end];
        writer.put_frame(frame);
        assert!(
            writer.is_empty(),
            "frame encoder must match its declared size"
        );
        packet.datagram.msg[end..padded_end].fill(0);
        packet.cursor = padded_end;
        packet.content += content;
        packet.in_flight = in_flight;
        match frame {
            Frame::Ack(ack) => packet.largest_acked = Some(ack.largest()),
            Frame::Crypto(frame, _) => self.records.push(GuaranteedFrame::Crypto(*frame)),
            Frame::Stream(frame, _) => self.records.push(GuaranteedFrame::Stream(*frame)),
            Frame::PathChallenge(frame) => packet.challenge = Some(*frame),
            Frame::PathResponse(frame) => packet.response = Some(*frame),
            frame => {
                if let Ok(reliable) = ReliableFrame::try_from(frame) {
                    self.records.push(GuaranteedFrame::Reliable(reliable));
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
            .datagram
            .msg
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
            self.packet.datagram.msg[self.packet.cursor..self.packet.cursor + count]
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
        UninitSlice::new(&mut self.packet.datagram.msg[self.packet.cursor..end])
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

impl Package<PacketWriter<'_>> for (DatagramFrame, Bytes) {
    fn dump(&mut self, packet: &mut PacketWriter<'_>) -> Result<PacketContent, Signals> {
        // Explicit length permits another source or trailing HP padding.
        let frame = DatagramFrame::new(true, self.0.len());
        packet.write(&Frame::Datagram(frame, &self.1))
    }
}

pub(crate) fn epoch(packet_type: Type) -> qbase::Epoch {
    use qbase::packet::r#type::long::{Type as Long, Ver1};
    match packet_type {
        Type::Long(Long::V1(Ver1::INITIAL)) => qbase::Epoch::Initial,
        Type::Long(Long::V1(Ver1::HANDSHAKE)) => qbase::Epoch::Handshake,
        _ => qbase::Epoch::Data,
    }
}

#[cfg(test)]
mod tests {
    use qbase::packet::OneRttHeader;

    use super::*;

    #[test]
    fn failed_sealing_leaves_journal_cancellation_to_the_caller() {
        let [(_client, transport, _path), _peer] = crate::tests::pair(1);
        let keys = crate::tests::keys(&transport);
        let journal = ArcSendJournal::default();
        let mut packet = Packet::new(
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
        let ((pn, encoded), key) = keys
            .reserve(|generation| journal.record_pending(generation, &mut frames))
            .unwrap();
        let result = packet.seal(&key, pn, encoded);
        assert!(result.is_err());
        // Sealing neither drains recovery records nor cancels their journal entry.
        assert!(frames.is_empty());
        assert!(super::super::finish_sealing(result, pn, &journal, &mut frames).is_err());
        assert!(
            matches!(frames.as_slice(), [GuaranteedFrame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 42)
        );
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
        let mut packet = Packet::new(
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
