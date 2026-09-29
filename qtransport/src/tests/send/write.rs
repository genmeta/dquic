use std::task::Poll;

use bytes::{Buf, BufMut, BytesMut};
use qbase::{
    frame::{self, Frame, FrameType, PathChallengeFrame, PathResponseFrame, ReliableFrame},
    packet::{
        GetType, HeaderSize, KeyPhaseBit, LongSpecificBits, Package, PacketContent, PacketNumber,
        ShortSpecificBits, Type, WritePacketNumber, header::io::WriteHeader,
    },
};

use super::{constraints::Constraints, records::ArcSentJournal};
pub use crate::keys::PacketError;
use crate::{GuaranteedFrame, keys::SealPacket};

/// Sealed bytes and submission metadata; recovery frames belong to ArcSendJournal.
/// It contains no borrowed source, journal lock, or buffer reference.
pub struct Datagram {
    pub msg: BytesMut,
    pub(super) raw_offset: usize,
}

pub struct PendingPacket {
    pub datagram: Datagram,
    pub packet_type: Type,
    pub challenge: Option<PathChallengeFrame>,
    pub response: Option<PathResponseFrame>,
    pub(super) journal: Option<ArcSentJournal>,
    pub(super) recovery: Option<std::sync::Arc<crate::space::DataSpace>>,
    pub pn: u64,
    pub generation: Option<u64>,
    pub content: PacketContent,
    pub in_flight: bool,
    pub largest_acked: Option<u64>,
}

impl PendingPacket {
    pub fn bytes(&self) -> &[u8] {
        &self.datagram.msg[self.datagram.raw_offset..]
    }

    pub fn epoch(&self) -> qbase::Epoch {
        epoch(self.packet_type)
    }

    pub fn into_buffer(mut self) -> BytesMut {
        std::mem::take(&mut self.datagram.msg)
    }
}

impl Drop for PendingPacket {
    fn drop(&mut self) {
        if let Some(journal) = &self.journal {
            journal.cancel(self.pn, |frame| {
                if let Some(data) = &self.recovery {
                    data.recover(&frame);
                }
            });
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
            datagram: Datagram {
                msg: buffer,
                raw_offset: 0,
            },
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

    pub(crate) fn has_path_frames(&self) -> bool {
        self.challenge.is_some() || self.response.is_some()
    }

    pub fn assemble<const N: usize>(
        &mut self,
        constraints: &Constraints,
        records: &mut Vec<GuaranteedFrame>,
        sources: [&mut dyn for<'a> Package<&'a mut [u8]>; N],
    ) -> Result<PacketContent, PacketError> {
        let mut limits = qbase::packet::Constraints {
            flow_ctrl: constraints.flow_ctrl.get(),
            send_quota: constraints.congestion,
            credit: constraints.anti_amplification,
            min_size: self.body_offset + 18,
            max_size: constraints.capacity.min(self.datagram.msg.len()),
            ..Default::default()
        };
        let mut frames = Vec::new();
        let mut bytes = &mut self.datagram.msg[self.cursor..];
        let mut buffer = qbase::packet::ConstraintBuffer::new(
            &mut bytes,
            &mut limits,
            self.packet_type,
            self.cursor,
            self.tag_len,
        );
        let mut blocked = Poll::Pending;
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        for source in sources {
            match source.poll_dump(&mut cx, &mut buffer, &mut frames) {
                Poll::Ready(Ok(_)) => blocked = Poll::Ready(()),
                Poll::Ready(Err(error)) => return Err(PacketError::Connection(error)),
                Poll::Pending => {}
            }
        }
        if frames.is_empty() {
            return Err(PacketError::Blocked(blocked));
        }
        let padding = buffer
            .limits
            .min_size()
            .saturating_sub(buffer.written() + self.tag_len);
        if padding != 0 {
            buffer.put_bytes(0, padding);
            frames.push(Frame::Padding(frame::PaddingFrame));
        }
        self.cursor = buffer.written();
        constraints.flow_ctrl.set(limits.flow_ctrl);
        self.content += qbase::packet::assemble::content(&frames);
        self.in_flight |= qbase::packet::assemble::in_flight(&frames);
        for frame in frames {
            match frame {
                Frame::Ack(ack) => self.largest_acked = Some(ack.largest()),
                Frame::Crypto(frame, _) => records.push(GuaranteedFrame::Crypto(frame)),
                Frame::Stream(frame, _) => records.push(GuaranteedFrame::Stream(frame)),
                Frame::PathChallenge(frame) => self.challenge = Some(frame),
                Frame::PathResponse(frame) => self.response = Some(frame),
                frame => {
                    if let Ok(reliable) = ReliableFrame::try_from(&frame) {
                        records.push(GuaranteedFrame::Reliable(reliable));
                    }
                }
            }
        }
        Ok(self.content)
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
            return Err(PacketError::Blocked(Poll::Ready(())));
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
                recovery: Default::default(),
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

pub fn epoch(packet_type: Type) -> qbase::Epoch {
    use qbase::packet::r#type::long::{Type as Long, Ver1};
    match packet_type {
        Type::Long(Long::V1(Ver1::INITIAL)) => qbase::Epoch::Initial,
        Type::Long(Long::V1(Ver1::HANDSHAKE)) => qbase::Epoch::Handshake,
        _ => qbase::Epoch::Data,
    }
}

#[cfg(test)]
mod tests {
    use qbase::{frame::AckFrame, packet::OneRttHeader};

    use super::*;

    #[test]
    fn failed_sealing_leaves_journal_cancellation_to_the_caller() {
        let [(_client, transport, _path), _peer] = crate::tests::pair(1);
        let keys = crate::tests::keys(&transport);
        let journal = ArcSentJournal::default();
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
                    flow_ctrl: std::cell::Cell::new(usize::MAX),
                    capacity: 1200,
                    congestion: 1200,
                    anti_amplification: 1200,
                },
                &mut frames,
                [&mut frame.clone()],
            )
            .unwrap();
        let ((pn, encoded), key) = keys
            .reserve(|generation| {
                journal
                    .record_pending(generation, &mut frames)
                    .map_err(Into::into)
            })
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
                .on_acked(&ack, |_| panic!("failed packet acknowledged"))
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
            flow_ctrl: std::cell::Cell::new(usize::MAX),
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
