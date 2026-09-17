use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut, buf::UninitSlice};
use qbase::{
    Epoch,
    frame::{
        self, AckFrame, ConnectionCloseFrame, CryptoFrame, EncodeSize, Frame, FrameFeature,
        FrameType, GetFrameType, PingFrame, ReliableFrame, StreamFrame, io::WriteFrame,
    },
    net::tx::Signals,
    packet::{
        GetType, HandshakeHeader, HeaderSize, InitialHeader, OneRttHeader, Package, PacketContent,
        Type, header::io::WriteHeader,
    },
    util::{Buffer, WriteData},
};

use super::constraints::Constraints;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PacketError {
    #[error("packet assembly blocked: {0:?}")]
    Blocked(Signals),
    #[error("frame {0:?} is not allowed in this packet")]
    IllegalFrame(FrameType),
    #[error("invalid packet layout or capacity")]
    Layout,
    #[error(transparent)]
    Crypto(#[from] qtls::CryptoError),
}

/// A sealed packet keeps its original frame ownership until socket completion.
/// It contains no borrowed source, journal lock, or buffer reference.
pub(crate) struct PendingPacket {
    pub(crate) bytes: BytesMut,
    pub(crate) pn: u64,
    pub(crate) epoch: Epoch,
    pub(crate) content: PacketContent,
    pub(crate) in_flight: bool,
    pub(crate) ack: Option<u64>,
    pub(crate) frames: Vec<Frame<()>>,
}

impl PendingPacket {
    /// Call only when no bytes of this packet reached the socket. An uncertain
    /// socket outcome burns the PN and retains congestion accounting instead.
    pub(crate) fn abort(self, constraints: &mut Constraints) -> Vec<Frame<()>> {
        constraints.capacity += self.bytes.len();
        constraints.anti_amplification += self.bytes.len();
        if self.in_flight {
            constraints.congestion += self.bytes.len();
        }
        self.frames
    }
}

// Layout/assembly is identical; the three concrete types restrict which source
// implementations can be supplied. No self-referential PacketWriter is stored.
macro_rules! packet {
    ($name:ident, $header:ty, $epoch:expr) => {
        pub(crate) struct $name {
            buffer: BytesMut,
            pn: u64,
            pn_offset: usize,
            body_offset: usize,
            cursor: usize,
            packet_type: Type,
            header_key: Arc<qtls::HeaderProtectionKey>,
            packet_key: qtls::PacketKey,
            limit: usize,
            source_end: usize,
            flight_limit: usize,
            reserved: usize,
            reserved_flight: usize,
            content: PacketContent,
            in_flight: bool,
            ack: Option<u64>,
            frames: Vec<Frame<()>>,
            illegal: Option<FrameType>,
            sealed: bool,
        }

        impl $name {
            pub(crate) fn frames(&self) -> &[Frame<()>] {
                &self.frames
            }

            pub(crate) fn new(
                mut buffer: BytesMut,
                header: $header,
                header_key: Arc<qtls::HeaderProtectionKey>,
                packet_key: qtls::PacketKey,
                pn: u64,
                key_phase: bool,
            ) -> Result<Self, PacketError> {
                let packet_type = header.get_type();
                let long = matches!(packet_type, Type::Long(_));
                let pn_offset = header.size() + if long { 2 } else { 0 };
                let body_offset = pn_offset + 4;
                let limit = buffer
                    .len()
                    .checked_sub(packet_key.tag_len())
                    .ok_or(PacketError::Layout)?;
                if body_offset >= limit
                    || pn > qbase::varint::VARINT_MAX
                    || (long && buffer.len() >= 16384)
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
                if !long && key_phase {
                    buffer[0] |= 4;
                }
                Ok(Self {
                    buffer,
                    pn,
                    pn_offset,
                    body_offset,
                    cursor: body_offset,
                    packet_type,
                    header_key,
                    packet_key,
                    limit,
                    source_end: limit,
                    flight_limit: 0,
                    reserved: 0,
                    reserved_flight: 0,
                    content: PacketContent::default(),
                    in_flight: false,
                    ack: None,
                    frames: Vec::new(),
                    illegal: None,
                    sealed: false,
                })
            }

            pub(crate) fn assemble<const N: usize>(
                &mut self,
                constraints: &mut Constraints,
                sources: [&mut dyn Package<Self>; N],
            ) -> Result<PacketContent, PacketError> {
                if self.sealed {
                    return Err(PacketError::Layout);
                }
                let tag = self.packet_key.tag_len();
                self.limit =
                    self.buffer
                        .len()
                        .min(self.reserved.saturating_add(
                            constraints.capacity.min(constraints.anti_amplification),
                        ))
                        .saturating_sub(tag);
                self.flight_limit = self.reserved_flight.saturating_add(constraints.congestion);
                let start = self.cursor;
                let mut blocked = Signals::empty();
                for source in sources {
                    // Prevent a reliable control queue from starving the following sources.
                    self.source_end = self.cursor.saturating_add(512).min(self.limit);
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

            fn write<D: ContinuousData>(
                &mut self,
                frame: &Frame<D>,
            ) -> Result<PacketContent, Signals>
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
                let in_flight = self.in_flight
                    || content.is_ack_eliciting()
                    || matches!(frame, Frame::Padding(_));
                if end > self.source_end
                    || end > self.limit
                    || (in_flight && end + self.packet_key.tag_len() > self.flight_limit)
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
            pub(crate) fn pad_to(
                &mut self,
                length: usize,
                constraints: &mut Constraints,
            ) -> Result<(), PacketError> {
                if self.sealed {
                    return Err(PacketError::Layout);
                }
                let size = self.cursor + self.packet_key.tag_len();
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
                self.buffer[self.cursor..length - self.packet_key.tag_len()].fill(0);
                constraints.capacity -= length - size;
                constraints.anti_amplification -= length - size;
                constraints.congestion -= length - self.reserved_flight;
                self.cursor = length - self.packet_key.tag_len();
                self.reserved = length;
                self.reserved_flight = length;
                self.in_flight = true;
                self.content += PacketContent::from(FrameType::Padding);
                Ok(())
            }

            /// Return unsent frame descriptors to their owning sources. This also
            /// refunds the local reservation; no packet number is made reusable.
            pub(crate) fn abort(mut self, constraints: &mut Constraints) -> Vec<Frame<()>> {
                constraints.capacity += self.reserved;
                constraints.anti_amplification += self.reserved;
                constraints.congestion += self.reserved_flight;
                std::mem::take(&mut self.frames)
            }

            pub(crate) fn seal(&mut self) -> Result<PendingPacket, PacketError> {
                if self.sealed || self.cursor == self.body_offset || self.illegal.is_some() {
                    return Err(PacketError::Layout);
                }
                self.sealed = true; // Even a failed AEAD attempt must not reuse this PN.
                if matches!(self.packet_type, Type::Long(_)) {
                    let payload_len = self.cursor + self.packet_key.tag_len() - self.pn_offset;
                    self.buffer[self.pn_offset - 2..self.pn_offset]
                        .copy_from_slice(&((payload_len as u16) | 0x4000).to_be_bytes());
                }
                let total = self.cursor + self.packet_key.tag_len();
                let (header, body_tag) = self.buffer[..total].split_at_mut(self.body_offset);
                let (body, tag) = body_tag.split_at_mut(self.cursor - self.body_offset);
                self.packet_key.seal(self.pn, header, body, tag)?;
                let (header_pn, sample) = self.buffer[..total].split_at_mut(self.body_offset);
                let (prefix, pn_bytes) = header_pn.split_at_mut(self.pn_offset);
                self.header_key.protect(
                    &sample[..self.header_key.sample_len()],
                    &mut prefix[0],
                    pn_bytes,
                )?;
                self.buffer.truncate(total);
                // Reservations move with PendingPacket, so aborting the consumed
                // packet shell cannot refund them a second time.
                self.reserved = 0;
                self.reserved_flight = 0;
                Ok(PendingPacket {
                    bytes: std::mem::take(&mut self.buffer),
                    pn: self.pn,
                    epoch: $epoch,
                    content: self.content,
                    in_flight: self.in_flight,
                    ack: self.ack,
                    frames: std::mem::take(&mut self.frames),
                })
            }
        }

        // STREAM sources also write raw pre-padding. Leave room for an explicit
        // STREAM length even when qrecovery selected a length-omitting encoding.
        // Only the checked frame adapter may consume these eight reserved bytes.
        unsafe impl BufMut for $name {
            fn remaining_mut(&self) -> usize {
                self.source_end
                    .min(self.limit)
                    .min(self.flight_limit.saturating_sub(self.packet_key.tag_len()))
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

        impl Package<$name> for (CryptoFrame, &[Bytes]) {
            fn dump(&mut self, packet: &mut $name) -> Result<PacketContent, Signals> {
                packet.write(&Frame::Crypto(self.0, self.1))
            }
        }
        impl Package<$name> for AckFrame {
            fn dump(&mut self, packet: &mut $name) -> Result<PacketContent, Signals> {
                packet.write(&Frame::<()>::Ack(self.clone()))
            }
        }
        impl Package<$name> for PingFrame {
            fn dump(&mut self, packet: &mut $name) -> Result<PacketContent, Signals> {
                packet.write(&Frame::<()>::Ping(*self))
            }
        }
        impl Package<$name> for ConnectionCloseFrame {
            fn dump(&mut self, packet: &mut $name) -> Result<PacketContent, Signals> {
                packet.write(&Frame::<()>::Close(self.clone()))
            }
        }
    };
}

packet!(InitialPacket, InitialHeader, Epoch::Initial);
packet!(HandshakePacket, HandshakeHeader, Epoch::Handshake);
packet!(OneRttPacket, OneRttHeader, Epoch::Data);

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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use qbase::{
        cid::ConnectionId,
        packet::{LongHeaderBuilder, Packet, PacketReader},
        varint::VarInt,
    };

    use super::*;
    use crate::recv::Topology;

    #[derive(Debug)]
    struct NoAuthority;
    impl qtls::ResolveServerAuthority for NoAuthority {
        fn resolve(&self, _: qtls::ServerCredentialRequest<'_>) -> Option<qtls::LocalAuthority> {
            None
        }
    }

    fn keys(cid: ConnectionId) -> qtls::BidirectionalKeys {
        qtls::ServerTlsEndpoint::new(qtls::ServerTlsConfig {
            provider: Arc::new(qtls::default_provider()),
            alpn: vec![b"qconn".to_vec()],
            resolve_local: Arc::new(NoAuthority),
            verify_client: None,
            resumption: qtls::ServerResumptionConfig::Disabled,
            limits: qtls::TlsLimits::default(),
        })
        .unwrap()
        .initial_keys(qtls::QuicVersion::V1, &cid)
        .unwrap()
    }

    fn matching_pair() -> (InitialPacket, Topology, Constraints) {
        let cid = ConnectionId::from_slice(b"original");
        let send = keys(cid).opening;
        let recv = keys(cid).opening;
        let header = LongHeaderBuilder::with_cid(cid, cid).initial(vec![]);
        (
            InitialPacket::new(
                BytesMut::zeroed(1200),
                header,
                Arc::new(send.header),
                send.packet,
                0,
                false,
            )
            .unwrap(),
            Topology::new(recv),
            Constraints {
                capacity: 1200,
                congestion: 1200,
                anti_amplification: 1200,
            },
        )
    }

    fn data_packet(bytes: BytesMut) -> qbase::packet::DataPacket {
        let Packet::Data(p) = PacketReader::new(bytes, 8).next().unwrap().unwrap() else {
            panic!()
        };
        p
    }

    fn ack() -> AckFrame {
        AckFrame::new(
            VarInt::from_u32(0),
            VarInt::from_u32(0),
            VarInt::from_u32(0),
            vec![],
            None,
        )
    }

    #[test]
    fn heterogeneous_sources_seal_and_open_with_qtls() {
        let (mut packet, mut topology, mut constraints) = matching_pair();
        let chunks = [Bytes::from_static(b"hello")];
        let mut crypto = (
            CryptoFrame::new(0u32.into(), 5u32.into()),
            chunks.as_slice(),
        );
        packet
            .assemble(&mut constraints, [&mut ack(), &mut crypto])
            .unwrap();
        packet.pad_to(1200, &mut constraints).unwrap();
        let pending = packet.seal().unwrap();
        assert!(packet.seal().is_err(), "a sealed PN cannot be reused");
        assert_eq!(pending.bytes.len(), 1200);
        assert_eq!(constraints.congestion, 0);
        let copy = pending.bytes.clone();
        let (epoch, pn, mut frames) = topology
            .open(data_packet(pending.bytes), Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert!(
            frames.any(|f| matches!(f.unwrap().0, Frame::Crypto(_, b) if b.as_ref() == b"hello"))
        );
        topology.commit(epoch, pn, pending.content, Duration::from_secs(1));
        assert!(
            topology
                .open(data_packet(copy), Duration::from_secs(1))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ack_only_bypasses_cwnd_but_padding_and_crypto_do_not() {
        let (mut packet, _, mut constraints) = matching_pair();
        constraints.congestion = 0;
        packet.assemble(&mut constraints, [&mut ack()]).unwrap();
        let reserved = constraints.capacity;
        let chunks = [Bytes::from_static(b"hello")];
        let mut crypto = (
            CryptoFrame::new(0u32.into(), 5u32.into()),
            chunks.as_slice(),
        );
        assert!(matches!(
            packet.assemble(&mut constraints, [&mut crypto]),
            Err(PacketError::Blocked(_))
        ));
        assert_eq!(constraints.capacity, reserved);
        assert!(packet.pad_to(1200, &mut constraints).is_err());
        let pending = packet.seal().unwrap();
        assert!(!pending.in_flight);
        assert_eq!(constraints.congestion, 0);
    }

    #[test]
    fn anti_amplification_applies_to_ack_and_authentication_failure_does_not_commit_pn() {
        let (mut packet, mut topology, mut constraints) = matching_pair();
        constraints.anti_amplification = 0;
        assert!(packet.assemble(&mut constraints, [&mut ack()]).is_err());
        constraints.anti_amplification = 1200;
        packet.assemble(&mut constraints, [&mut PingFrame]).unwrap();
        let pending = packet.seal().unwrap();
        let mut altered = pending.bytes.clone();
        let last = altered.len() - 1;
        altered[last] ^= 1;
        assert!(
            topology
                .open(data_packet(altered), Duration::from_secs(1))
                .unwrap()
                .is_none()
        );
        assert!(
            topology
                .open(data_packet(pending.bytes), Duration::from_secs(1))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn discarded_initial_nodes_cannot_be_reopened() {
        let (mut packet, mut topology, mut constraints) = matching_pair();
        packet.assemble(&mut constraints, [&mut PingFrame]).unwrap();
        let pending = packet.seal().unwrap();
        topology.discard(Epoch::Initial);
        assert!(topology.journal(Epoch::Initial).is_none());
        assert!(
            topology
                .open(data_packet(pending.bytes), Duration::from_secs(1))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn stream_length_does_not_consume_following_sources_or_padding() {
        let cid = ConnectionId::from_slice(b"original");
        let keys = keys(cid).opening;
        let mut packet = OneRttPacket::new(
            BytesMut::zeroed(1200),
            OneRttHeader::new(Default::default(), cid),
            Arc::new(keys.header),
            keys.packet,
            0,
            false,
        )
        .unwrap();
        let mut constraints = Constraints {
            capacity: 1200,
            congestion: 1200,
            anti_amplification: 1200,
        };
        let chunks = [Bytes::from_static(b"stream data")];
        let mut stream = (
            StreamFrame::new(VarInt::from_u32(0).into(), 0, chunks[0].len()),
            chunks.as_slice(),
        );
        packet
            .assemble(&mut constraints, [&mut stream, &mut PingFrame])
            .unwrap();
        packet.pad_to(1200, &mut constraints).unwrap();
        let payload = Bytes::copy_from_slice(&packet.buffer[packet.body_offset..packet.cursor]);
        let frames = frame::FrameReader::new(payload, packet.packet_type)
            .map(Result::unwrap)
            .map(|(frame, _)| frame)
            .collect::<Vec<_>>();
        assert!(matches!(&frames[0], Frame::Stream(_, bytes) if bytes.as_ref() == b"stream data"));
        assert!(matches!(&frames[1], Frame::Ping(_)));
    }

    #[tokio::test]
    async fn unsent_crypto_reservations_can_be_requeued_without_losing_data() {
        use tokio::io::AsyncWriteExt;
        let stream = qrecovery::crypto::CryptoStream::new(Default::default());
        stream
            .writer()
            .write_all(b"retained until acknowledged")
            .await
            .unwrap();
        // Handshake packaging does not force a replay of outstanding Initial data.
        let mut source = stream.outgoing().package(Epoch::Handshake);
        let (mut packet, mut topology, mut constraints) = matching_pair();
        packet.assemble(&mut constraints, [&mut source]).unwrap();
        let pending = packet.seal().unwrap();
        assert!(packet.abort(&mut constraints).is_empty());
        assert!(
            constraints.capacity < 1200,
            "the reservation belongs to PendingPacket"
        );
        let (mut next, _, _) = matching_pair();
        next.pn = 1;
        next.buffer[next.pn_offset..next.body_offset].copy_from_slice(&1u32.to_be_bytes());
        assert!(matches!(
            next.assemble(&mut constraints, [&mut source]),
            Err(PacketError::Blocked(_))
        ));

        for frame in pending.abort(&mut constraints) {
            let Frame::Crypto(frame, ()) = frame else {
                panic!("unexpected frame")
            };
            stream.outgoing().may_loss_data(&frame);
        }
        assert_eq!(constraints.capacity, 1200);
        assert_eq!(constraints.congestion, 1200);
        assert_eq!(constraints.anti_amplification, 1200);
        next.assemble(&mut constraints, [&mut source]).unwrap();
        let pending = next.seal().unwrap();
        let (_, pn, mut frames) = topology
            .open(data_packet(pending.bytes), Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(pn, 1);
        assert!(
            matches!(frames.next().unwrap().unwrap().0, Frame::Crypto(_, bytes) if bytes.as_ref() == b"retained until acknowledged")
        );
    }
}
