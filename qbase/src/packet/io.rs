use std::{
    any::Any,
    mem,
    task::{Context, Poll},
};

use bytes::BytesMut;
use nom::{Parser, multi::length_data};
pub use rustls::quic::DirectionalKeys;

use super::{
    error::Error,
    header::io::be_header,
    r#type::{Type, io::be_packet_type},
    *,
};
use crate::{Epoch, frame::*, util::Buffer, varint::be_varint};

/// Parse the payload of a packet.
///
/// - For long packets, the payload is a [`nom::multi::length_data`].
/// - For 1-RTT packet, the payload is the remaining content of the datagram.
fn be_payload(
    pkty: Type,
    datagram: &mut BytesMut,
    remain_len: usize,
) -> Result<(BytesMut, usize), Error> {
    let offset = datagram.len() - remain_len;
    let input = &datagram[offset..];
    let (remain, payload) = length_data(be_varint).parse(input).map_err(|e| match e {
        ne @ nom::Err::Incomplete(_) => Error::IncompleteHeader(pkty, ne.to_string()),
        _ => unreachable!("parsing packet header never generates error or failure"),
    })?;
    let payload_len = payload.len();
    if payload_len < 20 {
        // The payload needs at least 20 bytes to have enough samples to remove the packet header protection.
        return Err(Error::UnderSampling(pkty, payload.len()));
    }
    let packet_length = datagram.len() - remain.len();
    let bytes = datagram.split_to(packet_length);
    Ok((bytes, packet_length - payload_len))
}

/// Parse the QUIC packet from the datagram, given the length of the DCID.
/// Returns the parsed packet or an error, and the datagram removed the packet's content.
pub fn be_packet(datagram: &mut BytesMut, dcid_len: usize) -> Result<Packet, Error> {
    let input = datagram.as_ref();
    let (remain, pkty) = be_packet_type(input).map_err(|e| match e {
        ne @ nom::Err::Incomplete(_) => Error::IncompleteType(ne.to_string()),
        nom::Err::Error(e) => e,
        _ => unreachable!("parsing packet type never generates failure"),
    })?;
    let (remain, header) = be_header(pkty, dcid_len, remain).map_err(|e| match e {
        ne @ nom::Err::Incomplete(_) => Error::IncompleteHeader(pkty, ne.to_string()),
        _ => unreachable!("parsing packet header never generates error or failure"),
    })?;
    match header {
        Header::VN(header) => {
            datagram.clear();
            Ok(Packet::VN(header))
        }
        Header::Retry(header) => {
            datagram.clear();
            Ok(Packet::Retry(header))
        }
        Header::Initial(header) => {
            let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Long(long::DataHeader::Initial(header)),
                bytes,
                offset,
            }))
        }
        Header::ZeroRtt(header) => {
            let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Long(long::DataHeader::ZeroRtt(header)),
                bytes,
                offset,
            }))
        }
        Header::Handshake(header) => {
            let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Long(long::DataHeader::Handshake(header)),
                bytes,
                offset,
            }))
        }
        Header::OneRtt(header) => {
            if remain.len() < 20 {
                // The payload needs at least 20 bytes to have enough samples to remove the packet header protection.
                return Err(Error::UnderSampling(pkty, remain.len()));
            }
            let remain_len = remain.len();
            let bytes = mem::replace(datagram, BytesMut::new());
            let offset = bytes.len() - remain_len;
            datagram.clear();
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Short(header),
                bytes,
                offset,
            }))
        }
    }
}

pub trait ProductHeader<H> {
    fn new_header(&self) -> Result<H, Poll<()>>;
}

pub trait PacketSpace<H> {
    type PacketAssembler<'b>: AssemblePacket
    where
        Self: 'b;

    fn new_packet<'b>(
        &'b self,
        header: H,
        buffer: &'b mut [u8],
    ) -> Result<Self::PacketAssembler<'b>, Poll<()>>;
}

pub enum Keys {
    LongHeaderPacket {
        keys: DirectionalKeys,
    },
    ShortHeaderPacket {
        keys: DirectionalKeys,
        key_phase: KeyPhaseBit,
    },
}

impl Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LongHeaderPacket { .. } => f
                .debug_struct("LongHeaderPacket")
                .field("keys", &"...")
                .finish(),
            Self::ShortHeaderPacket { key_phase, .. } => f
                .debug_struct("ShortHeaderPacket")
                .field("keys", &"...")
                .field("key_phase", key_phase)
                .finish(),
        }
    }
}

impl Keys {
    fn hpk(&self) -> &dyn rustls::quic::HeaderProtectionKey {
        match self {
            Self::LongHeaderPacket { keys } | Self::ShortHeaderPacket { keys, .. } => {
                keys.header.as_ref()
            }
        }
    }

    fn pk(&self) -> &dyn rustls::quic::PacketKey {
        match self {
            Self::LongHeaderPacket { keys } | Self::ShortHeaderPacket { keys, .. } => {
                keys.packet.as_ref()
            }
        }
    }

    fn key_phase(&self) -> Option<KeyPhaseBit> {
        match self {
            Self::LongHeaderPacket { .. } => None,
            Self::ShortHeaderPacket { key_phase, .. } => Some(*key_phase),
        }
    }
}

#[derive(Debug)]
struct PacketLayout {
    hdr_len: usize,
    len_encoding: usize,
    pn_len: usize,

    cursor: usize,
    end: usize,
}

impl PacketLayout {
    pub fn payload_len(&self) -> usize {
        self.cursor - self.hdr_len - self.len_encoding
    }

    pub fn is_empty(&self) -> bool {
        self.payload_len() == self.pn_len
    }
}

#[derive(Debug, CopyGetters)]
pub struct PacketInfo {
    #[getset(get_copy = "pub")]
    packet_type: Type,
    #[getset(get_copy = "pub")]
    packet_number: u64,
    // Packets containing only frames with [`Spec::N`] are not ack-eliciting;
    // otherwise, they are ack-eliciting.
    #[getset(get_copy = "pub")]
    ack_eliciting: bool,
    // A Boolean that indicates whether the packet counts toward bytes in flight.
    // See [Section 2](https://www.rfc-editor.org/rfc/rfc9002#section-2)
    // and [Appendix A.1](https://www.rfc-editor.org/rfc/rfc9002#section-a.1)
    // of [QUIC Recovery](https://www.rfc-editor.org/rfc/rfc9002).
    //
    // Packets containing only frames with [`Spec::C`] do not
    // count toward bytes in flight for congestion control purposes.
    #[getset(get_copy = "pub")]
    in_flight: bool,
    // Packets containing only frames with [`Spec::P`] can be used to
    // probe new network paths during connection migration.
    #[getset(get_copy = "pub")]
    probe_new_path: bool,
    #[getset(get_copy = "pub")]
    largest_ack: Option<u64>,
}

impl PacketInfo {
    pub fn new(ty: Type, pn: u64) -> Self {
        Self {
            packet_type: ty,
            packet_number: pn,
            ack_eliciting: false,
            in_flight: false,
            probe_new_path: false,
            largest_ack: None,
        }
    }

    pub fn epoch(&self) -> Option<Epoch> {
        match self.packet_type() {
            Type::Long(long) => match long {
                r#type::long::Type::VersionNegotiation => None,
                r#type::long::Type::V1(version) => match version.0 {
                    r#type::long::v1::Type::Initial => Some(Epoch::Initial),
                    r#type::long::v1::Type::ZeroRtt => Some(Epoch::Data),
                    r#type::long::v1::Type::Handshake => Some(Epoch::Handshake),
                    r#type::long::v1::Type::Retry => None,
                },
            },
            Type::Short(..) => Some(Epoch::Data),
        }
    }

    pub fn add_frame<F: FrameFeature + 'static>(&mut self, frame: &F) {
        debug_assert!(
            frame.belongs_to(self.packet_type()),
            "Frame {:?} does not belong to packet type {:?}",
            std::any::type_name_of_val(frame),
            self.packet_type()
        );
        self.ack_eliciting |= !frame.specs().contain(Spec::NonAckEliciting);
        self.in_flight |= !frame.specs().contain(Spec::CongestionControlFree);
        self.probe_new_path |= frame.specs().contain(Spec::ProbeNewPath);
        if let Some(ack_frame) = (frame as &dyn Any).downcast_ref::<AckFrame>() {
            self.largest_ack = Some(match self.largest_ack {
                Some(largest_ack) => largest_ack.max(ack_frame.largest()),
                None => ack_frame.largest(),
            });
        }
    }
}

pub trait RecordFrame<F, D: Buffer> {
    fn record_frame(&mut self, frame: &F);
}

impl<D: Buffer> RecordFrame<Frame<D>, D> for PacketInfo {
    fn record_frame(&mut self, frame: &Frame<D>) {
        debug_assert!(
            frame.belongs_to(self.packet_type(),),
            "Frame {:?} does not belong to packet type {:?}",
            frame.frame_type(),
            self.packet_type()
        );
        self.ack_eliciting |= !frame.specs().contain(Spec::NonAckEliciting);
        self.in_flight |= !frame.specs().contain(Spec::CongestionControlFree);
        self.probe_new_path |= frame.specs().contain(Spec::ProbeNewPath);
        if let Frame::Ack(ack_frame) = frame {
            self.largest_ack = Some(match self.largest_ack {
                Some(largest_ack) => largest_ack.max(ack_frame.largest()),
                None => ack_frame.largest(),
            });
        }
    }
}

impl<F, D: Buffer> RecordFrame<F, D> for PacketWriter<'_>
where
    PacketInfo: RecordFrame<F, D>,
{
    #[inline]
    fn record_frame(&mut self, frame: &F) {
        self.pkt_info.record_frame(frame);
    }
}

pub struct PacketWriter<'b> {
    keys: Keys,
    layout: PacketLayout,
    pkt_info: PacketInfo,
    buffer: &'b mut [u8],
}

impl<'b> PacketWriter<'b> {
    pub fn new_long<S>(
        header: &LongHeader<S>,
        buffer: &'b mut [u8],
        (actual_pn, encoded_pn): (u64, PacketNumber),
        keys: DirectionalKeys,
    ) -> Result<Self, Poll<()>>
    where
        S: HeaderSize,
        LongHeader<S>: GetType,
        for<'a> &'a mut [u8]: WriteHeader<LongHeader<S>>,
    {
        let hdr_len = header.size();
        let len_encoding = header.length_encoding();
        if buffer.len() < hdr_len + len_encoding + 20 {
            return Err(Poll::Ready(()));
        }

        let (mut hdr_buf, mut payload_buf) = buffer.split_at_mut(hdr_len + len_encoding);
        hdr_buf.put_header(header);
        payload_buf.put_packet_number(encoded_pn);

        let cursor = hdr_len + len_encoding + encoded_pn.size();
        Ok(Self {
            layout: PacketLayout {
                hdr_len,
                len_encoding,
                pn_len: encoded_pn.size(),
                cursor,
                end: buffer.len() - keys.packet.tag_len(),
            },
            keys: Keys::LongHeaderPacket { keys },
            pkt_info: PacketInfo::new(header.get_type(), actual_pn),
            buffer,
        })
    }

    pub fn new_short(
        header: &OneRttHeader,
        buffer: &'b mut [u8],
        (actual_pn, encoded_pn): (u64, PacketNumber),
        keys: DirectionalKeys,
        key_phase: KeyPhaseBit,
    ) -> Result<Self, Poll<()>> {
        let hdr_len = header.size();
        if buffer.len() < hdr_len + 20 {
            return Err(Poll::Ready(()));
        }

        let (mut hdr_buf, mut payload_buf) = buffer.split_at_mut(hdr_len);
        hdr_buf.put_header(header);
        payload_buf.put_packet_number(encoded_pn);
        Ok(Self {
            layout: PacketLayout {
                hdr_len,
                len_encoding: 0,
                pn_len: encoded_pn.size(),
                cursor: hdr_len + encoded_pn.size(),
                end: buffer.len() - keys.packet.tag_len(),
            },
            keys: Keys::ShortHeaderPacket { keys, key_phase },
            pkt_info: PacketInfo::new(header.get_type(), actual_pn),
            buffer,
        })
    }

    #[inline]
    pub fn buffer(&self) -> &[u8] {
        self.buffer
    }

    #[inline]
    pub fn is_short_header(&self) -> bool {
        self.keys.key_phase().is_some()
    }

    #[inline]
    pub fn packet_type(&self) -> Type {
        self.pkt_info.packet_type()
    }

    #[inline]
    pub fn packet_number(&self) -> u64 {
        self.pkt_info.packet_number
    }

    #[inline]
    pub fn is_ack_eliciting(&self) -> bool {
        self.pkt_info.ack_eliciting
    }

    #[inline]
    pub fn in_flight(&self) -> bool {
        self.pkt_info.in_flight
    }

    #[inline]
    pub fn is_probe_new_path(&self) -> bool {
        self.pkt_info.probe_new_path
    }

    #[inline]
    pub fn payload_len(&self) -> usize {
        self.layout.payload_len()
    }

    #[inline]
    pub fn tag_len(&self) -> usize {
        self.keys.pk().tag_len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.layout.is_empty()
    }

    #[inline]
    pub fn packet_len(&self) -> usize {
        self.layout.cursor + self.keys.pk().tag_len()
    }
}

unsafe impl BufMut for PacketWriter<'_> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.layout.end - self.layout.cursor
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        if self.remaining_mut() < cnt {
            panic!(
                "advance out of bounds: the len is {} but advancing by {}",
                cnt,
                self.remaining_mut()
            );
        }

        self.layout.cursor += cnt;
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        let range = self.layout.cursor..self.layout.end;
        UninitSlice::new(&mut self.buffer[range])
    }
}

pub trait AssemblePacket: Assemble<1> {
    fn encrypt_and_protect_packet(self) -> (usize, PacketInfo);
}

impl<const N: usize> Assemble<N> for PacketWriter<'_> {
    type Buffer = Self;

    fn assemble(
        &mut self,
        cx: &mut Context<'_>,
        sources: [&mut dyn Package<Self>; N],
        frames: &mut Vec<Frame>,
    ) -> Poll<Result<usize, crate::error::Error>> {
        let start = frames.len();
        // This writer already excludes the authentication tag from its BufMut view.
        let mut limits = Constraints {
            flow_ctrl: usize::MAX,
            send_quota: usize::MAX,
            credit: usize::MAX,
            min_size: (self.layout.hdr_len + self.layout.len_encoding + 20)
                .saturating_sub(self.tag_len()),
            max_size: self.layout.end,
            ..Default::default()
        };
        let packet_type = self.packet_type();
        let written = self.layout.cursor;
        let mut buffer = ConstraintBuffer::new(self, &mut limits, packet_type, written, 0);
        let mut result = Poll::Pending;
        for source in sources {
            match source.poll_dump(cx, &mut buffer, frames) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => result = Poll::Ready(Ok(0)),
                Poll::Pending => {}
            }
        }
        if frames.len() == start {
            return result;
        }
        let padding = buffer.limits.min_size().saturating_sub(buffer.written());
        if padding != 0 {
            // Keep an omitted-LEN final frame final: put HP padding before the frames.
            let body = self.layout.hdr_len + self.layout.len_encoding + self.layout.pn_len;
            self.buffer
                .copy_within(body..self.layout.cursor, body + padding);
            self.buffer[body..body + padding].fill(0);
            self.layout.cursor += padding;
            frames.insert(start, Frame::Padding(PaddingFrame));
        }
        for frame in &frames[start..] {
            self.record_frame(frame);
        }
        Poll::Ready(Ok(frames.len() - start))
    }
}

impl AssemblePacket for PacketWriter<'_> {
    fn encrypt_and_protect_packet(self) -> (usize, PacketInfo) {
        use crate::{
            packet::encrypt::*,
            varint::{EncodeBytes, VarInt, WriteVarInt},
        };

        let Self {
            keys,
            layout,
            pkt_info,
            buffer,
        } = self;

        let payload_len = layout.payload_len();
        let tag_len = keys.pk().tag_len();

        let actual_pn = pkt_info.packet_number;
        let pn_len = layout.pn_len;
        let pkt_size = layout.cursor + tag_len;

        assert!(
            payload_len + tag_len >= 20,
            "The payload and tag needs at least 20 bytes to have enough samples for the packet header protection."
        );

        if let Some(key_phase) = keys.key_phase() {
            encode_short_first_byte(&mut buffer[0], pn_len, key_phase);

            let pk = keys.pk();
            let payload_offset = layout.hdr_len;
            let body_offset = payload_offset + pn_len;
            encrypt_packet(pk, actual_pn, &mut buffer[..pkt_size], body_offset);

            let hpk = keys.hpk();
            protect_header(hpk, &mut buffer[..pkt_size], payload_offset, pn_len);
        } else {
            let packet_len = payload_len + tag_len;
            let len_buffer_range = layout.hdr_len..layout.hdr_len + layout.len_encoding;
            let mut len_buf = &mut buffer[len_buffer_range];
            len_buf.encode_varint(&VarInt::try_from(packet_len).unwrap(), EncodeBytes::Two);

            encode_long_first_byte(&mut buffer[0], pn_len);

            let pk = keys.pk();
            let payload_offset = layout.hdr_len + layout.len_encoding;
            let body_offset = payload_offset + pn_len;
            encrypt_packet(pk, actual_pn, &mut buffer[..pkt_size], body_offset);

            let hpk = keys.hpk();
            protect_header(hpk, &mut buffer[..pkt_size], payload_offset, pn_len);
        }
        (pkt_size, pkt_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{frame::CryptoFrame, varint::VarInt};

    struct TransparentKeys;

    impl rustls::quic::PacketKey for TransparentKeys {
        fn decrypt_in_place<'a>(
            &self,
            _packet_number: u64,
            _header: &[u8],
            payload: &'a mut [u8],
        ) -> Result<&'a [u8], rustls::Error> {
            Ok(&payload[..payload.len() - self.tag_len()])
        }

        fn encrypt_in_place(
            &self,
            _packet_number: u64,
            _header: &[u8],
            _payload: &mut [u8],
        ) -> Result<rustls::quic::Tag, rustls::Error> {
            Ok(rustls::quic::Tag::from("transparent_keys".as_bytes()))
        }

        fn confidentiality_limit(&self) -> u64 {
            0
        }

        fn integrity_limit(&self) -> u64 {
            0
        }

        fn tag_len(&self) -> usize {
            16
        }
    }

    impl rustls::quic::HeaderProtectionKey for TransparentKeys {
        fn decrypt_in_place(
            &self,
            _sample: &[u8],
            _first_byte: &mut u8,
            _payload: &mut [u8],
        ) -> Result<(), rustls::Error> {
            Ok(())
        }

        fn encrypt_in_place(
            &self,
            _sample: &[u8],
            _first_byte: &mut u8,
            _payload: &mut [u8],
        ) -> Result<(), rustls::Error> {
            Ok(())
        }

        fn sample_len(&self) -> usize {
            20
        }
    }

    #[test]
    fn header_protection_padding_precedes_an_omitted_length_stream() {
        let mut bytes = [0; 64];
        let keys = DirectionalKeys {
            packet: Box::new(TransparentKeys),
            header: Box::new(TransparentKeys),
        };
        let header = OneRttHeader::new(Default::default(), Default::default());
        let mut packet = PacketWriter::new_short(
            &header,
            &mut bytes,
            (0, PacketNumber::U8(0)),
            keys,
            Default::default(),
        )
        .unwrap();
        let sid = crate::sid::StreamId::new(crate::role::Role::Client, crate::sid::Dir::Bi, 0);
        let mut source = (StreamFrame::new(sid, 0, 0), b"".as_slice());
        let mut frames = Vec::new();
        assert!(matches!(
            packet.assemble(
                &mut Context::from_waker(std::task::Waker::noop()),
                [&mut source],
                &mut frames
            ),
            Poll::Ready(Ok(2))
        ));
        assert!(matches!(
            frames.as_slice(),
            [Frame::Padding(_), Frame::Stream(_, ())]
        ));
        let body = packet.layout.hdr_len + packet.layout.pn_len;
        let decoded = FrameReader::new(
            BytesMut::from(&packet.buffer[body..packet.layout.cursor]).freeze(),
            header.get_type(),
        )
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        assert_eq!(decoded.len(), 2);
        assert!(
            matches!(&decoded[1].0, Frame::Stream(frame, data) if frame.is_empty() && data.is_empty())
        );
        assert_eq!(packet.payload_len() + packet.tag_len(), 20);
    }

    #[test]
    fn test_initial_packet_writer() {
        let mut buffer = vec![0u8; 128];
        let header = LongHeaderBuilder::with_cid(
            ConnectionId::from_slice("testdcid".as_bytes()),
            ConnectionId::from_slice("testscid".as_bytes()),
        )
        .initial(b"test_token".to_vec());

        let pn = (0, PacketNumber::encode(0, 0));

        let keys = DirectionalKeys {
            packet: Box::new(TransparentKeys),
            header: Box::new(TransparentKeys),
        };

        let mut writer = PacketWriter::new_long(&header, &mut buffer, pn, keys).unwrap();
        let frame = CryptoFrame::new(VarInt::from_u32(0), VarInt::from_u32(12));
        assert!(matches!(
            writer.assemble(
                &mut Context::from_waker(std::task::Waker::noop()),
                [&mut (frame, "client_hello".as_bytes())],
                &mut Vec::new(),
            ),
            Poll::Ready(Ok(1))
        ));
        assert!(writer.is_ack_eliciting());
        assert!(writer.in_flight());

        let (sent_bytes, final_packet_layout) = writer.encrypt_and_protect_packet();
        assert!(final_packet_layout.ack_eliciting());
        assert!(final_packet_layout.in_flight());
        assert_eq!(sent_bytes, 69);
        assert_eq!(
            &buffer[..sent_bytes],
            [
                // initial packet:
                // header form (1) = 1,, long header
                // fixed bit (1) = 1,
                // long packet type (2) = 0, initial packet
                // reserved bits (2) = 0,
                // packet number length (2) = 0, 1 byte
                193, // first byte
                0, 0, 0, 1, // quic version
                // destination connection id, "testdcid"
                8, // dcid length
                b't', b'e', b's', b't', b'd', b'c', b'i', b'd', // dcid bytes
                // source connection id, "testscid"
                8, // scid length
                b't', b'e', b's', b't', b's', b'c', b'i', b'd', // scid bytes
                10,   // token length, no token
                b't', b'e', b's', b't', b'_', b't', b'o', b'k', b'e', b'n', // token bytes
                64, 33, // payload length, 2 bytes encoded varint
                0, 0, // encoded packet number
                // crypto frame header
                6,  // crypto frame type
                0,  // crypto frame offset
                12, // crypto frame length
                // crypto frame data, "client hello"
                b'c', b'l', b'i', b'e', b'n', b't', b'_', b'h', b'e', b'l', b'l', b'o',
                // tag, "transparent_keys"
                b't', b'r', b'a', b'n', b's', b'p', b'a', b'r', b'e', b'n', b't', b'_', b'k', b'e',
                b'y', b's',
            ]
            .as_slice()
        );

        let mut padded = BytesMut::from(&buffer[..sent_bytes]);
        padded.resize(1200, 0);
        let Packet::Data(packet) = PacketReader::new(padded, 8).next().unwrap().unwrap() else {
            panic!("expected Initial packet");
        };
        assert_eq!(packet.bytes.len(), sent_bytes);

        let mut coalesced = BytesMut::from(&buffer[..sent_bytes]);
        coalesced.extend_from_slice(&buffer[..sent_bytes]);
        let mut packets = PacketReader::new(coalesced, 8);
        let Packet::Data(_first) = packets.next().unwrap().unwrap() else {
            panic!("expected first Initial packet");
        };
        let Packet::Data(_second) = packets.next().unwrap().unwrap() else {
            panic!("expected second Initial packet");
        };
        assert!(packets.next().is_none());
    }
}
