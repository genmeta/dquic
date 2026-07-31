use std::{fmt::Debug, ops};

use bytes::{BufMut, BytesMut, buf::UninitSlice};
use derive_more::{Deref, DerefMut};
use enum_dispatch::enum_dispatch;
use getset::CopyGetters;
use header::{LongHeader, io::WriteHeader};

use crate::{
    cid::ConnectionId,
    frame::{ContainSpec, FrameFeature, FrameType, Spec},
    packet::keys::DirectionalKeys,
};

/// QUIC packet parse error definitions.
pub mod error;

/// Define signal util, such as key phase bit and spin bit.
pub mod signal;
#[doc(hidden)]
pub use signal::{KeyPhaseBit, SpinBit};

/// Definitions of QUIC packet types.
pub mod r#type;
#[doc(hidden)]
pub use r#type::{
    GetPacketNumberLength, LONG_RESERVED_MASK, LongSpecificBits, SHORT_RESERVED_MASK,
    ShortSpecificBits, Type,
};

/// Definitions of QUIC packet headers.
pub mod header;
#[doc(hidden)]
pub use header::{
    EncodeHeader, GetDcid, GetScid, GetType, HandshakeHeader, Header, InitialHeader,
    LongHeaderBuilder, OneRttHeader, RetryHeader, VersionNegotiationHeader, ZeroRttHeader, long,
};

/// The io module provides the functions to parse the QUIC packet.
///
/// The writing of the QUIC packet is not provided here, they are written in place.
pub mod io;
pub use io::{
    AssemblePacket, Package, PacketInfo, PacketSpace, PacketWriter, ProductHeader, RecordFrame,
};

/// Encoding and decoding of packet number
pub mod number;
#[doc(hidden)]
pub use number::{InvalidPacketNumber, PacketNumber, WritePacketNumber, take_pn_len};

/// Include operations such as decrypting QUIC packets, removing header protection,
/// and parsing the first byte of the packet to get the right packet numbers
pub mod decrypt;

/// Include operations such as encrypting QUIC packets, adding header protection,
/// and encoding the first byte of the packet with pn_len and key_phase optionally.
pub mod encrypt;

/// Encapsulate the crypto keys's logic for long headers and 1-RTT headers.
pub mod keys;

/// The sum type of all QUIC packet headers.
#[derive(Debug, Clone)]
#[enum_dispatch(GetDcid, GetType)]
pub enum DataHeader {
    Long(long::DataHeader),
    Short(OneRttHeader),
}

/// The sum type of all QUIC data packets.
///
/// The long header has the len field, the short header does not have the len field.
/// Remember, the len field is not an attribute of the header, but a attribute of the packet.
///
/// ```text
///                                 +---> payload length in long packet
///                                 |     |<----------- payload --------->|
/// +-----------+---+--------+------+-----+-----------+---......--+-------+
/// |X|1|X X 0 0|0 0| ...hdr | len(0..16) | pn(8..32) | body...   |  tag  |
/// +---+-------+-+-+--------+------------+-----+-----+---......--+-------+
///               |                             |
///               +---> encoded pn length       +---> encoded packet number
/// ```
#[derive(Debug, Clone, Deref, DerefMut)]
pub struct DataPacket {
    #[deref]
    #[deref_mut]
    pub header: DataHeader,
    pub bytes: BytesMut,
    // payload_offset
    pub offset: usize,
}

impl GetType for DataPacket {
    fn get_type(&self) -> Type {
        self.header.get_type()
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub enum PacketContent {
    #[default]
    NonAckEliciting,
    JustPing,
    EffectivePayload,
}

impl PacketContent {
    pub fn is_ack_eliciting(self) -> bool {
        self != Self::NonAckEliciting
    }
}

impl From<FrameType> for PacketContent {
    fn from(frame_type: FrameType) -> Self {
        match frame_type {
            FrameType::Ping => Self::JustPing,
            fty if !fty.specs().contain(Spec::NonAckEliciting) => Self::EffectivePayload,
            _ => Self::NonAckEliciting,
        }
    }
}

impl ops::AddAssign<FrameType> for PacketContent {
    fn add_assign(&mut self, rhs: FrameType) {
        match rhs {
            FrameType::Ping if *self == PacketContent::NonAckEliciting => *self = Self::JustPing,
            fty if !fty.specs().contain(Spec::NonAckEliciting) => *self = Self::EffectivePayload,
            _ => (),
        }
    }
}

impl ops::AddAssign for PacketContent {
    fn add_assign(&mut self, rhs: Self) {
        match rhs {
            PacketContent::EffectivePayload => *self = PacketContent::EffectivePayload,
            PacketContent::JustPing if *self == PacketContent::NonAckEliciting => {
                *self = PacketContent::JustPing
            }
            _ => {}
        }
    }
}

/// The sum type of all QUIC packets.
#[derive(Debug, Clone)]
pub enum Packet {
    VN(VersionNegotiationHeader),
    Retry(RetryHeader),
    // Data(header, bytes, payload_offset)
    Data(DataPacket),
}

/// QUIC packet reader, reading packets from the incoming datagrams.
///
/// The parsing here does not involve removing header protection or decrypting the packet.
/// It only parses information such as packet type and connection ID,
/// and prepares for further delivery to the connection by finding the connection ID.
///
/// The received packet is a BytesMut, in order to be decrypted in future, and make as few
/// copies cheaply until it is read by the application layer.
///
/// Each item also carries the size of its containing UDP datagram. For a coalesced datagram,
/// only the first item carries the size; later items carry zero so receive accounting happens once.
#[derive(Debug)]
pub struct PacketReader {
    raw_bytes: BytesMut,
    dcid_len: usize,
    datagram_size: usize,
    // TODO: 添加level，各种包类型顺序不能错乱，否则失败
}

impl PacketReader {
    pub fn new(raw_bytes: BytesMut, dcid_len: usize) -> Self {
        let datagram_size = raw_bytes.len();
        Self::with_datagram_size(raw_bytes, dcid_len, datagram_size)
    }

    pub fn with_datagram_size(raw_bytes: BytesMut, dcid_len: usize, datagram_size: usize) -> Self {
        Self {
            raw_bytes,
            dcid_len,
            datagram_size,
        }
    }
}

impl Iterator for PacketReader {
    type Item = Result<(Packet, usize), error::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw_bytes.is_empty() {
            return None;
        }

        match io::be_packet(&mut self.raw_bytes, self.dcid_len) {
            Ok(packet) => Some(Ok((packet, std::mem::take(&mut self.datagram_size)))),
            Err(error) => {
                tracing::debug!(target: "dquic", ?error, "dropped unparsed packet");
                self.raw_bytes.clear(); // no longer parsing
                Some(Err(error))
            }
        }
    }
}
