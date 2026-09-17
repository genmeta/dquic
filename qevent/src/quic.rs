use std::{
    collections::HashMap, fmt::Display, marker::PhantomData, net::SocketAddr, time::Duration,
};

use bytes::Bytes;
use derive_builder::Builder;
use derive_more::{From, Into, LowerHex};
use qbase::{
    frame::{
        AckFrame, ConnectionCloseFrame, CryptoFrame, DatagramFrame, EncodeSize, Frame,
        GetFrameType, MaxStreamsFrame, NewTokenFrame, PathChallengeFrame, PathResponseFrame,
        PingFrame, ReliableFrame, StreamCtlFrame, StreamFrame, StreamsBlockedFrame,
    },
    packet::header::{
        GetDcid, GetScid,
        long::{HandshakeHeader, InitialHeader, ZeroRttHeader},
        short::OneRttHeader,
    },
    util::Buffer,
    varint::VarInt,
};
use serde::{Deserialize, Serialize};

pub mod connectivity;
pub mod recovery;
pub mod security;
pub mod transport;

use crate::{BeSpecificEventData, HexString, RawInfo};

// 8.1
#[derive(Debug, Clone, From, Into, PartialEq, Eq)]
pub struct QuicVersion(u32);

impl Serialize for QuicVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[serde_with::serde_as]
        #[derive(Serialize)]
        struct Helper(#[serde_as(as = "serde_with::hex::Hex")] [u8; 4]);
        Helper(self.0.to_be_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for QuicVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[serde_with::serde_as]
        #[derive(Deserialize)]
        struct Helper(#[serde_as(as = "serde_with::hex::Hex")] [u8; 4]);
        Helper::deserialize(deserializer).map(|b| Self(u32::from_be_bytes(b.0)))
    }
}

// 8.2
// TOOD: 这些结构的序列化/反序列化之后都可以写到qbase中，也不重复写两份结构
#[derive(Default, Debug, LowerHex, From, Into, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionID(qbase::cid::ConnectionId);

impl Serialize for ConnectionID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[serde_with::serde_as]
        #[derive(Serialize)]
        struct Helper<'b>(#[serde_as(as = "serde_with::hex::Hex")] &'b [u8]);

        Helper(self.0.as_ref()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ConnectionID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[serde_with::serde_as]
        #[derive(Deserialize)]
        struct Helper(#[serde_as(as = "serde_with::hex::Hex")] Vec<u8>);

        let bytes = Helper::deserialize(deserializer)?.0;
        if bytes.len() > qbase::cid::MAX_CID_SIZE {
            return Err(serde::de::Error::custom("ConnectionID too long"));
        }
        Ok(Self(qbase::cid::ConnectionId::from_slice(&bytes)))
    }
}

// 8.3
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    Local,
    Remote,
}

// 8.4
/// an IPAddress can either be a "human readable" form
/// (e.g., "127.0.0.1" for v4 or
/// "2001:0db8:85a3:0000:0000:8a2e:0370:7334" for v6) or
/// use a raw byte-form (as the string forms can be ambiguous).
/// Additionally, a hash-based or redacted representation
/// can be used if needed for privacy or security reasons.
#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct IPAddress(String);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde_with::skip_serializing_none]
#[serde(rename_all = "snake_case")]
pub enum IpVersion {
    V4,
    V6,
}

// 8.5
/// PathEndpointInfo indicates a single half/direction of a path.  A full
/// path is comprised of two halves.  Firstly: the server sends to the
/// remote client IP + port using a specific destination Connection ID.
/// Secondly: the client sends to the remote server IP + port using a
/// different destination Connection ID.
///
/// As such, structures logging path information SHOULD include two
/// different PathEndpointInfo instances, one for each half of the path.
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct PathEndpointInfo {
    ip_v4: Option<IPAddress>,
    ip_v6: Option<IPAddress>,
    port_v4: Option<u16>,
    port_v6: Option<u16>,

    /// Even though usually only a single ConnectionID
    /// is associated with a given path at a time,
    /// there are situations where there can be an overlap
    /// or a need to keep track of previous ConnectionIDs
    conenction_ids: Vec<ConnectionID>,
}

impl From<SocketAddr> for PathEndpointInfo {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(addr) => crate::build!(PathEndpointInfo {
                ip_v4: addr.ip().to_string(),
                port_v4: addr.port(),
            }),
            SocketAddr::V6(addr) => crate::build!(PathEndpointInfo {
                ip_v6: addr.ip().to_string(),
                port_v6: addr.port(),
            }),
        }
    }
}

// 8.6
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketType {
    Initial,
    Handshake,
    #[serde(rename = "0RTT")]
    ZeroRTT,
    #[serde(rename = "1RTT")]
    OneRTT,
    Retry,
    VersionNegotiation,
    StatelessReset,
    Unknown,
}

impl From<qbase::packet::Type> for PacketType {
    fn from(r#type: qbase::packet::Type) -> Self {
        match r#type {
            qbase::packet::r#type::Type::Long(long) => match long {
                qbase::packet::r#type::long::Type::VersionNegotiation => {
                    PacketType::VersionNegotiation
                }
                qbase::packet::r#type::long::Type::V1(
                    qbase::packet::r#type::long::Version::INITIAL,
                ) => PacketType::Initial,
                qbase::packet::r#type::long::Type::V1(
                    qbase::packet::r#type::long::Version::HANDSHAKE,
                ) => PacketType::Handshake,
                qbase::packet::r#type::long::Type::V1(
                    qbase::packet::r#type::long::Version::ZERO_RTT,
                ) => PacketType::ZeroRTT,
                qbase::packet::r#type::long::Type::V1(
                    qbase::packet::r#type::long::Version::RETRY,
                ) => PacketType::Retry,
            },
            qbase::packet::r#type::Type::Short(_one_rtt) => PacketType::OneRTT,
        }
    }
}

// 8.7
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketNumberSpace {
    Initial,
    Handshake,
    ApplicationData,
}

impl From<qbase::Epoch> for PacketNumberSpace {
    fn from(value: qbase::Epoch) -> Self {
        match value {
            qbase::Epoch::Initial => Self::Initial,
            qbase::Epoch::Handshake => Self::Handshake,
            qbase::Epoch::Data => Self::ApplicationData,
        }
    }
}

// 8.8
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct PacketHeader {
    #[builder(default)]
    #[serde(default)]
    quic_bit: bool,
    packet_type: PacketType,

    /// only if packet_type === "initial" || "handshake" || "0RTT" || "1RTT"
    #[builder(default)]
    packet_number: Option<u64>,

    ///  the bit flags of the packet headers (spin bit, key update bit,
    /// etc. up to and including the packet number length bits
    /// if present
    #[builder(default)]
    flags: Option<u8>,

    /// only if packet_type === "initial" || "retry"
    #[builder(default)]
    token: Option<Token>,

    /// only if packet_type === "initial" || "handshake" || "0RTT"
    /// Signifies length of the packet_number plus the payload
    #[builder(default)]
    length: Option<u16>,

    /// only if present in the header
    /// if correctly using transport:connection_id_updated events,
    /// dcid can be skipped for 1RTT packets
    #[builder(default)]
    version: Option<QuicVersion>,
    #[builder(default)]
    scil: Option<u8>,
    #[builder(default)]
    dcil: Option<u8>,
    #[builder(default)]
    scid: Option<ConnectionID>,
    #[builder(default)]
    dcid: Option<ConnectionID>,
}

impl PacketHeaderBuilder {
    /// Helper method used to set the fields of the initial header,
    ///
    /// Since the header defined by qbase is not complete enough, there are still many fields that need to be set manually.
    pub fn initial(&mut self, header: &InitialHeader) -> &mut Self {
        crate::build!(@field self,
            packet_type: PacketType::Initial,
            ?token: Token::try_from(header).ok(),
            scil: header.scid().len() as u8,
            scid: { *header.scid() },
            dcil: header.dcid().len() as u8,
            dcid: { *header.dcid() }
        );
        self
    }

    /// Helper method used to set the fields of the handshake header,
    ///
    /// Since the header defined by qbase is not complete enough, there are still many fields that need to be set manually.
    pub fn handshake(&mut self, header: &HandshakeHeader) -> &mut Self {
        self.packet_type(PacketType::Handshake)
            .scil(header.scid().len() as u8)
            .scid(*header.scid())
            .dcil(header.dcid().len() as u8)
            .dcid(*header.dcid())
    }

    /// Helper method used to set the fields of the 0rtt header,
    ///
    /// Since the header defined by qbase is not complete enough, there are still many fields that need to be set manually.
    pub fn zero_rtt(&mut self, header: &ZeroRttHeader) -> &mut Self {
        self.packet_type(PacketType::ZeroRTT)
            .scil(header.scid().len() as u8)
            .scid(*header.scid())
            .dcil(header.dcid().len() as u8)
            .dcid(*header.dcid())
    }

    /// Helper method used to set the fields of the 1rtt header,
    ///
    /// Since the header defined by qbase is not complete enough, there are still many fields that need to be set manually.
    pub fn one_rtt(&mut self, header: &OneRttHeader) -> &mut Self {
        self.packet_type(PacketType::OneRTT)
            .dcil(header.dcid().len() as u8)
            .dcid(*header.dcid())
    }
}

impl From<&InitialHeader> for PacketHeaderBuilder {
    fn from(header: &InitialHeader) -> Self {
        let mut builder = PacketHeader::builder();
        builder.initial(header);
        builder
    }
}

impl From<&HandshakeHeader> for PacketHeaderBuilder {
    fn from(header: &HandshakeHeader) -> Self {
        let mut builder = PacketHeader::builder();
        builder.handshake(header);
        builder
    }
}

impl From<&ZeroRttHeader> for PacketHeaderBuilder {
    fn from(header: &ZeroRttHeader) -> Self {
        let mut builder = PacketHeader::builder();
        builder.zero_rtt(header);
        builder
    }
}

impl From<&OneRttHeader> for PacketHeaderBuilder {
    fn from(header: &OneRttHeader) -> Self {
        let mut builder = PacketHeader::builder();
        builder.one_rtt(header);
        builder
    }
}

// 8.9
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
#[serde(default)]
pub struct Token {
    pub r#type: Option<TokenType>,

    /// decoded fields included in the token
    /// (typically: peer's IP address, creation time)
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    details: HashMap<String, serde_json::Value>,

    raw: Option<RawInfo>,
}

impl<H: 'static> TryFrom<&qbase::packet::header::LongHeader<H>> for Token {
    type Error = ();
    fn try_from(header: &qbase::packet::header::LongHeader<H>) -> Result<Self, Self::Error> {
        use qbase::packet::header::RetryHeader;
        let header: &dyn core::any::Any = header;
        if let Some(initial) = header.downcast_ref::<InitialHeader>() {
            if initial.token().is_empty() {
                return Err(());
            }
            return Ok(crate::build!(Token {
                // r#type: TokenType::?
                raw: initial.token(),
            }));
        }
        if let Some(retry) = header.downcast_ref::<RetryHeader>() {
            return Ok(crate::build!(Token {
                r#type: TokenType::Retry,
                raw: retry.token(),
            }));
        }
        Err(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Retry,
    Resumption,
}

// 8.10
#[serde_with::serde_as]
#[derive(Debug, Clone, Copy, From, Into, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatelessResetToken(#[serde_as(as = "serde_with::hex::Hex")] [u8; 16]);

impl From<qbase::token::ResetToken> for StatelessResetToken {
    fn from(value: qbase::token::ResetToken) -> Self {
        Self(*value)
    }
}

// 8.11
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    ServerInitialSecret,
    ClientInitialSecret,
    ServerHandshakeSecret,
    ClientHandshakeSecret,
    #[serde(rename = "server_0rtt_secret")]
    Server0RttSecret,
    #[serde(rename = "client_0rtt_secret")]
    Client0RttSecret,
    #[serde(rename = "server_1rtt_secret")]
    Server1RttSecret,
    #[serde(rename = "client_1rtt_secret")]
    Client1RttSecret,
}

// 8.12
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ECN {
    #[serde(rename = "Not-ECT")]
    NotEct,
    #[serde(rename = "ECT(1)")]
    Ect1,
    #[serde(rename = "ECT(0)")]
    Ect0,
    CE,
}

// 8.13
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "frame_type")]
#[serde(rename_all = "snake_case")]
pub enum QuicFrame {
    Padding {
        /// total frame length, including frame header
        length: Option<u32>,
        payload_length: u32,
    },
    Ping {
        /// total frame length, including frame header
        length: Option<u32>,
        payload_length: Option<u32>,
    },
    Ack {
        /// in ms
        ack_delay: Option<f32>,

        /// e.g., looks like \[\[1,2],\[4,5], \[7], \[10,22]] serialized
        ///
        /// ### AckRange:
        /// either a single number (e.g., \[1]) or two numbers (e.g., \[1,2]).
        ///
        /// For two numbers:
        ///
        /// the first number is "from": lowest packet number in interval
        ///
        /// the second number is "to": up to and including the highest
        /// packet number in the interval
        acked_ranges: Vec<[u64; 2]>,

        /// ECN (explicit congestion notification) related fields
        /// (not always present)
        ect1: Option<u64>,
        ect0: Option<u64>,
        ce: Option<u64>,

        /// total frame length, including frame header
        length: Option<u32>,
        payload_length: Option<u32>,
    },
    ResetStream {
        stream_id: u64,
        error_code: ApplicationCode,

        /// in bytes
        final_size: u64,

        /// total frame length, including frame header
        length: Option<u32>,
        payload_length: Option<u32>,
    },
    StopSending {
        stream_id: u64,
        error_code: ApplicationCode,

        /// total frame length, including frame header
        length: Option<u32>,
        payload_length: Option<u32>,
    },
    Crypto {
        offset: u64,
        length: u64,
        payload_length: Option<u32>,
        raw: Option<RawInfo>,
    },
    NewToken {
        token: Token,
    },
    Stream {
        stream_id: u64,

        /// These two MUST always be set
        /// If not present in the Frame type, log their default values
        offset: u64,
        length: u64,

        /// this MAY be set any time,
        /// but MUST only be set if the value is true
        /// if absent, the value MUST be assumed to be false
        #[serde(default)]
        fin: bool,
        raw: Option<RawInfo>,
    },
    MaxData {
        maximum: u64,
    },
    MaxStreamData {
        stream_id: u64,
        maximum: u64,
    },
    MaxStreams {
        stream_type: StreamType,
        maximum: u64,
    },
    DataBlocked {
        limit: u64,
    },
    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },
    StreamsBlocked {
        stream_type: StreamType,
        limit: u64,
    },
    NewConnectionId {
        sequence_number: u32,
        retire_prior_to: u32,

        /// mainly used if e.g., for privacy reasons the full
        /// connection_id cannot be logged
        connection_id_length: Option<u8>,
        connection_id: ConnectionID,
        stateless_reset_token: Option<StatelessResetToken>,
    },
    RetireConnectionId {
        sequence_number: u32,
    },
    PathChallenge {
        /// always 64-bit
        data: Option<HexString>,
    },
    PathResponse {
        /// always 64-bit
        data: Option<HexString>,
    },
    /// An endpoint that receives unknown error codes can record it in the
    /// error_code field using the numerical value without variable-length
    /// integer encoding.
    ///
    /// When the connection is closed due a connection-level error, the
    /// trigger_frame_type field can be used to log the frame that triggered
    /// the error.  For known frame types, the appropriate string value is
    /// used.  For unknown frame types, the numerical value without variable-
    /// length integer encoding is used.
    ///
    /// The CONNECTION_CLOSE reason phrase is a byte sequences.  It is likely
    /// that this sequence is presentable as UTF-8, in which case it can be
    /// logged in the reason field.  The reason_bytes field supports logging
    /// the raw bytes, which can be useful when the value is not UTF-8 or
    /// when an endpoint does not want to decode it.  Implementations SHOULD
    /// log at least one format, but MAY log both or none.
    ConnectionClose {
        error_space: Option<ConnectionCloseErrorSpace>,
        error_code: Option<ConnectionCloseErrorCode>,

        reason: Option<String>,
        reason_bytes: Option<HexString>,

        /// when error_space === "transport"
        trigger_frame_type: Option<ConnectionCloseTriggerFrameType>,
    },
    HandshakeDone {},
    /// The frame_type_bytes field is the numerical value without variable-
    /// length integer encoding.
    Unknow {
        frame_type_bytes: u64,
        raw: Option<RawInfo>,
    },
    Datagram {
        length: Option<u64>,
        raw: Option<RawInfo>,
    },
}

impl From<&PingFrame> for QuicFrame {
    fn from(frame: &PingFrame) -> Self {
        QuicFrame::Ping {
            length: Some(frame.encoding_size() as u32),
            payload_length: Some(0),
        }
    }
}

impl<D: Buffer + ?Sized> From<(&CryptoFrame, &D)> for QuicFrame {
    fn from((frame, data): (&CryptoFrame, &D)) -> Self {
        let payload_length = frame.len();
        let length = frame.encoding_size() as u64 + payload_length;
        QuicFrame::Crypto {
            offset: frame.offset(),
            length,
            payload_length: Some(payload_length as _),
            raw: Some(crate::build!(RawInfo {
                length,
                payload_length,
                data,
            })),
        }
    }
}

impl From<&CryptoFrame> for QuicFrame {
    fn from(frame: &CryptoFrame) -> Self {
        let payload_length = frame.len();
        let length = frame.encoding_size() as u64 + payload_length;
        QuicFrame::Crypto {
            offset: frame.offset(),
            length,
            payload_length: Some(payload_length as _),
            raw: Some(crate::build!(RawInfo {
                length,
                payload_length,
            })),
        }
    }
}

impl<D: Buffer + ?Sized> From<(&StreamFrame, &D)> for QuicFrame {
    fn from((frame, data): (&StreamFrame, &D)) -> Self {
        let payload_length = frame.len();
        let length = frame.encoding_size() + payload_length;
        QuicFrame::Stream {
            stream_id: frame.stream_id().into(),
            offset: frame.offset(),
            length: payload_length as u64,
            fin: frame.is_fin(),
            raw: Some(crate::build!(RawInfo {
                length: length as u64,
                payload_length: payload_length as u64,
                data: data,
            })),
        }
    }
}

impl From<&StreamFrame> for QuicFrame {
    fn from(frame: &StreamFrame) -> Self {
        let payload_length = frame.len();
        let length = frame.encoding_size() + payload_length;
        QuicFrame::Stream {
            stream_id: frame.stream_id().into(),
            offset: frame.offset(),
            length: payload_length as u64,
            fin: frame.is_fin(),
            raw: Some(crate::build!(RawInfo {
                length: length as u64,
                payload_length: payload_length as u64,
            })),
        }
    }
}

impl<D: Buffer + ?Sized> From<(&DatagramFrame, &D)> for QuicFrame {
    fn from((frame, data): (&DatagramFrame, &D)) -> Self {
        let payload_length = frame.len().into_u64();
        let length = frame.encoding_size() as u64 + payload_length;
        QuicFrame::Datagram {
            length: Some(payload_length as _),
            raw: Some(crate::build!(RawInfo {
                length,
                payload_length,
                data: data,
            })),
        }
    }
}

impl From<&DatagramFrame> for QuicFrame {
    fn from(frame: &DatagramFrame) -> Self {
        let payload_length = frame.len().into_u64();
        let length = frame.encoding_size() as u64 + payload_length;
        QuicFrame::Datagram {
            length: Some(payload_length as _),
            raw: Some(crate::build!(RawInfo {
                length,
                payload_length,
            })),
        }
    }
}

impl From<&PathChallengeFrame> for QuicFrame {
    fn from(frame: &PathChallengeFrame) -> Self {
        QuicFrame::PathChallenge {
            data: Some(Bytes::from_owner(frame.to_vec()).into()),
        }
    }
}

impl From<&PathResponseFrame> for QuicFrame {
    fn from(frame: &PathResponseFrame) -> Self {
        QuicFrame::PathResponse {
            data: Some(Bytes::from_owner(frame.to_vec()).into()),
        }
    }
}

impl From<&AckFrame> for QuicFrame {
    fn from(frame: &AckFrame) -> Self {
        Self::Ack {
            ack_delay: Some(Duration::from_micros(frame.delay()).as_secs_f32() * 1000.0),
            acked_ranges: frame
                .ranges()
                .iter()
                .fold(
                    (
                        frame.largest() - frame.first_range(),
                        vec![[frame.largest() - frame.first_range(), frame.largest()]],
                    ),
                    |(previous_smallest, mut acked_ranges), (gap, ack)| {
                        // see https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-ranges
                        let largest = previous_smallest - gap.into_u64() - 2;
                        let smallest = largest - ack.into_u64();
                        acked_ranges.push([smallest, largest]);
                        (smallest, acked_ranges)
                    },
                )
                .1,
            ect1: frame.ecn().map(|ecn| ecn.ect1()),
            ect0: frame.ecn().map(|ecn| ecn.ect0()),
            ce: frame.ecn().map(|ecn| ecn.ce()),
            length: Some(frame.encoding_size() as u32),
            payload_length: None,
        }
    }
}

impl From<&ReliableFrame> for QuicFrame {
    fn from(frame: &ReliableFrame) -> Self {
        match frame {
            ReliableFrame::NewToken(new_token_frame) => new_token_frame.into(),
            ReliableFrame::MaxData(max_data_frame) => QuicFrame::MaxData {
                maximum: max_data_frame.max_data(),
            },
            ReliableFrame::DataBlocked(data_blocked_frame) => QuicFrame::DataBlocked {
                limit: data_blocked_frame.limit(),
            },
            ReliableFrame::NewConnectionId(new_connection_id_frame) => QuicFrame::NewConnectionId {
                sequence_number: new_connection_id_frame.sequence() as u32,
                retire_prior_to: new_connection_id_frame.retire_prior_to() as u32,
                connection_id_length: Some(new_connection_id_frame.connection_id().len() as u8),
                connection_id: (*new_connection_id_frame.connection_id()).into(),
                stateless_reset_token: Some((**new_connection_id_frame.reset_token()).into()),
            },
            ReliableFrame::RetireConnectionId(retire_connection_id_frame) => {
                QuicFrame::RetireConnectionId {
                    sequence_number: retire_connection_id_frame.sequence() as u32,
                }
            }
            ReliableFrame::HandshakeDone(_handshake_done_frame) => QuicFrame::HandshakeDone {},
            ReliableFrame::AddAddress(frame) => QuicFrame::Unknow {
                frame_type_bytes: VarInt::from(frame.frame_type()).into_u64() as _,
                raw: None,
            },
            ReliableFrame::RemoveAddress(frame) => QuicFrame::Unknow {
                frame_type_bytes: VarInt::from(frame.frame_type()).into_u64() as _,
                raw: None,
            },
            ReliableFrame::PunchMeNow(frame) => QuicFrame::Unknow {
                frame_type_bytes: VarInt::from(frame.frame_type()).into_u64() as _,
                raw: None,
            },
            ReliableFrame::PunchDone(frame) => QuicFrame::Unknow {
                frame_type_bytes: VarInt::from(frame.frame_type()).into_u64() as _,
                raw: None,
            },
            ReliableFrame::StreamCtl(stream_ctl_frame) => QuicFrame::from(stream_ctl_frame),
        }
    }
}

impl From<&NewTokenFrame> for QuicFrame {
    fn from(value: &NewTokenFrame) -> Self {
        QuicFrame::NewToken {
            token: crate::build!(Token {
                r#type: TokenType::Retry,
                raw: RawInfo {
                    length: value.encoding_size() as u64,
                    payload_length: value.token().len() as u64,
                    data: value.token(),
                },
            }),
        }
    }
}

impl From<&StreamCtlFrame> for QuicFrame {
    fn from(frame: &StreamCtlFrame) -> Self {
        match frame {
            StreamCtlFrame::ResetStream(reset_stream_frame) => QuicFrame::ResetStream {
                stream_id: reset_stream_frame.stream_id().id(),
                error_code: (reset_stream_frame.app_error_code() as u32).into(),
                final_size: reset_stream_frame.final_size(),
                length: None,
                payload_length: None,
            },
            StreamCtlFrame::StopSending(stop_sending_frame) => QuicFrame::StopSending {
                stream_id: stop_sending_frame.stream_id().id(),
                error_code: (stop_sending_frame.app_err_code() as u32).into(),
                length: None,
                payload_length: None,
            },
            StreamCtlFrame::MaxStreamData(max_stream_data_frame) => QuicFrame::MaxStreamData {
                stream_id: max_stream_data_frame.stream_id().id(),
                maximum: max_stream_data_frame.max_stream_data(),
            },
            StreamCtlFrame::MaxStreams(max_streams_frame) => match max_streams_frame {
                MaxStreamsFrame::Bi(maximum) => QuicFrame::MaxStreams {
                    stream_type: StreamType::Bidirectional,
                    maximum: maximum.into_u64(),
                },
                MaxStreamsFrame::Uni(maximum) => QuicFrame::MaxStreams {
                    stream_type: StreamType::Unidirectional,
                    maximum: maximum.into_u64(),
                },
            },
            StreamCtlFrame::StreamDataBlocked(stream_data_blocked_frame) => {
                QuicFrame::StreamDataBlocked {
                    stream_id: stream_data_blocked_frame.stream_id().id(),
                    limit: stream_data_blocked_frame.maximum_stream_data(),
                }
            }
            StreamCtlFrame::StreamsBlocked(streams_blocked_frame) => match streams_blocked_frame {
                StreamsBlockedFrame::Bi(limit) => QuicFrame::StreamsBlocked {
                    stream_type: StreamType::Bidirectional,
                    limit: limit.into_u64(),
                },
                StreamsBlockedFrame::Uni(limit) => QuicFrame::StreamsBlocked {
                    stream_type: StreamType::Unidirectional,
                    limit: limit.into_u64(),
                },
            },
        }
    }
}

impl From<&ConnectionCloseFrame> for QuicFrame {
    fn from(frame: &ConnectionCloseFrame) -> Self {
        Self::ConnectionClose {
            error_space: Some(match &frame {
                ConnectionCloseFrame::App(..) => ConnectionCloseErrorSpace::Application,
                ConnectionCloseFrame::Quic(..) => ConnectionCloseErrorSpace::Transport,
            }),
            error_code: match &frame {
                ConnectionCloseFrame::App(frame) => {
                    Some(ApplicationCode::from(frame.error_code() as u32).into())
                }
                ConnectionCloseFrame::Quic(frame) => {
                    Some(connectivity::ConnectionCode::from(frame.error_kind()).into())
                }
            },
            reason: match &frame {
                ConnectionCloseFrame::App(frame) => Some(frame.reason().to_owned()),
                ConnectionCloseFrame::Quic(frame) => Some(frame.reason().to_owned()),
            },
            // TODO: 不应该强制要求reason是utf8的
            reason_bytes: None,
            trigger_frame_type: match &frame {
                ConnectionCloseFrame::Quic(frame) => {
                    Some((VarInt::from(frame.frame_type()).into_u64()).into())
                }
                ConnectionCloseFrame::App(..) => None,
            },
        }
    }
}

impl<D: Buffer> From<&Frame<D>> for QuicFrame {
    fn from(frame: &Frame<D>) -> Self {
        match frame {
            Frame::Padding(..) => QuicFrame::Padding {
                length: Some(1),
                payload_length: 1,
            },
            Frame::Ping(..) => QuicFrame::Ping {
                length: Some(1),
                payload_length: Some(1),
            },
            Frame::Ack(frame) => frame.into(),
            Frame::Close(frame) => frame.into(),
            Frame::NewToken(frame) => frame.into(),
            Frame::MaxData(frame) => (&ReliableFrame::from(*frame)).into(),
            Frame::DataBlocked(frame) => (&ReliableFrame::from(*frame)).into(),
            Frame::NewConnectionId(frame) => (&ReliableFrame::from(*frame)).into(),
            Frame::RetireConnectionId(frame) => (&ReliableFrame::from(*frame)).into(),
            Frame::HandshakeDone(frame) => (&ReliableFrame::from(*frame)).into(),
            Frame::AddAddress(frame) => (&ReliableFrame::from(*frame)).into(),
            Frame::RemoveAddress(frame) => (&ReliableFrame::from(*frame)).into(),
            Frame::PunchMeNow(frame) => (&ReliableFrame::from(*frame)).into(),
            Frame::PathChallenge(frame) => frame.into(),
            Frame::PathResponse(frame) => frame.into(),
            Frame::StreamCtl(frame) => frame.into(),
            Frame::Stream(frame, bytes) if bytes.is_empty() => (frame, bytes).into(),
            Frame::Crypto(frame, bytes) if bytes.is_empty() => (frame, bytes).into(),
            Frame::Datagram(frame, bytes) if bytes.is_empty() => (frame, bytes).into(),
            Frame::Stream(frame, bytes) => (frame, bytes).into(),
            Frame::Crypto(frame, bytes) => (frame, bytes).into(),
            Frame::Datagram(frame, bytes) => (frame, bytes).into(),
            Frame::PunchHello(frame) => QuicFrame::Unknow {
                frame_type_bytes: VarInt::from(frame.frame_type()).into_u64() as _,
                raw: None,
            },
            Frame::PunchDone(frame) => QuicFrame::Unknow {
                frame_type_bytes: VarInt::from(frame.frame_type()).into_u64() as _,
                raw: None,
            },
        }
    }
}

/// A collection of automatically and efficiently converting raw quic frames into qlog quic frames.
#[derive(Debug)]
pub struct QuicFramesCollector<E> {
    event: PhantomData<E>,
    frames: Vec<QuicFrame>,
}

impl<E> QuicFramesCollector<E> {
    pub fn new() -> Self {
        Self {
            event: PhantomData,
            frames: Vec::new(),
        }
    }
}

impl<E> Default for QuicFramesCollector<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E, F> Extend<F> for QuicFramesCollector<E>
where
    E: BeSpecificEventData,
    F: Into<QuicFrame>,
{
    fn extend<T: IntoIterator<Item = F>>(&mut self, iter: T) {
        if !crate::telemetry::Span::current().filter_event(E::scheme()) {
            return;
        }
        for frame in iter.into_iter().map(Into::into) {
            if let Some(last) = self.frames.last_mut() {
                match last {
                    QuicFrame::Padding {
                        length,
                        payload_length,
                    } => {
                        *last = QuicFrame::Padding {
                            length: length.map(|length| length + 1),
                            payload_length: *payload_length + 1,
                        };
                        continue;
                    }
                    QuicFrame::Ping {
                        length,
                        payload_length,
                    } => {
                        *last = QuicFrame::Ping {
                            length: length.map(|length| length + 1),
                            payload_length: payload_length.map(|length| length + 1),
                        };
                        continue;
                    }
                    _ => {}
                }
            }
            self.frames.push(frame);
        }
    }
}

impl<E> From<QuicFramesCollector<E>> for Vec<QuicFrame> {
    fn from(value: QuicFramesCollector<E>) -> Self {
        value.frames
    }
}

#[derive(Debug, Clone, From, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ApplicationCode {
    ApplicationError(ApplicationError),
    Value(u32),
}

impl From<ApplicationCode> for ConnectionCloseErrorCode {
    fn from(value: ApplicationCode) -> Self {
        match value {
            ApplicationCode::ApplicationError(error) => {
                ConnectionCloseErrorCode::ApplicationError(error)
            }
            ApplicationCode::Value(value) => ConnectionCloseErrorCode::Value(value as _),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamType {
    Unidirectional,
    Bidirectional,
}

impl From<qbase::sid::Dir> for StreamType {
    fn from(dir: qbase::sid::Dir) -> Self {
        match dir {
            qbase::sid::Dir::Bi => Self::Bidirectional,
            qbase::sid::Dir::Uni => Self::Unidirectional,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionCloseErrorSpace {
    Transport,
    Application,
}

#[derive(Debug, Clone, From, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ConnectionCloseErrorCode {
    TransportError(TransportError),
    CryptoError(CryptoError),
    ApplicationError(ApplicationError),
    Value(u64),
}

#[derive(Debug, Clone, Serialize, From, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ConnectionCloseTriggerFrameType {
    Id(u64),
    Text(String),
}

// 8.13.23
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportError {
    NoError,
    InternalError,
    ConnectionRefused,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ConnectionIdLimitError,
    ProtocolViolation,
    InvalidToken,
    ApplicationError,
    CryptoBufferExceeded,
    KeyUpdateError,
    AeadLimitReached,
    NoViablePath,
}

// 8.13.24
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ApplicationError(String);

// 8.13.25
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError(u8);

impl Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "crypto_error_0x1{:02x}", self.0)
    }
}

impl Serialize for CryptoError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CryptoError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        string.strip_prefix("crypto_error_0x1").map_or_else(
            || Err(serde::de::Error::custom("invalid crypto error")),
            |s| {
                u8::from_str_radix(s, 16)
                    .map(CryptoError)
                    .map_err(serde::de::Error::custom)
            },
        )
    }
}

crate::gen_builder_method! {
    PathEndpointInfoBuilder => PathEndpointInfo;
    PacketHeaderBuilder     => PacketHeader;
    TokenBuilder            => Token;
}

mod rollback {
    use super::*;
    use crate::{build, legacy::quic as legacy};

    impl From<IPAddress> for legacy::IPAddress {
        #[inline]
        fn from(value: IPAddress) -> Self {
            legacy::IPAddress::from(value.0)
        }
    }

    impl From<IpVersion> for legacy::IPVersion {
        #[inline]
        fn from(value: IpVersion) -> Self {
            match value {
                IpVersion::V4 => legacy::IPVersion::V4,
                IpVersion::V6 => legacy::IPVersion::V6,
            }
        }
    }

    impl From<ConnectionID> for legacy::ConnectionID {
        #[inline]
        fn from(value: ConnectionID) -> Self {
            legacy::ConnectionID::from(HexString::from(Bytes::from(value.0.to_vec())))
        }
    }

    impl From<Owner> for legacy::Owner {
        #[inline]
        fn from(value: Owner) -> Self {
            match value {
                Owner::Local => legacy::Owner::Local,
                Owner::Remote => legacy::Owner::Remote,
            }
        }
    }

    impl From<PacketType> for legacy::PacketType {
        #[inline]
        fn from(value: PacketType) -> Self {
            match value {
                PacketType::Initial => legacy::PacketType::Initial,
                PacketType::Handshake => legacy::PacketType::Handshake,
                PacketType::ZeroRTT => legacy::PacketType::ZeroRTT,
                PacketType::OneRTT => legacy::PacketType::OneRTT,
                PacketType::Retry => legacy::PacketType::Retry,
                PacketType::VersionNegotiation => legacy::PacketType::VersionNegotiation,
                PacketType::StatelessReset => legacy::PacketType::StatelessReset,
                PacketType::Unknown => legacy::PacketType::Unknown,
            }
        }
    }

    impl From<PacketNumberSpace> for legacy::PacketNumberSpace {
        #[inline]
        fn from(value: PacketNumberSpace) -> Self {
            match value {
                PacketNumberSpace::Initial => legacy::PacketNumberSpace::Initial,
                PacketNumberSpace::Handshake => legacy::PacketNumberSpace::Handshake,
                PacketNumberSpace::ApplicationData => legacy::PacketNumberSpace::ApplicationData,
            }
        }
    }

    impl From<TokenType> for legacy::TokenType {
        #[inline]
        fn from(value: TokenType) -> Self {
            match value {
                TokenType::Retry => legacy::TokenType::Retry,
                TokenType::Resumption => legacy::TokenType::Resumption,
            }
        }
    }

    impl From<Token> for legacy::Token {
        #[inline]
        fn from(value: Token) -> Self {
            build!(legacy::Token {
                ?r#type: value.r#type,
                details: value.details,
                ?length: value.raw.as_ref().and_then(|raw| raw.length.map(|length| length as u32)),
                ?data: value.raw.and_then(|raw| raw.data)
            })
        }
    }

    impl From<StatelessResetToken> for legacy::Token {
        #[inline]
        fn from(value: StatelessResetToken) -> Self {
            build!(legacy::Token {
                r#type: TokenType::Resumption,
                details: HashMap::new(),
                length: 16u32,
                data: { Bytes::from_owner(value.0.to_vec()) }
            })
        }
    }

    impl From<PacketHeader> for legacy::PacketHeader {
        fn from(value: PacketHeader) -> Self {
            build!(legacy::PacketHeader {
                packet_type: value.packet_type,
                ?packet_number: value.packet_number,
                ?flags: value.flags,
                ?token: value.token,
                ?length: value.length,
                ?version: value.version,
                ?scil: value.scil,
                ?dcil: value.dcil,
                ?scid: value.scid,
                ?dcid: value.dcid
            })
        }
    }

    impl From<TransportError> for legacy::TransportError {
        #[inline]
        fn from(value: TransportError) -> Self {
            match value {
                TransportError::NoError => legacy::TransportError::NoError,
                TransportError::InternalError => legacy::TransportError::InternalError,
                TransportError::ConnectionRefused => legacy::TransportError::ConnectionRefused,
                TransportError::FlowControlError => legacy::TransportError::FlowControlError,
                TransportError::StreamLimitError => legacy::TransportError::StreamLimitError,
                TransportError::StreamStateError => legacy::TransportError::StreamStateError,
                TransportError::FinalSizeError => legacy::TransportError::FinalSizeError,
                TransportError::FrameEncodingError => legacy::TransportError::FrameEncodingError,
                TransportError::TransportParameterError => {
                    legacy::TransportError::TransportParameterError
                }
                TransportError::ConnectionIdLimitError => {
                    legacy::TransportError::ConnectionIdLimitError
                }
                TransportError::ProtocolViolation => legacy::TransportError::ProtocolViolation,
                TransportError::InvalidToken => legacy::TransportError::InvalidToken,
                TransportError::ApplicationError => legacy::TransportError::ApplicationError,
                TransportError::CryptoBufferExceeded => {
                    legacy::TransportError::CryptoBufferExceeded
                }
                TransportError::KeyUpdateError => legacy::TransportError::KeyUpdateError,
                TransportError::AeadLimitReached => legacy::TransportError::AeadLimitReached,
                TransportError::NoViablePath => legacy::TransportError::NoViablePath,
            }
        }
    }

    impl From<StreamType> for legacy::StreamType {
        #[inline]
        fn from(value: StreamType) -> Self {
            match value {
                StreamType::Unidirectional => legacy::StreamType::Unidirectional,
                StreamType::Bidirectional => legacy::StreamType::Bidirectional,
            }
        }
    }

    impl From<ConnectionCloseErrorSpace> for legacy::ConnectionCloseErrorSpace {
        #[inline]
        fn from(value: ConnectionCloseErrorSpace) -> Self {
            match value {
                ConnectionCloseErrorSpace::Transport => {
                    legacy::ConnectionCloseErrorSpace::Transport
                }
                ConnectionCloseErrorSpace::Application => {
                    legacy::ConnectionCloseErrorSpace::Application
                }
            }
        }
    }

    impl TryFrom<ConnectionCloseErrorCode> for legacy::ConnectionCloseErrorCode {
        type Error = ();
        #[inline]
        fn try_from(value: ConnectionCloseErrorCode) -> Result<Self, ()> {
            match value {
                ConnectionCloseErrorCode::TransportError(error) => Ok(
                    legacy::ConnectionCloseErrorCode::TransportError(error.into()),
                ),
                ConnectionCloseErrorCode::CryptoError(_error) => Err(()),
                ConnectionCloseErrorCode::ApplicationError(error) => Ok(
                    legacy::ConnectionCloseErrorCode::ApplicationError(error.into()),
                ),
                ConnectionCloseErrorCode::Value(value) => {
                    Ok(legacy::ConnectionCloseErrorCode::Value(value))
                }
            }
        }
    }

    impl From<ConnectionCloseTriggerFrameType> for legacy::ConnectionCloseTriggerFrameType {
        #[inline]
        fn from(value: ConnectionCloseTriggerFrameType) -> Self {
            match value {
                ConnectionCloseTriggerFrameType::Id(id) => {
                    legacy::ConnectionCloseTriggerFrameType::Id(id)
                }
                ConnectionCloseTriggerFrameType::Text(text) => {
                    legacy::ConnectionCloseTriggerFrameType::Text(text)
                }
            }
        }
    }

    impl From<QuicFrame> for legacy::QuicFrame {
        fn from(value: QuicFrame) -> Self {
            match value {
                QuicFrame::Padding {
                    length,
                    payload_length,
                } => legacy::QuicFrame::Padding {
                    length,
                    payload_length,
                },
                QuicFrame::Ping {
                    length,
                    payload_length,
                } => legacy::QuicFrame::Ping {
                    length,
                    payload_length,
                },
                QuicFrame::Ack {
                    ack_delay,
                    acked_ranges,
                    ect1,
                    ect0,
                    ce,
                    length,
                    payload_length,
                } => legacy::QuicFrame::Ack {
                    ack_delay,
                    acked_ranges,
                    ect1,
                    ect0,
                    ce,
                    length,
                    payload_length,
                },
                QuicFrame::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                    length,
                    payload_length,
                } => legacy::QuicFrame::ResetStream {
                    stream_id,
                    error_code: error_code.into(),
                    final_size,
                    length,
                    payload_length,
                },
                QuicFrame::StopSending {
                    stream_id,
                    error_code,
                    length,
                    payload_length,
                } => legacy::QuicFrame::StopSending {
                    stream_id,
                    error_code: error_code.into(),
                    length,
                    payload_length,
                },
                QuicFrame::Crypto {
                    offset,
                    length,
                    payload_length,
                    raw: _,
                } => legacy::QuicFrame::Crypto {
                    offset,
                    length,
                    payload_length,
                },
                QuicFrame::NewToken { token } => legacy::QuicFrame::NewToken {
                    token: token.into(),
                },
                QuicFrame::Stream {
                    stream_id,
                    offset,
                    length,
                    fin,
                    raw,
                } => legacy::QuicFrame::Stream {
                    stream_id,
                    offset,
                    length,
                    fin,
                    raw,
                },
                QuicFrame::MaxData { maximum } => legacy::QuicFrame::MaxData { maximum },
                QuicFrame::MaxStreamData { stream_id, maximum } => {
                    legacy::QuicFrame::MaxStreamData { stream_id, maximum }
                }
                QuicFrame::MaxStreams {
                    stream_type,
                    maximum,
                } => legacy::QuicFrame::MaxStreams {
                    stream_type: stream_type.into(),
                    maximum,
                },
                QuicFrame::DataBlocked { limit } => legacy::QuicFrame::DataBlocked { limit },
                QuicFrame::StreamDataBlocked { stream_id, limit } => {
                    legacy::QuicFrame::StreamDataBlocked { stream_id, limit }
                }
                QuicFrame::StreamsBlocked { stream_type, limit } => {
                    legacy::QuicFrame::StreamsBlocked {
                        stream_type: stream_type.into(),
                        limit,
                    }
                }
                QuicFrame::NewConnectionId {
                    sequence_number,
                    retire_prior_to,
                    connection_id_length,
                    connection_id,
                    stateless_reset_token,
                } => legacy::QuicFrame::NewConnectionId {
                    sequence_number,
                    retire_prior_to,
                    connection_id_length,
                    connection_id: connection_id.into(),
                    stateless_reset_token: stateless_reset_token.map(Into::into),
                },
                QuicFrame::RetireConnectionId { sequence_number } => {
                    legacy::QuicFrame::RetireConnectionId { sequence_number }
                }
                QuicFrame::PathChallenge { data } => legacy::QuicFrame::PathChallenge { data },
                QuicFrame::PathResponse { data } => legacy::QuicFrame::PathResponse { data },
                QuicFrame::ConnectionClose {
                    error_space,
                    error_code,
                    reason,
                    reason_bytes: _,
                    trigger_frame_type,
                } => legacy::QuicFrame::ConnectionClose {
                    error_space: error_space.map(Into::into),
                    raw_error_code: match &error_code {
                        Some(ConnectionCloseErrorCode::CryptoError(CryptoError(value))) => {
                            Some(*value as u32)
                        }
                        _ => None,
                    },
                    error_code: error_code.and_then(|error_code| error_code.try_into().ok()),
                    reason,
                    trigger_frame_type: trigger_frame_type.map(Into::into),
                },
                QuicFrame::HandshakeDone {} => legacy::QuicFrame::HandshakeDone {},
                QuicFrame::Unknow {
                    frame_type_bytes,
                    raw,
                } => legacy::QuicFrame::Unknown {
                    raw_frame_type: frame_type_bytes,
                    raw_length: raw
                        .as_ref()
                        .and_then(|raw| raw.length.map(|length| length as u32)),
                    raw: raw.and_then(|raw| raw.data),
                },
                QuicFrame::Datagram { length, raw } => legacy::QuicFrame::Datagram { length, raw },
            }
        }
    }

    impl From<ApplicationError> for legacy::ApplicationError {
        #[inline]
        fn from(value: ApplicationError) -> Self {
            value.0.into()
        }
    }

    impl From<ApplicationCode> for legacy::ApplicationCode {
        #[inline]
        fn from(value: ApplicationCode) -> Self {
            match value {
                ApplicationCode::ApplicationError(error) => {
                    legacy::ApplicationCode::ApplicationError(error.into())
                }
                ApplicationCode::Value(value) => legacy::ApplicationCode::Value(value),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack() {
        // 123 56 9
        let frame = AckFrame::new(
            9u32.into(),
            1000u32.into(),
            0u32.into(),
            vec![(1u32.into(), 1u32.into()), (0u32.into(), 2u32.into())],
            None,
        );

        let encoding_size = frame.encoding_size();

        let quic_frame: QuicFrame = (&frame).into();
        assert_eq!(
            quic_frame,
            QuicFrame::Ack {
                ack_delay: Some(1.0),
                acked_ranges: vec![[9, 9], [5, 6], [1, 3]],
                ect1: None,
                ect0: None,
                ce: None,
                length: Some(encoding_size as u32),
                payload_length: None,
            }
        );
    }
}
