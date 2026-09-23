use std::{collections::HashMap, time::Duration};

use derive_builder::Builder;
use derive_more::From;
use qbase::param::{ClientParameters, ParameterId, ServerParameters};
use serde::{Deserialize, Serialize};

use super::{
    ConnectionID, ECN, IPAddress, Owner, PacketHeader, PacketNumberSpace, PathEndpointInfo,
    QuicFrame, QuicVersion, StatelessResetToken, StreamType,
};
use crate::{HexString, PathID, RawInfo};

/// The version_information event supports QUIC version negotiation; see
/// Section 6 of [QUIC-TRANSPORT].  It has Core importance level; see
/// Section 9.2 of [QLOG-MAIN].
///
/// QUIC endpoints each have their own list of QUIC versions they
/// support.  The client uses the most likely version in their first
/// initial.  If the server does not support that version, it replies
/// with a Version Negotiation packet, which contains its supported
/// versions.  From this, the client selects a version.  The
/// version_information event aggregates all this information in a single
/// event type.  It also allows logging of supported versions at an
/// endpoint without actual version negotiation needing to happen.
///
/// [QUIC-TRANSPORT]: https://www.rfc-editor.org/rfc/rfc9000
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct VersionInformation {
    // Vec for `? filed: [ +ty]``, Option<Vec> for `* filed: [* ty]`
    #[serde(skip_serializing_if = "Vec::is_empty")]
    server_versions: Vec<QuicVersion>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    client_versions: Vec<QuicVersion>,
    chosen_version: Option<QuicVersion>,
}

/// The alpn_information event supports Application-Layer Protocol
/// Negotiation (ALPN) over the QUIC transport; see [RFC7301] and
/// Section 7.4 of [QUIC-TRANSPORT].  It has Core importance level; see
/// Section 9.2 of [QLOG-MAIN].
///
/// QUIC endpoints are configured with a list of supported ALPN
/// identifiers.  Clients send the list in a TLS ClientHello, and servers
/// match against their list.  On success, a single ALPN identifier is
/// chosen and sent back in a TLS ServerHello.  If no match is found, the
/// connection is closed.
///
/// ALPN identifiers are byte sequences, that may be possible to present
/// as UTF-8.  The ALPNIdentifier` type supports either format.
/// Implementations SHOULD log at least one format, but MAY log both or
/// none.
///
/// [RFC7301]: https://www.rfc-editor.org/rfc/rfc7301
/// [QUIC-TRANSPORT]: https://www.rfc-editor.org/rfc/rfc9000
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct ALPNInformation {
    server_alpns: Option<Vec<ALPNIdentifier>>,
    client_alpns: Option<Vec<ALPNIdentifier>>,
    chosen_alpn: Option<ALPNIdentifier>,
}

/// ALPN identifiers are byte sequences, that may be possible to present
/// as UTF-8.  The ALPNIdentifier` type supports either format.
/// Implementations SHOULD log at least one format, but MAY log both or
/// none.
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct ALPNIdentifier {
    byte_value: Option<HexString>,
    string_value: Option<String>,
}

/// The parameters_set event groups settings from several different
/// sources (transport parameters, TLS ciphers, etc.) into a single
/// event.  This is done to minimize the amount of events and to decouple
/// conceptual setting impacts from their underlying mechanism for easier
/// high-level reasoning.  The event has Core importance level; see
/// Section 9.2 of [QLOG-MAIN].
///
/// Most of these settings are typically set once and never change.
/// However, they are usually set at different times during the
/// connection, so there will regularly be several instances of this
/// event with different fields set.
///
/// Note that some settings have two variations (one set locally, one
/// requested by the remote peer).  This is reflected in the owner field.
/// As such, this field MUST be correct for all settings included a
/// single event instance.  If you need to log settings from two sides,
/// you MUST emit two separate event instances.
///
/// Implementations are not required to recognize, process or support
/// every setting/parameter received in all situations.  For example,
/// QUIC implementations MUST discard transport parameters that they do
/// not understand Section 7.4.2 of [QUIC-TRANSPORT].  The
/// unknown_parameters field can be used to log the raw values of any
/// unknown parameters (e.g., GREASE, private extensions, peer-side
/// experimentation).
///
/// In the case of connection resumption and 0-RTT, some of the server's
/// parameters are stored up-front at the client and used for the initial
/// connection startup.  They are later updated with the server's reply.
/// In these cases, utilize the separate parameters_restored event to
/// indicate the initial values, and this event to indicate the updated
/// values, as normal.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
/// [QUIC-TRANSPORT]: https://www.rfc-editor.org/rfc/rfc9000

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct ParametersSet {
    owner: Option<Owner>,

    /// true if valid session ticket was received
    resumption_allowed: Option<bool>,

    /// true if early data extension was enabled on the TLS layer
    early_data_enabled: Option<bool>,

    /// e.g., "AES_128_GCM_SHA256"
    tls_cipher: Option<String>,

    // RFC9000
    original_destination_connection_id: Option<ConnectionID>,
    initial_source_connection_id: Option<ConnectionID>,
    retry_source_connection_id: Option<ConnectionID>,
    stateless_reset_token: Option<StatelessResetToken>,
    disable_active_migration: Option<bool>,
    max_idle_timeout: Option<u64>,
    max_udp_payload_size: Option<u32>,
    ack_delay_exponent: Option<u16>,
    max_ack_delay: Option<u16>,
    active_connection_id_limit: Option<u32>,
    initial_max_data: Option<u64>,
    initial_max_stream_data_bidi_local: Option<u64>,
    initial_max_stream_data_bidi_remote: Option<u64>,
    initial_max_stream_data_uni: Option<u64>,
    initial_max_streams_bidi: Option<u64>,
    initial_max_streams_uni: Option<u64>,
    preferred_address: Option<PreferredAddress>,
    unknown_parameters: Option<Vec<UnknownParameter>>,

    // RFC9221
    max_datagram_frame_size: Option<u64>,

    // RFC9287
    /// can only be restored at the client.
    /// servers MUST NOT restore this parameter!
    grease_quic_bit: Option<bool>,
}

macro_rules! extract_parameter {
    ( $(
        $id:ident as $as:ident $(.map($($tt:tt)*))? from $set:ident to $this:ident.$field:ident
    ),* $(,)? ) => {
        $( extract_parameter!(@one $id as $as $(.map($($tt)*))? from $set to $this.$field); )*
    };
    (@one $id:ident as $as:ident .map($($tt:tt)*) from $set:ident to $this:ident.$field:ident) => {
        $this.$field = $this.$field.take().or_else(|| {
            Some($set.try_get::<$as>(ParameterId::$id).map($($tt)*))
        });
    };
    (@one $id:ident as $as:ident from $set:ident to $this:ident.$field:ident) => {
        $this.$field = $this.$field.take().or_else(|| {
            Some($set.try_get::<$as>(ParameterId::$id).map(Into::into))
        });
    };
}

impl ParametersSetBuilder {
    /// helper method to set all client parameters at once
    pub fn client_parameters(&mut self, params: &ClientParameters) -> &mut Self {
        use qbase::cid::ConnectionId;
        extract_parameter! {
            InitialSourceConnectionId as ConnectionId from params to self.initial_source_connection_id,
            DisableActiveMigration as bool from params to self.disable_active_migration,
            MaxIdleTimeout as Duration.map(|d| d.as_millis() as _) from params to self.max_idle_timeout,
            MaxUdpPayloadSize as u64.map(|u| u as u32) from params to self.max_udp_payload_size,
            AckDelayExponent as u64.map(|u| u as u16) from params to self.ack_delay_exponent,
            MaxAckDelay as Duration.map(|d| d.as_millis() as _) from params to self.max_ack_delay,
            ActiveConnectionIdLimit as u64.map(|u| u as u32) from params to self.active_connection_id_limit,
            InitialMaxData as u64 from params to self.initial_max_data,
            InitialMaxStreamDataBidiLocal as u64 from params to self.initial_max_stream_data_bidi_local,
            InitialMaxStreamDataBidiRemote as u64 from params to self.initial_max_stream_data_bidi_remote,
            InitialMaxStreamDataUni as u64 from params to self.initial_max_stream_data_uni,
            InitialMaxStreamsBidi as u64 from params to self.initial_max_streams_bidi,
            InitialMaxStreamsUni as u64 from params to self.initial_max_streams_uni,
            MaxDatagramFrameSize as u64 from params to self.max_datagram_frame_size,
            GreaseQuicBit as bool from params to self.grease_quic_bit,
        }
        self
    }

    /// helper method to set all server parameters at once
    pub fn server_parameters(&mut self, params: &ServerParameters) -> &mut Self {
        use qbase::{
            cid::ConnectionId, param::preferred_address::PreferredAddress, token::ResetToken,
        };
        extract_parameter! {
            OriginalDestinationConnectionId as ConnectionId from params to self.original_destination_connection_id,
            InitialSourceConnectionId as ConnectionId from params to self.initial_source_connection_id,
            RetrySourceConnectionId as ConnectionId from params to self.retry_source_connection_id,
            StatelessResetToken as ResetToken from params to self.stateless_reset_token,
            DisableActiveMigration as bool from params to self.disable_active_migration,
            MaxIdleTimeout as Duration.map(|d| d.as_millis() as _) from params to self.max_idle_timeout,
            MaxUdpPayloadSize as u64.map(|u| u as u32) from params to self.max_udp_payload_size,
            AckDelayExponent as u64.map(|u| u as u16) from params to self.ack_delay_exponent,
            MaxAckDelay as Duration.map(|d| d.as_millis() as _) from params to self.max_ack_delay,
            ActiveConnectionIdLimit as u64.map(|u| u as u32) from params to self.active_connection_id_limit,
            InitialMaxData as u64 from params to self.initial_max_data,
            InitialMaxStreamDataBidiLocal as u64 from params to self.initial_max_stream_data_bidi_local,
            InitialMaxStreamDataBidiRemote as u64 from params to self.initial_max_stream_data_bidi_remote,
            InitialMaxStreamDataUni as u64 from params to self.initial_max_stream_data_uni,
            InitialMaxStreamsBidi as u64 from params to self.initial_max_streams_bidi,
            InitialMaxStreamsUni as u64 from params to self.initial_max_streams_uni,
            PreferredAddress as PreferredAddress from params to self.preferred_address,
            MaxDatagramFrameSize as u64 from params to self.max_datagram_frame_size,
            GreaseQuicBit as bool from params to self.grease_quic_bit,
        }
        self
    }
}

#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into), build_fn(private, name = "fallible_build"))]
pub struct PreferredAddress {
    ip_v4: IPAddress,
    ip_v6: IPAddress,
    port_v4: u16,
    port_v6: u16,
    connection_id: ConnectionID,
    stateless_reset_token: StatelessResetToken,
}

impl From<qbase::param::preferred_address::PreferredAddress> for PreferredAddress {
    fn from(pa: qbase::param::preferred_address::PreferredAddress) -> Self {
        crate::build!(Self {
            ip_v4: pa.address_v4().ip().to_string(),
            ip_v6: pa.address_v6().ip().to_string(),
            port_v4: pa.address_v4().port(),
            port_v6: pa.address_v6().port(),
            connection_id: pa.connection_id(),
            stateless_reset_token: pa.stateless_reset_token(),
        })
    }
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct UnknownParameter {
    id: u64,
    #[builder(default)]
    value: Option<HexString>,
}

/// When using QUIC 0-RTT, clients are expected to remember and restore
/// the server's transport parameters from the previous connection.  The
/// parameters_restored event is used to indicate which parameters were
/// restored and to which values when utilizing 0-RTT.  It has Base
/// importance level; see Section 9.2 of [QLOG-MAIN].
///
/// Note that not all transport parameters should be restored (many are
/// even prohibited from being re-utilized).  The ones listed here are
/// the ones expected to be useful for correct 0-RTT usage.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct ParametersRestored {
    // RFC 9000
    disable_active_migration: Option<bool>,
    max_idle_timeout: Option<u64>,
    max_udp_payload_size: Option<u32>,
    active_connection_id_limit: Option<u32>,
    initial_max_data: Option<u64>,
    initial_max_stream_data_bidi_local: Option<u64>,
    initial_max_stream_data_bidi_remote: Option<u64>,
    initial_max_stream_data_uni: Option<u64>,
    initial_max_streams_bidi: Option<u64>,
    initial_max_streams_uni: Option<u64>,

    // RFC9221
    max_datagram_frame_size: Option<u64>,

    // RFC9287
    /// can only be restored at the client.
    /// servers MUST NOT restore this parameter!
    grease_quic_bit: Option<bool>,
}

impl ParametersRestoredBuilder {
    /// helper method to set all client parameters at once
    pub fn client_parameters(&mut self, params: &ServerParameters) -> &mut Self {
        extract_parameter! {
            DisableActiveMigration as bool from params to self.disable_active_migration,
            MaxIdleTimeout as Duration.map(|d| d.as_millis() as _) from params to self.max_idle_timeout,
            MaxUdpPayloadSize as u64.map(|u| u as u32) from params to self.max_udp_payload_size,
            ActiveConnectionIdLimit as u64.map(|u| u as u32) from params to self.active_connection_id_limit,
            InitialMaxData as u64 from params to self.initial_max_data,
            InitialMaxStreamDataBidiLocal as u64 from params to self.initial_max_stream_data_bidi_local,
            InitialMaxStreamDataBidiRemote as u64 from params to self.initial_max_stream_data_bidi_remote,
            InitialMaxStreamDataUni as u64 from params to self.initial_max_stream_data_uni,
            InitialMaxStreamsBidi as u64 from params to self.initial_max_streams_bidi,
            InitialMaxStreamsUni as u64 from params to self.initial_max_streams_uni,
            MaxDatagramFrameSize as u64 from params to self.max_datagram_frame_size,
            GreaseQuicBit as bool from params to self.grease_quic_bit,
        }
        self
    }
}

/// The packet_sent event indicates a QUIC-level packet was sent.  It has
/// Core importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct PacketSent {
    header: PacketHeader,
    #[builder(default)]
    frames: Option<Vec<QuicFrame>>,

    /// only if header.packet_type === "stateless_reset"
    /// is always 128 bits in length.
    #[builder(default)]
    stateless_reset_token: Option<StatelessResetToken>,

    /// only if header.packet_type === "version_negotiation"
    #[builder(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    supported_versions: Vec<QuicVersion>,
    #[builder(default)]
    raw: Option<RawInfo>,
    #[builder(default)]
    datagram_id: Option<u32>,
    #[builder(default)]
    #[serde(default)]
    is_mtu_probe_packet: bool,

    #[builder(default)]
    trigger: Option<PacketSentTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketSentTrigger {
    RetransmitReordered,
    RetransmitTimeout,
    PtoProbe,
    RetransmitCrypto,
    CcBandwidthProbe,
}

/// The packet_received event indicates a QUIC-level packet was received.
/// It has Core importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct PacketReceived {
    header: PacketHeader,
    #[builder(default)]
    frames: Option<Vec<QuicFrame>>,

    /// only if header.packet_type === "stateless_reset"
    /// is always 128 bits in length.
    #[builder(default)]
    stateless_reset_token: Option<StatelessResetToken>,

    /// only if header.packet_type === "version_negotiation"
    #[builder(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    supported_versions: Vec<QuicVersion>,
    #[builder(default)]
    raw: Option<RawInfo>,
    #[builder(default)]
    datagram_id: Option<u32>,

    #[builder(default)]
    trigger: Option<PacketReceivedTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketReceivedTrigger {
    /// if packet was buffered because it couldn't be
    /// decrypted before
    KeysAvailable,
}
/// The packet_dropped event indicates a QUIC-level packet was dropped.
/// It has Base importance level; see Section 9.2 of [QLOG-MAIN].
///
/// The trigger field indicates a general reason category for dropping
/// the packet, while the details field can contain additional
/// implementation-specific information.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
#[serde(default)]
pub struct PacketDropped {
    /// Primarily packet_type should be filled here,
    /// as other fields might not be decrypteable or parseable
    header: Option<PacketHeader>,
    raw: Option<RawInfo>,
    datagram_id: Option<u32>,
    details: HashMap<String, serde_json::Value>,
    trigger: Option<PacketDroppedTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketDroppedTrigger {
    /// not initialized, out of memory
    InternalError,
    /// limits reached, DDoS protection, unwilling to track more paths, duplicate packet
    Rejected,
    /// unknown or unsupported version.
    Unsupported,
    /// packet parsing or validation error
    Invalid,
    /// duplicate packet
    Duplicate,
    /// packet does not relate to a known connection or Connection ID
    ConnectionUnknown,
    /// decryption failed
    DecryptionFailure,
    /// decryption key was unavailable
    KeyUnavailable,
    /// situations not clearly covered in the other categories
    Genera,
}

impl From<qbase::packet::InvalidPacketNumber> for PacketDroppedTrigger {
    fn from(value: qbase::packet::InvalidPacketNumber) -> Self {
        match value {
            qbase::packet::InvalidPacketNumber::TooOld
            | qbase::packet::InvalidPacketNumber::TooLarge => PacketDroppedTrigger::Genera,
            qbase::packet::InvalidPacketNumber::Duplicate => PacketDroppedTrigger::Duplicate,
        }
    }
}

impl From<qbase::packet::error::Error> for PacketDroppedTrigger {
    fn from(error: qbase::packet::error::Error) -> Self {
        match error {
            qbase::packet::error::Error::UnsupportedVersion(_) => Self::Unsupported,
            qbase::packet::error::Error::InvalidFixedBit
            | qbase::packet::error::Error::InvalidReservedBits(_, _)
            | qbase::packet::error::Error::IncompleteType(_)
            | qbase::packet::error::Error::IncompleteHeader(_, _)
            | qbase::packet::error::Error::IncompletePacket(_, _)
            | qbase::packet::error::Error::UnderSampling(..) => Self::Invalid,
            qbase::packet::error::Error::RemoveProtectionFailure
            | qbase::packet::error::Error::DecryptPacketFailure => Self::DecryptionFailure,
        }
    }
}

/// The packet_buffered event is emitted when a packet is buffered
/// because it cannot be processed yet.  Typically, this is because the
/// packet cannot be parsed yet, and thus only the full packet contents
/// can be logged when it was parsed in a packet_received event.  The
/// event has Base importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct PacketBuffered {
    /// Primarily packet_type should be filled here,
    /// as other fields might not be decrypteable or parseable
    header: Option<PacketHeader>,
    raw: Option<RawInfo>,
    datagram_id: Option<u32>,
    trigger: Option<PacketBufferedTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketBufferedTrigger {
    /// indicates the parser cannot keep up, temporarily buffers
    /// packet for later processing
    Backpressure,
    /// if packet cannot be decrypted because the proper keys were
    /// not yet available
    KeysUnavailable,
}

/// The packets_acked event is emitted when a (group of) sent packet(s)
/// is acknowledged by the remote peer _for the first time_. It has Extra
/// importance level; see Section 9.2 of [QLOG-MAIN].
///
/// This information could also be deduced from the contents of received
/// ACK frames.  However, ACK frames require additional processing logic
/// to determine when a given packet is acknowledged for the first time,
/// as QUIC uses ACK ranges which can include repeated ACKs.
/// Additionally, this event can be used by implementations that do not
/// log frame contents.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct PacketsAcked {
    packet_number_space: Option<PacketNumberSpace>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    packet_nubers: Vec<u64>,
}
/// The datagrams_sent event indicates when one or more UDP-level
/// datagrams are passed to the underlying network socket.  This is
/// useful for determining how QUIC packet buffers are drained to the OS.
/// The event has Extra importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct UdpDatagramsSent {
    /// to support passing multiple at once
    count: Option<u16>,

    /// The RawInfo fields do not include the UDP headers,
    /// only the UDP payload
    #[serde(skip_serializing_if = "Vec::is_empty")]
    raw: Vec<RawInfo>,

    /// ECN bits in the IP header
    /// if not set, defaults to the value used on the last
    /// QUICDatagramsSent event
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ecn: Vec<ECN>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    datagram_ids: Vec<u32>,
}

/// When one or more UDP-level datagrams are received from the socket.
/// This is useful for determining how datagrams are passed to the user
/// space stack from the OS.  The event has Extra importance level; see
/// Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct UdpDatagramsReceived {
    /// to support passing multiple at once
    count: Option<u16>,

    /// The RawInfo fields do not include the UDP headers,
    /// only the UDP payload
    #[serde(skip_serializing_if = "Vec::is_empty")]
    raw: Vec<RawInfo>,

    /// ECN bits in the IP header
    /// if not set, defaults to the value used on the last
    /// QUICDatagramsSent event
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ecn: Vec<ECN>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    datagram_ids: Vec<u32>,
}

/// When a UDP-level datagram is dropped.  This is typically done if it
/// does not contain a valid QUIC packet.  If it does, but the QUIC
/// packet is dropped for other reasons, the packet_dropped event
/// (Section 5.7) should be used instead.  The event has Extra importance
/// level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct UdpDatagramDropped {
    /// The RawInfo fields do not include the UDP headers,
    /// only the UDP payload
    raw: Option<RawInfo>,
}
// The stream_state_updated event is emitted whenever the internal state
// of a QUIC stream is updated; see Section 3 of [QUIC-TRANSPORT].  Most
// of this can be inferred from several types of frames going over the
// wire, but it's much easier to have explicit signals for these state
// changes.  The event has Base importance level; see Section 9.2 of
// [QLOG-MAIN].
///
/// [QUIC-TRANSPORT]: https://www.rfc-editor.org/rfc/rfc9000
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct StreamStateUpdated {
    stream_id: u64,

    /// mainly useful when opening the stream
    #[builder(default)]
    stream_type: Option<StreamType>,
    #[builder(default)]
    old: Option<StreamState>,
    new: StreamState,

    #[builder(default)]
    stream_side: Option<StreamSide>,
}

#[derive(Debug, Clone, Copy, From, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum StreamState {
    Base(BaseStreamStates),
    Granular(GranularStreamStates),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BaseStreamStates {
    Idle,
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GranularStreamStates {
    // bidirectional stream states, RFC 9000 Section 3.4.
    HalfClosedLocal,
    HalfClosedRemote,
    // sending-side stream states, RFC 9000 Section 3.1.
    Ready,
    Send,
    DataSent,
    ResetSent,
    ResetReceived,
    // receive-side stream states, RFC 9000 Section 3.2.
    Receive,
    SizeKnown,
    DataRead,
    ResetRead,
    // both-side states
    DataReceived,
    // qlog-defined: memory actually freed
    Destroyed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamSide {
    Sending,
    Receiving,
}

/// The frame_processed event is intended to prevent a large
/// proliferation of specific purpose events (e.g., packets_acknowledged,
/// flow_control_updated, stream_data_received).  It has Extra importance
/// level; see Section 9.2 of [QLOG-MAIN].
///
/// Implementations have the opportunity to (selectively) log this type
/// of signal without having to log packet-level details (e.g., in
/// packet_received).  Since for almost all cases, the effects of
/// applying a frame to the internal state of an implementation can be
/// inferred from that frame's contents, these events are aggregated into
/// this single frames_processed event.
///
/// The frame_processed event can be used to signal internal state change
/// not resulting directly from the actual "parsing" of a frame (e.g.,
/// the frame could have been parsed, data put into a buffer, then later
/// processed, then logged with this event).
///
/// The packet_received event can convey all constituent frames.  It is
/// not expected that the frames_processed event will also be used for a
/// redundant purpose.  Rather, implementations can use this event to
/// avoid having to log full packets or to convey extra information about
/// when frames are processed (for example, if frame processing is
/// deferred for any reason).
///
/// Note that for some events, this approach will lose some information
/// (e.g., for which encryption level are packets being acknowledged?).
/// If this information is important, the packet_received event can be
/// used instead.
///
/// In some implementations, it can be difficult to log frames directly,
/// even when using packet_sent and packet_received events.  For these
/// cases, the frames_processed event also contains the packet_numbers
/// field, which can be used to more explicitly link this event to the
/// packet_sent/received events.  The field is an array, which supports
/// using a single frames_processed event for multiple frames received
/// over multiple packets.  To map between frames and packets, the
/// position and order of entries in the frames and packet_numbers is
/// used.  If the optional packet_numbers field is used, each frame MUST
/// have a corresponding packet number at the same index.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct FramesProcessed {
    frames: Vec<QuicFrame>,
    #[builder(default)]
    packet_numbers: Option<Vec<u64>>,
}

/// The stream_data_moved event is used to indicate when QUIC stream data
/// moves between the different layers.  This helps make clear the flow
/// of data, how long data remains in various buffers, and the overheads
/// introduced by individual layers.  The event has Base importance
/// level; see Section 9.2 of [QLOG-MAIN].
///
/// This event relates to stream data only.  There are no packet or frame
/// headers and length values in the length or raw fields MUST reflect
/// that.
///
/// For example, it can be useful to understand when data moves from an
/// application protocol (e.g., HTTP) to QUIC stream buffers and vice
/// versa.
///
/// The stream_data_moved event can provide insight into whether received
/// data on a QUIC stream is moved to the application protocol
/// immediately (for example per received packet) or in larger batches
/// (for example, all QUIC packets are processed first and afterwards the
/// application layer reads from the streams with newly available data).
/// This can help identify bottlenecks, flow control issues, or
/// scheduling problems.
///
/// The additional_info field supports optional logging of information
/// related to the stream state.  For example, an application layer that
/// moves data into transport and simultaneously ends the stream, can log
/// fin_set.  As another example, a transport layer that has received an
/// instruction to reset a stream can indicate this to the application
/// layer using reset_stream.  In both cases, the length-carrying fields
/// (length or raw) can be omitted or contain zero values.
///
/// This event is only for data in QUIC streams.  For data in QUIC
/// Datagram Frames, see the datagram_data_moved event defined in
/// Section 5.16.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct StreamDataMoved {
    stream_id: Option<u64>,
    offset: Option<u64>,

    /// byte length of the moved data
    length: Option<u64>,

    from: Option<StreamDataLocation>,
    to: Option<StreamDataLocation>,

    additional_info: Option<DataMovedAdditionalInfo>,

    raw: Option<RawInfo>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamDataLocation {
    Application,
    Transport,
    Network,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataMovedAdditionalInfo {
    FinSet,
    StreamReset,
}

/// The datagram_data_moved event is used to indicate when QUIC Datagram
/// Frame data (see [RFC9221]) moves between the different layers.  This
/// helps make clear the flow of data, how long data remains in various
/// buffers, and the overheads introduced by individual layers.  The
/// event has Base importance level; see Section 9.2 of [QLOG-MAIN].
///
/// This event relates to datagram data only.  There are no packet or
/// frame headers and length values in the length or raw fields MUST
/// reflect that.
///
/// For example, passing from the application protocol (e.g.,
/// WebTransport) to QUIC Datagram Frame buffers and vice versa.
///
/// The datagram_data_moved event can provide insight into whether
/// received data in a QUIC Datagram Frame is moved to the application
/// protocol immediately (for example per received packet) or in larger
/// batches (for example, all QUIC packets are processed first and
/// afterwards the application layer reads all Datagrams at once).  This
/// can help identify bottlenecks, flow control issues, or scheduling
/// problems.
///
/// This event is only for data in QUIC Datagram Frames.  For data in
/// QUIC streams, see the stream_data_moved event defined in
/// Section 5.15.
///
/// [RFC9221]: https://www.rfc-editor.org/rfc/rfc9221.html
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct DatagramDataMoved {
    /// byte length of the moved data
    length: Option<u64>,
    from: Option<StreamDataLocation>,
    to: Option<StreamDataLocation>,
    raw: Option<RawInfo>,
}

/// Use to provide additional information when attempting (client-side)
/// connection migration.  While most details of the QUIC connection
/// migration process can be inferred by observing the PATH_CHALLENGE and
/// PATH_RESPONSE frames, in combination with the QUICPathAssigned event,
/// it can be useful to explicitly log the progression of the migration
/// and potentially made decisions in a single location/event.  The event
/// has Extra importance level; see Section 9.2 of [QLOG-MAIN].
///
/// Generally speaking, connection migration goes through two phases: a
/// probing phase (which is not always needed/present), and a migration
/// phase (which can be abandoned upon error).
///
/// Implementations that log per-path information in a
/// QUICMigrationStateUpdated, SHOULD also emit QUICPathAssigned events,
/// to serve as a ground-truth source of information.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct MigrationStateUpdated {
    #[builder(default)]
    old: Option<MigrationState>,
    new: MigrationState,

    #[builder(default)]
    path_id: Option<PathID>,

    /// the information for traffic going towards the remote receiver
    #[builder(default)]
    path_remote: Option<PathEndpointInfo>,

    /// the information for traffic coming in at the local endpoint
    #[builder(default)]
    path_local: Option<PathEndpointInfo>,
}

/// Note that MigrationState does not describe a full state machine
/// These entries are not necessarily chronological,
/// nor will they always all appear during
/// a connection migration attempt.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    /// probing packets are sent, migration not initiated yet
    ProbingStarted,
    /// did not get reply to probing packets,
    /// discarding path as an option
    ProbingAbandoned,
    /// received reply to probing packets, path is migration candidate
    ProbingSuccessful,
    /// non-probing packets are sent, attempting migration
    MigrationStarted,
    /// something went wrong during the migration, abandoning attempt
    MigrationAbandoned,
    /// new path is now fully used, old path is discarded
    MigrationComplete,
}

crate::gen_builder_method! {
    VersionInformationBuilder    => VersionInformation;
    ALPNInformationBuilder       => ALPNInformation;
    ALPNIdentifierBuilder        => ALPNIdentifier;
    ParametersSetBuilder         => ParametersSet;
    PreferredAddressBuilder      => PreferredAddress;
    UnknownParameterBuilder      => UnknownParameter;
    ParametersRestoredBuilder    => ParametersRestored;
    PacketSentBuilder            => PacketSent;
    PacketReceivedBuilder        => PacketReceived;
    PacketDroppedBuilder         => PacketDropped;
    PacketBufferedBuilder        => PacketBuffered;
    PacketsAckedBuilder          => PacketsAcked;
    UdpDatagramsSentBuilder      => UdpDatagramsSent;
    UdpDatagramsReceivedBuilder  => UdpDatagramsReceived;
    UdpDatagramDroppedBuilder    => UdpDatagramDropped;
    StreamStateUpdatedBuilder    => StreamStateUpdated;
    FramesProcessedBuilder       => FramesProcessed;
    StreamDataMovedBuilder       => StreamDataMoved;
    DatagramDataMovedBuilder     => DatagramDataMoved;
    MigrationStateUpdatedBuilder => MigrationStateUpdated;
}

mod rollback {
    use bytes::Bytes;

    use super::*;
    use crate::{build, legacy::quic as legacy};

    impl From<QuicVersion> for legacy::QuicVersion {
        #[inline]
        fn from(value: QuicVersion) -> Self {
            HexString::from(Bytes::from(value.0.to_be_bytes().to_vec())).into()
        }
    }

    impl From<VersionInformation> for legacy::TransportVersionInformation {
        fn from(vi: VersionInformation) -> Self {
            build!(legacy::TransportVersionInformation {
                server_versions: vi
                    .server_versions
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<_>>(),
                client_versions: vi
                    .client_versions
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<_>>(),
                ?chosen_version: vi.chosen_version,
            })
        }
    }

    impl From<ALPNIdentifier> for String {
        fn from(value: ALPNIdentifier) -> Self {
            value.string_value.as_ref().map_or(
                value
                    .byte_value
                    .as_ref()
                    .map(|b| b.to_string())
                    .unwrap_or_default(),
                |s| s.to_string(),
            )
        }
    }

    impl From<ALPNInformation> for legacy::TransportALPNInformation {
        fn from(ai: ALPNInformation) -> Self {
            build!(legacy::TransportALPNInformation {
                ?client_alpns: ai.client_alpns.map( |v| {
                    v.into_iter()
                        .map(Into::into)
                        .collect::<Vec<_>>()
                }),
                ?server_alpns: ai.server_alpns.map( |v| {
                    v.into_iter()
                        .map(Into::into)
                        .collect::<Vec<_>>()
                }),
                //
                ?chosen_alpn: ai.chosen_alpn.map(String::from),
            })
        }
    }

    impl From<PreferredAddress> for legacy::PreferredAddress {
        fn from(pa: PreferredAddress) -> Self {
            build!(legacy::PreferredAddress {
                ip_v4: pa.ip_v4,
                ip_v6: pa.ip_v6,
                port_v4: pa.port_v4,
                port_v6: pa.port_v6,
                connection_id: pa.connection_id,
                stateless_reset_token: pa.stateless_reset_token,
            })
        }
    }

    impl From<ParametersSet> for legacy::TransportParametersSet {
        fn from(ps: ParametersSet) -> Self {
            build!(legacy::TransportParametersSet {
                ?owner: ps.owner,
                ?resumption_allowed: ps.resumption_allowed,
                ?early_data_enabled: ps.early_data_enabled,
                ?tls_cipher: ps.tls_cipher,
                ?original_destination_connection_id: ps.original_destination_connection_id,
                ?initial_source_connection_id: ps.initial_source_connection_id,
                ?retry_source_connection_id: ps.retry_source_connection_id,
                ?stateless_reset_token: ps.stateless_reset_token,
                ?disable_active_migration: ps.disable_active_migration,
                ?max_idle_timeout: ps.max_idle_timeout,
                ?max_udp_payload_size: ps.max_udp_payload_size,
                ?ack_delay_exponent: ps.ack_delay_exponent,
                ?max_ack_delay: ps.max_ack_delay,
                ?active_connection_id_limit: ps.active_connection_id_limit,
                ?initial_max_data: ps.initial_max_data,
                ?initial_max_stream_data_bidi_local: ps.initial_max_stream_data_bidi_local,
                ?initial_max_stream_data_bidi_remote: ps.initial_max_stream_data_bidi_remote,
                ?initial_max_stream_data_uni: ps.initial_max_stream_data_uni,
                ?initial_max_streams_bidi: ps.initial_max_streams_bidi,
                ?initial_max_streams_uni: ps.initial_max_streams_uni,
                ?preferred_address: ps.preferred_address,
                // legacy doesnt support these
                // ?unknown_parameters: ,
                // ?max_datagram_frame_size: ps.max_datagram_frame_size,
                // ?grease_quic_bit: ps.grease_quic_bit,
            })
        }
    }

    impl From<ParametersRestored> for legacy::TransportParametersRestored {
        fn from(value: ParametersRestored) -> Self {
            build!(legacy::TransportParametersRestored {
                ?disable_active_migration: value.disable_active_migration,
                ?max_idle_timeout: value.max_idle_timeout,
                ?max_udp_payload_size: value.max_udp_payload_size,
                ?active_connection_id_limit: value.active_connection_id_limit,
                ?initial_max_data: value.initial_max_data,
                ?initial_max_stream_data_bidi_local: value.initial_max_stream_data_bidi_local,
                ?initial_max_stream_data_bidi_remote: value.initial_max_stream_data_bidi_remote,
                ?initial_max_stream_data_uni: value.initial_max_stream_data_uni,
                ?initial_max_streams_bidi: value.initial_max_streams_bidi,
                ?initial_max_streams_uni: value.initial_max_streams_uni,
                // legacy doesnt support these
                // ?max_datagram_frame_size: value.max_datagram_frame_size,
                // ?grease_quic_bit: value.grease_quic_bit,
            })
        }
    }

    impl From<PacketSentTrigger> for legacy::TransportPacketSentTrigger {
        fn from(value: PacketSentTrigger) -> Self {
            match value {
                PacketSentTrigger::RetransmitReordered => Self::RetransmitReordered,
                PacketSentTrigger::RetransmitTimeout => Self::RetransmitTimeout,
                PacketSentTrigger::PtoProbe => Self::PtoProbe,
                PacketSentTrigger::RetransmitCrypto => Self::RetransmitCrypto,
                PacketSentTrigger::CcBandwidthProbe => Self::CcBandwidthProbe,
            }
        }
    }

    impl From<PacketSent> for legacy::TransportPacketSent {
        fn from(value: PacketSent) -> Self {
            build!(legacy::TransportPacketSent {
                header: value.header,
                ?frames: value.frames.map(|v| {
                    v.into_iter()
                        .map(Into::into)
                        .collect::<Vec<_>>()
                }),
                ?stateless_reset_token: value.stateless_reset_token.map(|tk| Bytes::from(tk.0.to_vec())),
                supported_versions: value.supported_versions.into_iter()
                        .map(Into::into)
                        .collect::<Vec<_>>(),
                ?raw: value.raw,
                ?datagram_id: value.datagram_id,
                ?trigger: value.trigger,
            })
        }
    }

    impl From<PacketReceivedTrigger> for legacy::TransportPacketReceivedTrigger {
        #[inline]
        fn from(value: PacketReceivedTrigger) -> Self {
            match value {
                PacketReceivedTrigger::KeysAvailable => Self::KeysAvailable,
            }
        }
    }

    impl From<PacketReceived> for legacy::TransportPacketReceived {
        fn from(value: PacketReceived) -> Self {
            build!(legacy::TransportPacketReceived {
                header: value.header,
                ?frames: value.frames.map(|v| {
                    v.into_iter()
                        .map(Into::into)
                        .collect::<Vec<_>>()
                }),
                ?stateless_reset_token: value.stateless_reset_token.map(|tk| Bytes::from(tk.0.to_vec())),
                supported_versions: value.supported_versions.into_iter()
                        .map(Into::into)
                        .collect::<Vec<_>>(),
                ?raw: value.raw,
                ?datagram_id: value.datagram_id,
                ?trigger: value.trigger,
            })
        }
    }

    impl TryFrom<PacketDroppedTrigger> for legacy::TransportpacketDroppedTrigger {
        type Error = ();
        #[inline]
        fn try_from(value: PacketDroppedTrigger) -> Result<Self, ()> {
            match value {
                // 新设计不如旧的
                PacketDroppedTrigger::InternalError
                | PacketDroppedTrigger::Invalid
                | PacketDroppedTrigger::Genera
                // 似乎并没有完全对应, 移除头部保护失败也是这个错误
                // PacketDroppedTrigger::DecryptionFailure => Ok(Self::PayloadDecryptError),
                | PacketDroppedTrigger::DecryptionFailure
                | PacketDroppedTrigger::Rejected => Err(()),
                PacketDroppedTrigger::Unsupported => Ok(Self::UnsupportedVersion),
                PacketDroppedTrigger::Duplicate => Ok(Self::Duplicate),
                PacketDroppedTrigger::ConnectionUnknown => Ok(Self::UnknownConnectionId),
                PacketDroppedTrigger::KeyUnavailable => Ok(Self::KeyUnavailable),
            }
        }
    }

    impl From<PacketDropped> for legacy::TransportPacketDropped {
        fn from(value: PacketDropped) -> Self {
            build!(legacy::TransportPacketDropped {
                ?header: value.header,
                ?raw: value.raw,
                ?datagram_id: value.datagram_id,
                ?trigger: value.trigger.and_then(|trigger| legacy::TransportpacketDroppedTrigger::try_from(trigger).ok()),
            })
        }
    }

    impl From<PacketBufferedTrigger> for legacy::TransportPacketBufferedTrigger {
        #[inline]
        fn from(value: PacketBufferedTrigger) -> Self {
            match value {
                PacketBufferedTrigger::Backpressure => Self::Backpressure,
                PacketBufferedTrigger::KeysUnavailable => Self::KeysUnavailable,
            }
        }
    }

    impl From<PacketBuffered> for legacy::TransportPacketBuffered {
        fn from(value: PacketBuffered) -> Self {
            build!(legacy::TransportPacketBuffered {
                ?header: value.header,
                ?raw: value.raw,
                ?datagram_id: value.datagram_id,
                ?trigger: value.trigger,
            })
        }
    }

    impl From<PacketsAcked> for legacy::TransportPacketsAcked {
        fn from(value: PacketsAcked) -> Self {
            build!(legacy::TransportPacketsAcked {
                ?packet_number_space: value.packet_number_space,
                packet_numbers: value.packet_nubers,
            })
        }
    }

    impl From<UdpDatagramsSent> for legacy::TransportDatagramsSent {
        fn from(value: UdpDatagramsSent) -> Self {
            build!(legacy::TransportDatagramsSent {
                ?count: value.count,
                raw: value.raw.into_iter().collect::<Vec<_>>(),
                datagram_ids: value.datagram_ids,
            })
        }
    }

    impl From<UdpDatagramsReceived> for legacy::TransportDatagramsReceived {
        fn from(value: UdpDatagramsReceived) -> Self {
            build!(legacy::TransportDatagramsReceived {
                ?count: value.count,
                raw: value.raw.into_iter().collect::<Vec<_>>(),
                datagram_ids: value.datagram_ids,
            })
        }
    }

    impl From<UdpDatagramDropped> for legacy::TransportDatagramDropped {
        fn from(value: UdpDatagramDropped) -> Self {
            build!(legacy::TransportDatagramDropped {
                ?raw: value.raw,
            })
        }
    }

    impl From<StreamState> for legacy::StreamState {
        #[inline]
        fn from(value: StreamState) -> Self {
            match value {
                StreamState::Base(BaseStreamStates::Idle) => Self::Idle,
                StreamState::Base(BaseStreamStates::Open) => Self::Open,
                StreamState::Base(BaseStreamStates::Closed) => Self::Closed,
                StreamState::Granular(GranularStreamStates::HalfClosedLocal) => {
                    Self::HalfClosedLocal
                }
                StreamState::Granular(GranularStreamStates::HalfClosedRemote) => {
                    Self::HalfClosedRemote
                }
                StreamState::Granular(GranularStreamStates::Ready) => Self::Ready,
                StreamState::Granular(GranularStreamStates::Send) => Self::Send,
                StreamState::Granular(GranularStreamStates::DataSent) => Self::DataSent,
                StreamState::Granular(GranularStreamStates::ResetSent) => Self::ResetSent,
                StreamState::Granular(GranularStreamStates::ResetReceived) => Self::ResetReceived,
                StreamState::Granular(GranularStreamStates::Receive) => Self::Receive,
                StreamState::Granular(GranularStreamStates::SizeKnown) => Self::SizeKnown,
                StreamState::Granular(GranularStreamStates::DataRead) => Self::DataRead,
                StreamState::Granular(GranularStreamStates::ResetRead) => Self::ResetRead,
                StreamState::Granular(GranularStreamStates::DataReceived) => Self::DataReceived,
                StreamState::Granular(GranularStreamStates::Destroyed) => Self::Destroyed,
            }
        }
    }

    impl From<StreamSide> for legacy::StreamSide {
        #[inline]
        fn from(value: StreamSide) -> Self {
            match value {
                StreamSide::Sending => Self::Sending,
                StreamSide::Receiving => Self::Receiving,
            }
        }
    }

    impl From<StreamStateUpdated> for legacy::TransportStreamStateUpdated {
        fn from(value: StreamStateUpdated) -> Self {
            build!(legacy::TransportStreamStateUpdated {
                stream_id: value.stream_id,
                ?stream_type: value.stream_type,
                ?old: value.old,
                new: value.new,
                ?stream_side: value.stream_side,
            })
        }
    }

    impl From<FramesProcessed> for legacy::TransportFramesProcessed {
        fn from(value: FramesProcessed) -> Self {
            assert!(
                value.packet_numbers.as_ref().is_none()
                    || value.packet_numbers.as_ref().is_some_and(|v| v.len() != 1),
                "it not possible to do this convert"
            );
            build!(legacy::TransportFramesProcessed {
                frames: value.frames.into_iter().map(Into::into).collect::<Vec<_>>(),
                ?packet_number: value.packet_numbers.map(|v| v[0]),
            })
        }
    }

    impl From<StreamDataLocation> for legacy::StreamDataLocation {
        #[inline]
        fn from(value: StreamDataLocation) -> Self {
            match value {
                StreamDataLocation::Application => Self::Application,
                StreamDataLocation::Transport => Self::Transport,
                StreamDataLocation::Network => Self::Network,
            }
        }
    }

    impl From<StreamDataMoved> for legacy::TransportDataMoved {
        fn from(value: StreamDataMoved) -> Self {
            build!(legacy::TransportDataMoved {
                ?stream_id: value.stream_id,
                ?offset: value.offset,
                ?length: value.length,
                ?from: value.from,
                ?to: value.to,
                ?data: value.raw.and_then(|raw| raw.data),
            })
        }
    }
}
