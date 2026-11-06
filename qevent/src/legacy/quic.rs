use std::collections::HashMap;

use derive_builder::Builder;
use derive_more::{From, Into};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{HexString, RawInfo};

#[serde_with::skip_serializing_none]
#[derive(Default, Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ConnectivityServerListening {
    ip_v4: Option<IPAddress>,
    ip_v6: Option<IPAddress>,
    port_v4: Option<u16>,
    port_v6: Option<u16>,

    /// the server will always answer client initials with a retry
    /// (no 1-RTT connection setups by choice)
    retry_required: Option<bool>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ConnectivityConnectionStarted {
    #[builder(default)]
    ip_version: Option<IPVersion>,
    src_ip: IPAddress,
    dst_ip: IPAddress,

    /// transport layer protocol
    #[builder(default = "ConnectivityConnectionStarted::default_protocol()")]
    #[serde(default = "ConnectivityConnectionStarted::default_protocol")]
    protocol: String,
    #[builder(default)]
    src_port: Option<u16>,
    #[builder(default)]
    dst_port: Option<u16>,

    #[builder(default)]
    src_cid: Option<ConnectionID>,
    #[builder(default)]
    dst_cid: Option<ConnectionID>,
}

impl ConnectivityConnectionStarted {
    pub fn default_protocol() -> String {
        "QUIC".to_string()
    }
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ConnectivityConnectionClosed {
    /// which side closed the connection
    #[builder(default)]
    owner: Option<Owner>,

    #[builder(default)]
    connection_code: Option<ConnectionCode>,
    #[builder(default)]
    application_code: Option<ApplicationCode>,
    #[builder(default)]
    internal_code: Option<u32>,

    #[builder(default)]
    reason: Option<String>,
    #[builder(default)]
    trigger: Option<ConnectivityConnectionClosedTrigger>,
}

#[derive(Debug, Clone, Copy, From, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ConnectionCode {
    TransportError(TransportError),
    CryptoError(CryptoError),
    Value(u32),
}

#[derive(Debug, Clone, From, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ApplicationCode {
    ApplicationError(ApplicationError),
    Value(u32),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityConnectionClosedTrigger {
    Clean,
    HandshakeTimeout,
    IdleTimeout,
    /// this is called the "immediate close" in the QUIC RFC
    Error,
    StatelessReset,
    VersionMismatch,
    /// for example HTTP/3's GOAWAY frame
    Application,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ConnectivityConnectionIdUpdated {
    owner: Owner,

    old: Option<ConnectionID>,
    new: Option<ConnectionID>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ConnectivitySpinBitUpdated {
    state: bool,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ConnectivityConnectionStateUpdated {
    #[builder(default)]
    old: Option<ConnectionState>,
    new: ConnectionState,
}

// SimpleConnectionState is a subset of this, so skip SimpleConnectionState
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// initial sent/received
    Attempted,
    /// peer address validated by: client sent Handshake packet OR
    /// client used CONNID chosen by the server.
    /// transport-draft-32, section-8.1
    PeerValidated,
    HandshakeStarted,
    /// 1 RTT can be sent, but handshake isn't done yet
    EarlyWrite,
    /// TLS handshake complete: Finished received and sent
    /// tls-draft-32, section-4.1.1
    HandshakeComplete,
    /// HANDSHAKE_DONE sent/received (connection is now "active", 1RTT
    /// can be sent). tls-draft-32, section-4.1.2
    HandshakeConfirmed,
    Closing,
    /// connection_close sent/received
    Draining,
    /// draining period done, connection state discarded
    Closed,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct SecurityKeyUpdated {
    key_type: KeyType,

    old: Option<HexString>,
    new: HexString,

    /// needed for 1RTT key updates
    generation: Option<u32>,

    trigger: Option<SecurityKeyUpdatedTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityKeyUpdatedTrigger {
    /// (e.g., initial, handshake and 0-RTT keys
    /// are generated by TLS)
    Tls,
    RemoteUpdate,
    LocalUpdate,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct SecurityKeyRetired {
    key_type: KeyType,
    key: Option<HexString>,

    /// needed for 1RTT key updates
    generation: Option<u32>,

    trigger: Option<SecurityKeyRetiredTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityKeyRetiredTrigger {
    /// (e.g., initial, handshake and 0-RTT keys
    /// are generated by TLS)
    Tls,
    RemoteUpdate,
    LocalUpdate,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportVersionInformation {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    server_versions: Vec<QuicVersion>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    client_versions: Vec<QuicVersion>,
    chosen_version: Option<QuicVersion>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportALPNInformation {
    server_alpns: Option<Vec<String>>,
    client_alpns: Option<Vec<String>>,
    chosen_alpn: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportParametersSet {
    owner: Option<Owner>,

    /// true if valid session ticket was received
    resumption_allowed: Option<bool>,

    /// true if early data extension was enabled on the TLS layer
    early_data_enabled: Option<bool>,

    /// e.g., "AES_128_GCM_SHA256"
    tls_cipher: Option<String>,

    /// depends on the TLS cipher, but it's easier to be explicit.
    /// in bytes
    #[serde(default = "TransportParametersSet::default_aead_key_length")]
    #[builder(default = "TransportParametersSet::default_aead_key_length()")]
    aead_tag_length: u8,

    /// transport parameters from the TLS layer:
    original_destination_connection_id: Option<ConnectionID>,
    initial_source_connection_id: Option<ConnectionID>,
    retry_source_connection_id: Option<ConnectionID>,
    stateless_reset_token: Option<Token>,
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
}

impl TransportParametersSet {
    pub fn default_aead_key_length() -> u8 {
        16
    }
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct PreferredAddress {
    ip_v4: IPAddress,
    ip_v6: IPAddress,

    port_v4: u16,
    port_v6: u16,

    connection_id: ConnectionID,
    stateless_reset_token: Token,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportParametersRestored {
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
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportPacketSent {
    header: PacketHeader,

    /// see appendix for the QuicFrame definitions
    frames: Option<Vec<QuicFrame>>,

    #[serde(default)]
    #[builder(default)]
    is_coalesced: bool,

    /// only if header.packet_type === "retry"
    #[builder(default)]
    retry_token: Option<Token>,

    /// only if header.packet_type === "stateless_reset"
    /// is always 128 bits in length.
    #[builder(default)]
    stateless_reset_token: Option<HexString>,

    /// only if header.packet_type === "version_negotiation"
    #[builder(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    supported_versions: Vec<QuicVersion>,

    #[builder(default)]
    raw: Option<RawInfo>,
    #[builder(default)]
    datagram_id: Option<u32>,

    #[builder(default)]
    trigger: Option<TransportPacketSentTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportPacketSentTrigger {
    RetransmitReordered,
    RetransmitTimeout,
    PtoProbe,
    RetransmitCrypto,
    CcBandwidthProbe,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportPacketReceived {
    header: PacketHeader,

    /// see appendix for the definitions
    #[builder(default)]
    frames: Option<Vec<QuicFrame>>,

    #[serde(default)]
    #[builder(default)]
    is_coalesced: bool,

    /// only if header.packet_type === "retry"
    #[builder(default)]
    retry_token: Option<Token>,

    /// only if header.packet_type === "stateless_reset"
    #[builder(default)]
    /// Is always 128 bits in length.
    stateless_reset_token: Option<HexString>,

    /// only if header.packet_type === "version_negotiation"
    #[builder(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    supported_versions: Vec<QuicVersion>,

    #[builder(default)]
    raw: Option<RawInfo>,
    #[builder(default)]
    datagram_id: Option<u32>,

    #[builder(default)]
    trigger: Option<TransportPacketReceivedTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportPacketReceivedTrigger {
    KeysAvailable,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportPacketDropped {
    /// primarily packet_type should be filled here,
    /// as other fields might not be parseable
    header: Option<PacketHeader>,

    raw: Option<RawInfo>,
    datagram_id: Option<u32>,

    trigger: Option<TransportpacketDroppedTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportpacketDroppedTrigger {
    KeyUnavailable,
    UnknownConnectionId,
    HeaderParseError,
    PayloadDecryptError,
    ProtocolViolation,
    DosPrevention,
    UnsupportedVersion,
    UnexpectedPacket,
    UnexpectedSourceConnectionId,
    UnexpectedVersion,
    Duplicate,
    InvalidInitial,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportPacketBuffered {
    /// primarily packet_type and possible packet_number should be
    /// filled here as other elements might not be available yet
    header: Option<PacketHeader>,

    raw: Option<RawInfo>,
    datagram_id: Option<u32>,

    trigger: Option<TransportPacketBufferedTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportPacketBufferedTrigger {
    /// indicates the parser cannot keep up, temporarily buffers
    /// packet for later processing
    Backpressure,
    /// if packet cannot be decrypted because the proper keys were
    /// not yet available
    KeysUnavailable,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportPacketsAcked {
    packet_number_space: Option<PacketNumberSpace>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    packet_numbers: Vec<u64>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportDatagramsSent {
    /// to support passing multiple at once
    count: Option<u16>,

    /// RawInfo:length field indicates total length of the datagrams
    /// including UDP header length
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    raw: Vec<RawInfo>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    datagram_ids: Vec<u32>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportDatagramsReceived {
    /// to support passing multiple at once
    count: Option<u16>,

    /// RawInfo:length field indicates total length of the datagrams
    /// including UDP header length
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    raw: Vec<RawInfo>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    datagram_ids: Vec<u32>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportDatagramDropped {
    raw: Option<RawInfo>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportStreamStateUpdated {
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamState {
    Idle,
    Open,
    // bidirectional stream states, RFC 9000 Section 3.4.
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
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
pub enum StreamType {
    Unidirectional,
    Bidirectional,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamSide {
    Sending,
    Receiving,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportFramesProcessed {
    /// see appendix for the QuicFrame definitions
    frames: Vec<QuicFrame>,

    #[builder(default)]
    packet_number: Option<u64>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TransportDataMoved {
    stream_id: Option<u64>,
    offset: Option<u64>,

    /// byte length of the moved data
    length: Option<u64>,

    from: Option<StreamDataLocation>,
    to: Option<StreamDataLocation>,

    /// raw bytes that were transferred
    data: Option<HexString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamDataLocation {
    User,
    Application,
    Transport,
    Network,
    Other(String),
}

impl Serialize for StreamDataLocation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            StreamDataLocation::User => serializer.serialize_str("user"),
            StreamDataLocation::Application => serializer.serialize_str("application"),
            StreamDataLocation::Transport => serializer.serialize_str("transport"),
            StreamDataLocation::Network => serializer.serialize_str("network"),
            StreamDataLocation::Other(s) => serializer.serialize_str(s),
        }
    }
}

impl<'de> Deserialize<'de> for StreamDataLocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match String::deserialize(deserializer)? {
            s if s == "user" => Ok(StreamDataLocation::User),
            s if s == "application" => Ok(StreamDataLocation::Application),
            s if s == "transport" => Ok(StreamDataLocation::Transport),
            s if s == "network" => Ok(StreamDataLocation::Network),
            s => Ok(StreamDataLocation::Other(s)),
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct RecoveryParametersSet {
    /// Loss detection, see recovery draft-23, Appendix A.2
    /// in amount of packets
    #[builder(default)]
    reordering_threshold: Option<u16>,

    /// as RTT multiplier
    #[builder(default)]
    time_threshold: Option<f32>,

    /// in ms
    timer_granularity: u16,

    /// in ms
    #[builder(default)]
    initial_rtt: Option<f32>,

    /// congestion control, Appendix B.1.
    /// in bytes. Note: this, could be updated after pmtud
    #[builder(default)]
    max_datagram_size: Option<u32>,

    /// in bytes
    #[builder(default)]
    initial_congestion_window: Option<u64>,

    /// Note: this, could change when max_datagram_size changes
    /// in bytes
    #[builder(default)]
    minimum_congestion_window: Option<u32>,
    #[builder(default)]
    loss_reduction_factor: Option<f32>,

    /// as PTO multiplier
    #[builder(default)]
    persistent_congestion_threshold: Option<u16>,

    /// Additionally, this event can contain any number of unspecified fields
    /// to support different recovery approaches.
    #[builder(default)]
    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    custom_fields: HashMap<String, serde_json::Value>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct RecoveryMetricsUpdated {
    /// Loss detection, see recovery draft-23, Appendix A.3
    /// all following rtt fields are expressed in ms
    #[builder(default)]
    min_rtt: Option<f32>,
    #[builder(default)]
    smoothed_rtt: Option<f32>,
    #[builder(default)]
    latest_rtt: Option<f32>,
    #[builder(default)]
    rtt_variance: Option<f32>,

    #[builder(default)]
    pto_count: Option<u16>,

    /// Congestion control, Appendix B.2.
    /// in bytes
    #[builder(default)]
    congestion_window: Option<u64>,
    #[builder(default)]
    bytes_in_flight: Option<u64>,

    /// in bytes
    #[builder(default)]
    ssthresh: Option<u64>,

    /// qlog defined
    /// sum of all packet number spaces
    #[builder(default)]
    packets_in_flight: Option<u64>,

    /// in bits per second
    #[builder(default)]
    pacing_rate: Option<u64>,

    /// Additionally, this event can contain any number of unspecified fields
    /// to support different recovery approaches.
    #[builder(default)]
    #[serde(flatten)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    custom_fields: HashMap<String, serde_json::Value>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct RecoveryCongestionStateUpdated {
    #[builder(default)]
    old: Option<String>,
    new: String,

    #[builder(default)]
    trigger: Option<RecoveryCongestionStateUpdatedTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryCongestionStateUpdatedTrigger {
    PersistentCongestion,
    Ecn,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct RecoveryLossTimerUpdated {
    /// called "mode" in draft-23 A.9.
    #[builder(default)]
    timer_type: Option<LossTimerType>,
    #[builder(default)]
    packet_number_space: Option<PacketNumberSpace>,

    event_type: LossTimerEventType,

    /// if event_type === "set": delta, time is in ms from
    /// this event's timestamp until when the timer will trigger
    #[builder(default)]
    delta: Option<f32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LossTimerType {
    Ack,
    Pto,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LossTimerEventType {
    Set,
    Expired,
    Cancelled,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct RecoveryPacketLost {
    /// should include at least the packet_type and packet_number
    header: Option<PacketHeader>,

    /// not all implementations will keep track of full
    /// packets, so these are optional
    /// see appendix for the QuicFrame definitions
    frames: Option<Vec<QuicFrame>>,

    trigger: Option<RecoveryPacketLostTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPacketLostTrigger {
    ReorderingThreshold,
    TimeThreshold,
    /// draft-23 section 5.3.1, MAY
    PtoExpired,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct RecoveryMarkedForRetransmit {
    /// see appendix for the QuicFrame definitions
    frames: Vec<QuicFrame>,
}

// A.1: skip

// A.2
#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct QuicVersion(HexString);

#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ConnectionID(HexString);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    Local,
    Remote,
}

// A.5
#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct IPAddress(String);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IPVersion {
    V4,
    V6,
}

// A.6
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketType {
    Initial,
    Retry,
    Handshake,
    #[serde(rename = "0RTT")]
    ZeroRTT,
    #[serde(rename = "1RTT")]
    OneRTT,
    StatelessReset,
    VersionNegotiation,
    Unknown,
}

// A.7
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketNumberSpace {
    Initial,
    Handshake,
    ApplicationData,
}

// A.8

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct PacketHeader {
    packet_type: PacketType,
    // In rfc https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-quic-events-02#name-packetheader, this field mut be present.
    // But in fact, for packet type Retry and VN and for packet dropped before pn decoded, this field is not exist.
    // In the updated RFC this field is optional, so here we simply mark it as optional as well.
    #[builder(default)]
    packet_number: Option<u64>,

    /// the bit flags of the packet headers (spin bit, key update bit,
    /// etc. up to and including the packet number length bits
    /// if present
    #[builder(default)]
    flags: Option<u8>,

    /// only if packet_type === "initial"
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

// A.9
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Token {
    r#type: Option<TokenType>,

    /// byte length of the token
    length: Option<u32>,

    /// raw byte value of the token
    data: Option<HexString>,

    /// decoded fields included in the token
    /// (typically: peer,'s IP address, creation time)
    #[builder(default)]
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    details: HashMap<String, Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Retry,
    Resumption,
    StatelessReset,
}

// A.10
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    ServerInitialSecret,
    ClientInitialSecret,
    ServerHandshakeSecret,
    ClientHandshakeSecret,
    #[serde(rename = "server_0rtt_secret")]
    Server0RTTSecret,
    #[serde(rename = "client_0rtt_secret")]
    Client0RTTSecret,
    #[serde(rename = "server_1rtt_secret")]
    Server1RTTSecret,
    #[serde(rename = "client_1rtt_secret")]
    Client1RTTSecret,
}

#[derive(Debug, Clone, Serialize, From, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ConnectionCloseTriggerFrameType {
    Id(u64),
    Text(String),
}

#[derive(Debug, Clone, From, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ConnectionCloseErrorCode {
    TransportError(TransportError),
    ApplicationError(ApplicationError),
    Value(u64),
}

// A.11#
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "frame_type")]
#[serde(rename_all = "snake_case")]
pub enum QuicFrame {
    Padding {
        length: Option<u32>,
        payload_length: u32,
    },

    Ping {
        length: Option<u32>,
        payload_length: Option<u32>,
    },

    Ack {
        ack_delay: Option<f32>,
        acked_ranges: Vec<[u64; 2]>,

        ect1: Option<u64>,
        ect0: Option<u64>,
        ce: Option<u64>,

        length: Option<u32>,
        payload_length: Option<u32>,
    },

    ResetStream {
        stream_id: u64,
        error_code: ApplicationCode,
        final_size: u64,

        length: Option<u32>,
        payload_length: Option<u32>,
    },

    StopSending {
        stream_id: u64,
        error_code: ApplicationCode,

        length: Option<u32>,
        payload_length: Option<u32>,
    },

    Crypto {
        offset: u64,
        length: u64,

        payload_length: Option<u32>,
    },

    NewToken {
        token: Token,
    },

    Stream {
        stream_id: u64,
        offset: u64,
        length: u64,
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
        connection_id_length: Option<u8>,
        connection_id: ConnectionID,
        stateless_reset_token: Option<Token>,
    },

    RetireConnectionId {
        sequence_number: u32,
    },

    PathChallenge {
        data: Option<HexString>,
    },

    PathResponse {
        data: Option<HexString>,
    },

    ConnectionClose {
        error_space: Option<ConnectionCloseErrorSpace>,
        error_code: Option<ConnectionCloseErrorCode>,
        raw_error_code: Option<u32>,
        reason: Option<String>,

        trigger_frame_type: Option<ConnectionCloseTriggerFrameType>,
    },

    HandshakeDone {},

    Unknown {
        raw_frame_type: u64,
        raw_length: Option<u32>,
        raw: Option<HexString>,
    },
    // not in v1
    Datagram {
        length: Option<u64>,
        raw: Option<RawInfo>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ConnectionCloseErrorSpace {
    Transport,
    Application,
}

// A.11.22
#[derive(Debug, Clone, Copy, From, Serialize, Deserialize, PartialEq, Eq)]
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
    // not in v1
    KeyUpdateError,
    AeadLimitReached,
    NoViablePath,
}

// A.11.23
#[derive(Debug, Clone, From, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplicationError(String);

// A.11.24
#[derive(Debug, Clone, Copy, From, PartialEq)]
pub struct CryptoError(u8);

impl Serialize for CryptoError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("crypto_error_0x1{:02x}", self.0))
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
            |s| u8::from_str_radix(s, 16).map(CryptoError).map_err(serde::de::Error::custom),
        )
    }
}

crate::gen_builder_method! {
    ConnectivityServerListeningBuilder        => ConnectivityServerListening;
    ConnectivityConnectionStartedBuilder      => ConnectivityConnectionStarted;
    ConnectivityConnectionClosedBuilder       => ConnectivityConnectionClosed;
    ConnectivityConnectionIdUpdatedBuilder    => ConnectivityConnectionIdUpdated;
    ConnectivitySpinBitUpdatedBuilder         => ConnectivitySpinBitUpdated;
    ConnectivityConnectionStateUpdatedBuilder => ConnectivityConnectionStateUpdated;
    SecurityKeyUpdatedBuilder                 => SecurityKeyUpdated;
    SecurityKeyRetiredBuilder                 => SecurityKeyRetired;
    TransportVersionInformationBuilder        => TransportVersionInformation;
    TransportALPNInformationBuilder           => TransportALPNInformation;
    TransportParametersSetBuilder             => TransportParametersSet;
    PreferredAddressBuilder                   => PreferredAddress;
    TransportParametersRestoredBuilder        => TransportParametersRestored;
    TransportPacketSentBuilder                => TransportPacketSent;
    TransportPacketReceivedBuilder            => TransportPacketReceived;
    TransportPacketDroppedBuilder             => TransportPacketDropped;
    TransportPacketBufferedBuilder            => TransportPacketBuffered;
    TransportPacketsAckedBuilder              => TransportPacketsAcked;
    TransportDatagramsSentBuilder             => TransportDatagramsSent;
    TransportDatagramsReceivedBuilder         => TransportDatagramsReceived;
    TransportDatagramDroppedBuilder           => TransportDatagramDropped;
    TransportStreamStateUpdatedBuilder        => TransportStreamStateUpdated;
    TransportFramesProcessedBuilder           => TransportFramesProcessed;
    TransportDataMovedBuilder                 => TransportDataMoved;
    RecoveryParametersSetBuilder              => RecoveryParametersSet;
    RecoveryMetricsUpdatedBuilder             => RecoveryMetricsUpdated;
    RecoveryCongestionStateUpdatedBuilder     => RecoveryCongestionStateUpdated;
    RecoveryLossTimerUpdatedBuilder           => RecoveryLossTimerUpdated;
    RecoveryPacketLostBuilder                 => RecoveryPacketLost;
    RecoveryMarkedForRetransmitBuilder        => RecoveryMarkedForRetransmit;
    PacketHeaderBuilder                       => PacketHeader;
    TokenBuilder                              => Token;
}
