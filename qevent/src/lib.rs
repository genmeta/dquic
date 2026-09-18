pub mod legacy;
pub mod loglevel;
pub mod quic;
pub mod telemetry;

#[doc(hidden)]
pub mod macro_support;
mod macros;
pub mod packet;

use std::{collections::HashMap, fmt::Display, net::SocketAddr};

use bytes::Bytes;
use derive_builder::Builder;
use derive_more::{Display, From, Into};
use qbase::{cid::ConnectionId, role::Role, util::Buffer};
use quic::ConnectionID;
use serde::{Deserialize, Serialize};

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct LogFile {
    file_schema: String,
    serialization_format: String,
    #[builder(default)]
    title: Option<String>,
    #[builder(default)]
    description: Option<String>,
    #[builder(default)]
    event_schemas: Vec<String>,
}

#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into), build_fn(private, name = "fallible_build"))]
pub struct QlogFile {
    #[serde(flatten)]
    log_file: LogFile,
    traces: Vec<Traces>,
}

/// A qlog file using the QlogFileSeq schema can be serialized to a
/// streamable JSON format called JSON Text Sequences (JSON-SEQ)
/// ([RFC7464]). The top-level element in this schema defines only a
/// small set of "header" fields and an array of component traces.
///
/// [RFC7464]: https://www.rfc-editor.org/rfc/rfc7464
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into), build_fn(private, name = "fallible_build"))]
pub struct QlogFileSeq {
    #[serde(flatten)]
    log_file: LogFile,
    trace_seq: TraceSeq,
}

impl QlogFileSeq {
    pub const SCHEMA: &'static str = "urn:ietf:params:qlog:file:sequential";
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Traces {
    Trace(Trace),
    TraceError(TraceError),
}

///  The exact conceptual definition of a Trace can be fluid.  For
/// example, a trace could contain all events for a single connection,
/// for a single endpoint, for a single measurement interval, for a
/// single protocol, etc.  In the normal use case however, a trace is a
/// log of a single data flow collected at a single location or vantage
/// point.  For example, for QUIC, a single trace only contains events
/// for a single logical QUIC connection for either the client or the
/// server.
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Trace {
    /// The optional "title" fields provide additional free-text information about the trace.
    #[builder(default)]
    title: Option<String>,
    /// The optional "description" fields provide additional free-text information about the trace.
    #[builder(default)]
    description: Option<String>,
    #[builder(default)]
    common_fields: Option<CommonFields>,
    #[builder(default)]
    vantage_point: Option<VantagePoint>,
    events: Vec<Event>,
}

/// TraceSeq is used with QlogFileSeq. It is conceptually similar to a
/// Trace, with the exception that qlog events are not contained within
/// it, but rather appended after it in a QlogFileSeq.
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct TraceSeq {
    /// The optional "title" fields provide additional free-text information about the trace.
    title: Option<String>,
    /// The optional "description" fields provide additional free-text information about the trace.
    description: Option<String>,
    common_fields: Option<CommonFields>,
    vantage_point: Option<VantagePoint>,
}

#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct CommonFields {
    path: PathID,
    time_format: TimeFormat,
    reference_time: ReferenceTime,
    protocol_types: ProtocolTypeList,
    group_id: GroupID,
    #[builder(default)]
    #[serde(flatten)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    //  * text => any
    custom_fields: HashMap<String, serde_json::Value>,
}

/// A VantagePoint describes the vantage point from which a trace originates
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct VantagePoint {
    #[builder(default)]
    name: Option<String>,
    r#type: VantagePointType,
    #[builder(default)]
    flow: Option<VantagePointType>,
}

#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VantagePointType {
    /// endpoint which initiates the connection
    Client,
    /// endpoint which accepts the connection
    Server,
    /// observer in between client and server
    Network,
    #[default]
    Unknow,
}

impl From<Role> for VantagePointType {
    fn from(role: Role) -> Self {
        match role {
            Role::Client => VantagePointType::Client,
            Role::Server => VantagePointType::Server,
        }
    }
}

impl Display for VantagePointType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VantagePointType::Client => write!(f, "client"),
            VantagePointType::Server => write!(f, "server"),
            VantagePointType::Network => write!(f, "network"),
            VantagePointType::Unknow => write!(f, "unknow"),
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TraceError {
    error_description: String,
    #[builder(default)]
    uri: Option<String>,
    #[builder(default)]
    vantage_point: Option<VantagePoint>,
}

/// Events are logged at a time instant and convey specific details of the logging use case.
///
/// Events can contain any amount of custom fields.
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Event {
    time: f64,
    #[serde(flatten)]
    data: EventData,
    /// A qlog event can be associated with a single "network path" (usually, but not always, identified by a 4-tuple
    /// of IP addresses and ports). In many cases, the path will be the same for all events in a given trace, and does
    /// not need to be logged explicitly with each event. In this case, the "path" field can be omitted (in which case
    /// the default value of "" is assumed) or reflected in "common_fields" instead
    #[builder(default)]
    path: Option<PathID>,
    #[builder(default)]
    time_format: Option<TimeFormat>,
    #[builder(default)]
    protocol_types: Option<ProtocolTypeList>,
    #[builder(default)]
    group_id: Option<GroupID>,
    #[builder(default)]
    system_info: Option<SystemInformation>,
    /// events can contain any amount of custom fields
    #[builder(default)]
    #[serde(flatten)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    // * text => any
    custom_fields: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct PathID(String);

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
#[serde(try_from = "UncheckedReferenceTime")]
pub struct ReferenceTime {
    /// The required "clock_type" field represents the type of clock used for time measurements. The value "system"
    /// represents a clock that uses system time, commonly measured against a chosen or well-known epoch. However,
    /// depending on the system, System time can potentially jump forward or back. In contrast, a clock using monotonic
    /// time is generally guaranteed to never go backwards. The value "monotonic" represents such a clock.
    clock_type: TimeClockType,
    /// The required "epoch" field is the start of the ReferenceTime. When using the "system" clock type, the epoch field
    /// **SHOULD** have a date/time value using the format defined in [RFC3339]. However, the value "unknown" **MAY** be
    /// used
    ///
    /// [RFC3339]: https://www.rfc-editor.org/rfc/rfc3339
    #[serde(default)]
    epoch: TimeEpoch,
    /// The optional "wall_clock_time" field can be used to provide an approximate date/time value that logging commenced
    /// at if the epoch value is "unknown". It uses the format defined in [RFC3339]. Note that conversion of timestamps
    /// to calendar time based on wall clock times cannot be safely relied on.
    ///
    /// [RFC3339]: https://www.rfc-editor.org/rfc/rfc3339
    #[builder(default)]
    wall_clock_time: Option<RFC3339DateTime>,
}

/// Intermediate data types during deserialization
#[derive(Deserialize)]
struct UncheckedReferenceTime {
    clock_type: TimeClockType,
    #[serde(default)]
    epoch: TimeEpoch,
    wall_clock_time: Option<RFC3339DateTime>,
}

impl TryFrom<UncheckedReferenceTime> for ReferenceTime {
    type Error = &'static str;
    fn try_from(value: UncheckedReferenceTime) -> Result<Self, Self::Error> {
        if value.clock_type == TimeClockType::Monotaonic && value.epoch != TimeEpoch::Unknow {
            return Err(
                r#"When using the "monotonic" clock type, the epoch field MUST have the value "unknown"."#,
            );
        }

        Ok(ReferenceTime {
            clock_type: value.clock_type,
            epoch: value.epoch,
            wall_clock_time: value.wall_clock_time,
        })
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimeClockType {
    /// The value "system" represents a clock that uses system time, commonly measured against a chosen or well-known
    /// epoch
    #[default]
    System,
    /// A clock using monotonic time is generally guaranteed to never go backwards. The value "monotonic" represents
    /// such a clock.
    ///
    /// When using the "monotonic" clock type, the epoch field MUST have the value "unknown".
    Monotaonic,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimeEpoch {
    Unknow,
    #[serde(untagged)]
    RFC3339DateTime(RFC3339DateTime),
}

impl Default for TimeEpoch {
    fn default() -> Self {
        Self::RFC3339DateTime(Default::default())
    }
}

#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct RFC3339DateTime(String);

impl Default for RFC3339DateTime {
    fn default() -> Self {
        Self("1970-01-01T00:00:00.000Z".to_owned())
    }
}

#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimeFormat {
    /// A duration relative to the ReferenceTime "epoch" field. This approach uses the largest amount of characters.
    /// It is good for stateless loggers. This is the default value of the "time_format" field.
    #[default]
    RelativeToEpoch,
    /// A delta-encoded value, based on the previously logged value. The first event in a trace is always relative to
    /// the ReferenceTime. This approach uses the least amount of characters. It is suitable for stateful loggers.
    RelativeToPreviousEvent,
}

#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ProtocolTypeList(Vec<ProtocolType>);

#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ProtocolType(String);

impl ProtocolType {
    pub fn quic() -> ProtocolType {
        ProtocolType("QUIC".to_owned())
    }

    pub fn http3() -> ProtocolType {
        ProtocolType("HTTP/3".to_owned())
    }
}

#[derive(Debug, Display, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct GroupID(String);

impl From<ConnectionId> for GroupID {
    fn from(value: ConnectionId) -> Self {
        Self(format!("{value:x}"))
    }
}

impl From<ConnectionID> for GroupID {
    fn from(value: ConnectionID) -> Self {
        Self(format!("{value:x}"))
    }
}

impl From<(SocketAddr, SocketAddr)> for GroupID {
    fn from(_value: (SocketAddr, SocketAddr)) -> Self {
        todo!()
    }
}

/// The "system_info" field can be used to record system-specific details related to an event. This is useful, for instance,
/// where an application splits work across CPUs, processes, or threads and events for a single trace occur on potentially
/// different combinations thereof. Each field is optional to support deployment diversity.
#[derive(Builder, Default, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde_with::skip_serializing_none]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct SystemInformation {
    processor_id: Option<u32>,
    process_id: Option<u32>,
    thread_id: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventImportance {
    Core = 1,
    Base = 2,
    Extra = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "name", content = "data")]
#[enum_dispatch::enum_dispatch(BeEventData)]
pub enum EventData {
    #[serde(rename = "quic:server_listening")]
    ServerListening(quic::connectivity::ServerListening),
    #[serde(rename = "quic:connection_started")]
    ConnectionStarted(quic::connectivity::ConnectionStarted),
    #[serde(rename = "quic:connection_closed")]
    ConnectionClosed(quic::connectivity::ConnectionClosed),
    #[serde(rename = "quic:connection_id_updated")]
    ConnectionIdUpdated(quic::connectivity::ConnectionIdUpdated),
    #[serde(rename = "quic:spin_bit_updated")]
    SpinBitUpdated(quic::connectivity::SpinBitUpdated),
    #[serde(rename = "quic:connection_state_updated")]
    ConnectionStateUpdated(quic::connectivity::ConnectionStateUpdated),
    #[serde(rename = "quic:path_assigned")]
    PathAssigned(quic::connectivity::PathAssigned),
    #[serde(rename = "quic:mtu_updated")]
    MtuUpdated(quic::connectivity::MtuUpdated),
    #[serde(rename = "quic:version_information")]
    VersionInformation(quic::transport::VersionInformation),
    #[serde(rename = "quic:alpn_information")]
    ALPNInformation(quic::transport::ALPNInformation),
    #[serde(rename = "quic:parameters_set")]
    ParametersSet(quic::transport::ParametersSet),
    #[serde(rename = "quic:parameters_restored")]
    ParametersRestored(quic::transport::ParametersRestored),
    #[serde(rename = "quic:packet_sent")]
    PacketSent(quic::transport::PacketSent),
    #[serde(rename = "quic:packet_received")]
    PacketReceived(quic::transport::PacketReceived),
    #[serde(rename = "quic:packet_dropped")]
    PacketDropped(quic::transport::PacketDropped),
    #[serde(rename = "quic:packet_buffered")]
    PacketBuffered(quic::transport::PacketBuffered),
    #[serde(rename = "quic:packets_acked")]
    PacketsAcked(quic::transport::PacketsAcked),
    #[serde(rename = "quic:udp_datagrams_sent")]
    UdpDatagramSent(quic::transport::UdpDatagramsSent),
    #[serde(rename = "quic:udp_datagrams_received")]
    UdpDatagramReceived(quic::transport::UdpDatagramsReceived),
    #[serde(rename = "quic:udp_datagram_dropped")]
    UdpDatagramDropped(quic::transport::UdpDatagramDropped),
    #[serde(rename = "quic:stream_state_updated")]
    StreamStateUpdated(quic::transport::StreamStateUpdated),
    #[serde(rename = "quic:frames_processed")]
    FramesProcessed(quic::transport::FramesProcessed),
    #[serde(rename = "quic:stream_data_moved")]
    StreamDataMoved(quic::transport::StreamDataMoved),
    #[serde(rename = "quic:datagram_data_moved")]
    DatagramDataMoved(quic::transport::DatagramDataMoved),
    #[serde(rename = "quic:migration_state_updated")]
    MigrationStateUpdated(quic::transport::MigrationStateUpdated),
    #[serde(rename = "quic:key_updated")]
    KeyUpdated(quic::security::KeyUpdated),
    #[serde(rename = "quic:key_discarded")]
    KeyDiscarded(quic::security::KeyDiscarded),
    #[serde(rename = "quic:recovery_parameters_set")]
    RecoveryParametersSet(quic::recovery::RecoveryParametersSet),
    #[serde(rename = "quic:recovery_metrics_updated")]
    RecoveryMetricsUpdated(quic::recovery::RecoveryMetricsUpdated),
    #[serde(rename = "quic:congestion_state_updated")]
    CongestionStateUpdated(quic::recovery::CongestionStateUpdated),
    #[serde(rename = "quic:loss_timer_updated")]
    LossTimerUpdated(quic::recovery::LossTimerUpdated),
    #[serde(rename = "quic:packet_lost")]
    PacketLost(quic::recovery::PacketLost),
    #[serde(rename = "quic:marked_for_retransmit")]
    MarkedForRetransmit(quic::recovery::MarkedForRetransmit),
    #[serde(rename = "quic:ecn_state_updated")]
    ECNStateUpdated(quic::recovery::ECNStateUpdated),
    #[serde(rename = "loglevel:error")]
    Error(loglevel::Error),
    #[serde(rename = "loglevel:warning")]
    Warning(loglevel::Warning),
    #[serde(rename = "loglevel:info")]
    Info(loglevel::Info),
    #[serde(rename = "loglevel:debug")]
    Debug(loglevel::Debug),
    #[serde(rename = "loglevel:verbose")]
    Verbose(loglevel::Verbose),
}

pub trait BeSpecificEventData {
    fn scheme() -> &'static str;

    fn importance() -> EventImportance;
}

#[enum_dispatch::enum_dispatch]
pub trait BeEventData {
    fn scheme(&self) -> &'static str;

    fn importance(&self) -> EventImportance;
}

impl<S: BeSpecificEventData> BeEventData for S {
    #[inline]
    fn scheme(&self) -> &'static str {
        S::scheme()
    }

    #[inline]
    fn importance(&self) -> EventImportance {
        S::importance()
    }
}

macro_rules! imp_be_events {
    ( $($importance:ident $event:ty => $prefix:ident $schme:literal ;)* ) => {
        $( imp_be_events!{@impl_one $importance $event => $prefix $schme ; } )*
    };
    (@impl_one $importance:ident $event:ty => urn $schme:literal ; ) => {
        impl BeSpecificEventData for $event {
            fn scheme() -> &'static str {
                concat!["urn:ietf:params:qlog:events:",$schme]
            }

            fn importance() -> EventImportance {
                EventImportance::$importance
            }
        }
    };
}

imp_be_events! {
    Extra quic::connectivity::ServerListening        => urn "quic:server_listening";
    Base  quic::connectivity::ConnectionStarted      => urn "quic:connection_started";
    Base  quic::connectivity::ConnectionClosed       => urn "quic:connection_closed";
    Base  quic::connectivity::ConnectionIdUpdated    => urn "quic:connection_id_updated";
    Base  quic::connectivity::SpinBitUpdated         => urn "quic:spin_bit_updated";
    Base  quic::connectivity::ConnectionStateUpdated => urn "quic:connection_state_updated";
    Base  quic::connectivity::PathAssigned           => urn "quic:path_assigned";
    Extra quic::connectivity::MtuUpdated             => urn "quic:mtu_updated";
    Core  quic::transport::VersionInformation        => urn "quic:version_information";
    Core  quic::transport::ALPNInformation           => urn "quic:alpn_information";
    Core  quic::transport::ParametersSet             => urn "quic:parameters_set";
    Base  quic::transport::ParametersRestored        => urn "quic:parameters_restored";
    Core  quic::transport::PacketSent                => urn "quic:packet_sent";
    Core  quic::transport::PacketReceived            => urn "quic:packet_received";
    Base  quic::transport::PacketDropped             => urn "quic:packet_dropped";
    Base  quic::transport::PacketBuffered            => urn "quic:packet_buffered";
    Extra quic::transport::PacketsAcked              => urn "quic:packets_acked";
    Extra quic::transport::UdpDatagramsSent           => urn "quic:udp_datagrams_sent";
    Extra quic::transport::UdpDatagramsReceived       => urn "quic:udp_datagrams_received";
    Extra quic::transport::UdpDatagramDropped        => urn "quic:udp_datagram_dropped";
    Base  quic::transport::StreamStateUpdated        => urn "quic:stream_state_updated";
    Extra quic::transport::FramesProcessed           => urn "quic:frames_processed";
    Base  quic::transport::StreamDataMoved           => urn "quic:stream_data_moved";
    Base  quic::transport::DatagramDataMoved         => urn "quic:datagram_data_moved";
    Extra quic::transport::MigrationStateUpdated     => urn "quic:migration_state_updated";
    Base  quic::security::KeyUpdated                 => urn "quic:key_updated";
    Base  quic::security::KeyDiscarded               => urn "quic:key_discarded";
    Base  quic::recovery::RecoveryParametersSet      => urn "quic:recovery_parameters_set";
    Core  quic::recovery::RecoveryMetricsUpdated     => urn "quic:recovery_metrics_updated";
    Base  quic::recovery::CongestionStateUpdated     => urn "quic:congestion_state_updated";
    Extra quic::recovery::LossTimerUpdated           => urn "quic:loss_timer_updated";
    Core  quic::recovery::PacketLost                 => urn "quic:packet_lost";
    Extra quic::recovery::MarkedForRetransmit        => urn "quic:marked_for_retransmit";
    Extra quic::recovery::ECNStateUpdated            => urn "quic:ecn_state_updated";
    Core  loglevel::Error                            => urn "loglevel:error";
    Base  loglevel::Warning                          => urn "loglevel:warning";
    Extra loglevel::Info                             => urn "loglevel:info";
    Extra loglevel::Debug                            => urn "loglevel:debug";
    Extra loglevel::Verbose                          => urn "loglevel:verbose";
}

/// serialize/deserialize as hex string, but store as bytes in memory
#[serde_with::serde_as]
#[derive(Debug, Clone, From, Into, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct HexString(#[serde_as(as = "serde_with::hex::Hex")] Bytes);

impl Display for HexString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(
    default,
    setter(into, strip_option),
    build_fn(private, name = "fallible_build")
)]
pub struct RawInfo {
    /// the full byte length of the entity (e.g., packet or frame),
    /// including possible headers and trailers
    length: Option<u64>,
    /// the byte length of the entity's payload,
    /// excluding possible headers or trailers
    payload_length: Option<u64>,
    /// the (potentially truncated) contents of the full entity,
    /// including headers and possibly trailers
    #[builder(setter(custom))]
    data: Option<HexString>,
}

impl RawInfoBuilder {
    /// the (potentially truncated) contents of the full entity,
    /// including headers and possibly trailers
    pub fn data<D: Buffer>(&mut self, data: D) -> &mut Self {
        self.data = telemetry::filter::raw_data().then(|| Some(data.to_bytes().into()));
        self
    }
}

impl<D: Buffer> From<D> for RawInfo {
    fn from(data: D) -> Self {
        build!(RawInfo {
            length: data.len() as u64,
            data: data
        })
    }
}

/// ``` rust, ignore
/// crate::gen_builder_method! {
///     FooBuilder       => Foo;
///     BarBuilder       => Bar;
/// }
/// ```
#[doc(hidden)]
#[macro_export] // used in this crate only
macro_rules! gen_builder_method {
    ( $($builder:ty => $event:ty;)* ) => {
        $( $crate::gen_builder_method!{@impl_one $event => $builder ;} )*
    };
    (@impl_one $event:ty => $builder:ty ; ) => {
        impl $event {
            pub fn builder() -> $builder {
                Default::default()
            }
        }

        impl $builder {
            pub fn build(&mut self) -> $event {
                self.fallible_build().expect("Failed to build event")
            }
        }
    };
}

gen_builder_method! {
    LogFileBuilder       => LogFile;
    QlogFileBuilder      => QlogFile;
    QlogFileSeqBuilder   => QlogFileSeq;
    TraceBuilder         => Trace;
    TraceSeqBuilder      => TraceSeq;
    TraceErrorBuilder    => TraceError;
    CommonFieldsBuilder  => CommonFields;
    VantagePointBuilder  => VantagePoint;
    EventBuilder         => Event;
    ReferenceTimeBuilder => ReferenceTime;
    RawInfoBuilder       => RawInfo;
}

mod rollback {

    use super::*;
    use crate::{build, legacy};

    impl TryFrom<EventData> for legacy::EventData {
        type Error = ();
        #[rustfmt::skip]
        fn try_from(value: EventData) -> Result<Self, Self::Error> {
            match value {
                EventData::ServerListening(data) => Ok(legacy::EventData::ServerListening(data.into())),
                EventData::ConnectionStarted(data) => Ok(legacy::EventData::ConnectionStarted(data.into())),
                EventData::ConnectionClosed(data) => Ok(legacy::EventData::ConnectionClosed(data.into())),
                EventData::ConnectionIdUpdated(data) => Ok(legacy::EventData::ConnectionIdUpdated(data.into())),
                EventData::SpinBitUpdated(data) => Ok(legacy::EventData::SpinBitUpdated(data.into())),
                EventData::ConnectionStateUpdated(data) => Ok(legacy::EventData::ConnectionStateUpdated(data.into())),
                EventData::PathAssigned(_data) => Err(()),
                EventData::MtuUpdated(_data) => Err(()),
                EventData::VersionInformation(data) => Ok(legacy::EventData::VersionInformation(data.into())),
                EventData::ALPNInformation(data) => Ok(legacy::EventData::AlpnInformation(data.into())),
                EventData::ParametersSet(data) => Ok(legacy::EventData::TransportParametersSet(data.into())),
                EventData::ParametersRestored(data) => Ok(legacy::EventData::TransportParametersRestored(data.into())),
                EventData::PacketSent(data) => Ok(legacy::EventData::PacketSent(data.into())),
                EventData::PacketReceived(data) => Ok(legacy::EventData::PacketReceived(data.into())),
                EventData::PacketDropped(data) => Ok(legacy::EventData::PacketDropped(data.into())),
                EventData::PacketBuffered(data) => Ok(legacy::EventData::PacketBuffered(data.into())),
                EventData::PacketsAcked(data) => Ok(legacy::EventData::PacketsAcked(data.into())),
                EventData::UdpDatagramSent(data) => Ok(legacy::EventData::DatagramsSent(data.into())),
                EventData::UdpDatagramReceived(data) => Ok(legacy::EventData::DatagramsReceived(data.into())),
                EventData::UdpDatagramDropped(data) => Ok(legacy::EventData::DatagramDropped(data.into())),
                EventData::StreamStateUpdated(data) => Ok(legacy::EventData::StreamStateUpdated(data.into())),
                EventData::FramesProcessed(data) => Ok(legacy::EventData::FramesProcessed(data.into())),
                EventData::StreamDataMoved(data) => Ok(legacy::EventData::DataMoved(data.into())),
                EventData::DatagramDataMoved(_data) => Err(()),
                EventData::MigrationStateUpdated(_data) => Err(()),
                EventData::KeyUpdated(data) => Ok(legacy::EventData::KeyUpdated(data.into())),
                EventData::KeyDiscarded(data) => Ok(legacy::EventData::KeyDiscarded(data.into())),
                EventData::RecoveryParametersSet(data) => Ok(legacy::EventData::RecoveryParametersSet(data.into())),
                EventData::RecoveryMetricsUpdated(data) => Ok(legacy::EventData::MetricsUpdated(data.into())),
                EventData::CongestionStateUpdated(data) => Ok(legacy::EventData::CongestionStateUpdated(data.into())),
                EventData::LossTimerUpdated(data) => Ok(legacy::EventData::LossTimerUpdated(data.into())),
                EventData::PacketLost(data) => Ok(legacy::EventData::PacketLost(data.into())),
                EventData::MarkedForRetransmit(data) => Ok(legacy::EventData::MarkedForRetransmit(data.into())),
                EventData::ECNStateUpdated(_data) => Err(()),
                EventData::Error(data) => Ok(legacy::EventData::GenericError(data.into())),
                EventData::Warning(data) => Ok(legacy::EventData::GenericWarning(data.into())),
                EventData::Info(data) => Ok(legacy::EventData::GenericInfo(data.into())),
                EventData::Debug(data) => Ok(legacy::EventData::GenericDebug(data.into())),
                EventData::Verbose(data) => Ok(legacy::EventData::GenericVerbose(data.into())),
            }
        }
    }

    impl From<TimeFormat> for legacy::TimeFormat {
        fn from(value: TimeFormat) -> Self {
            match value {
                // note: depending on reference_time
                //TOOD: check reference_time here
                TimeFormat::RelativeToEpoch => legacy::TimeFormat::Absolute,
                TimeFormat::RelativeToPreviousEvent => legacy::TimeFormat::Delta,
            }
        }
    }

    impl From<ProtocolTypeList> for legacy::ProtocolType {
        fn from(value: ProtocolTypeList) -> Self {
            value
                .0
                .into_iter()
                .map(|x| x.into())
                .collect::<Vec<_>>()
                .into()
        }
    }

    impl TryFrom<Event> for legacy::Event {
        type Error = ();
        fn try_from(mut event: Event) -> Result<Self, Self::Error> {
            if let Some(system_info) = event.system_info {
                let value = serde_json::to_value(system_info).unwrap();
                event.custom_fields.insert("system_info".to_owned(), value);
            }
            if let Some(path) = event.path {
                let value = serde_json::to_value(path).unwrap();
                event.custom_fields.insert("path".to_owned(), value);
            }
            Ok(build!(legacy::Event {
                time: event.time,
                data: { legacy::EventData::try_from(event.data)? },
                ?time_format: event.time_format,
                ?protocol_type: event.protocol_types,
                ?group_id: event.group_id,
                custom_fields: event.custom_fields
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use qbase::cid::ConnectionId;

    use super::*;
    use crate::{loglevel::Warning, quic::connectivity::ConnectionStarted, telemetry::ExportEvent};

    #[test]
    fn custom_fields() {
        let odcid = ConnectionID::from(ConnectionId::from_slice(&[
            0x61, 0xb6, 0x91, 0x78, 0x80, 0xf7, 0x95, 0xee,
        ]));
        let common_fields = build!(CommonFields {
            path: "".to_owned(),
            time_format: TimeFormat::default(),
            reference_time: ReferenceTime::default(),
            protocol_types: ProtocolTypeList::from(vec![ProtocolType::quic()]),
            group_id: GroupID::from(odcid),
        });
        let expect = r#"{
  "path": "",
  "time_format": "relative_to_epoch",
  "reference_time": {
    "clock_type": "system",
    "epoch": "1970-01-01T00:00:00.000Z"
  },
  "protocol_types": [
    "QUIC"
  ],
  "group_id": "61b6917880f795ee"
}"#;
        assert_eq!(
            serde_json::to_string_pretty(&common_fields).unwrap(),
            expect
        );
        let with_custom_fields = r#"{
  "path": "",
  "time_format": "relative_to_epoch",
  "reference_time": {
    "clock_type": "system",
    "epoch": "1970-01-01T00:00:00.000Z"
  },
  "protocol_types": [
    "QUIC"
  ],
  "group_id": "61b6917880f795ee",
  "pathway": "from A to relay",
  "customB": "some other extensions"
}"#;
        let des = serde_json::from_str::<CommonFields>(with_custom_fields).unwrap();
        let filed_string = serde_json::to_string_pretty(&des).unwrap();
        let des2 = serde_json::from_str::<CommonFields>(&filed_string).unwrap();
        assert_eq!(des, des2);
    }

    #[test]
    fn event_data() {
        let data = EventData::from(build!(Warning {
            message: "deepseek（已深度思考（用时0秒））：服务器繁忙，请稍后再试。",
            code: 255u64,
        }));
        let event = build!(Event {
            time: 1.0,
            data: data.clone(),
        });
        let expect = r#"{
  "time": 1.0,
  "name": "loglevel:warning",
  "data": {
    "code": 255,
    "message": "deepseek（已深度思考（用时0秒））：服务器繁忙，请稍后再试。"
  }
}"#;
        assert_eq!(serde_json::to_string_pretty(&event).unwrap(), expect);
        assert_eq!(data.importance(), EventImportance::Base);
    }

    #[test]
    fn rollback() {
        fn group_id() -> GroupID {
            GroupID::from(ConnectionID::from(ConnectionId::from_slice(&[
                0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65, 0x43, 0x32,
            ])))
        }

        fn protocol_types() -> Vec<String> {
            vec!["QUIC".to_owned(), "UNKNOW".to_owned()]
        }

        struct TestBroker;

        impl ExportEvent for TestBroker {
            fn emit(&self, event: Event) {
                let legacy = legacy::Event::try_from(event).unwrap();
                let event = serde_json::to_value(legacy).unwrap();

                let data = serde_json::json!({
                    "ip_version": "v4",
                    "src_ip": "127.0.0.1",
                    "dst_ip": "192.168.31.1",
                    "protocol": "QUIC",
                    "src_port": 23456,
                    "dst_port": 21
                });
                // in 10: this callde protocol_types
                let protocol_type = serde_json::json!(["QUIC", "UNKNOW"]);

                assert_eq!(event["data"], data);
                assert_eq!(event["protocol_types"], serde_json::Value::Null);
                assert_eq!(event["protocol_type"], protocol_type);
                assert_eq!(event["to_router"], true);
            }
        }

        span!(
            Arc::new(TestBroker),
            group_id = group_id(),
            protocol_types = protocol_types()
        )
        .in_scope(|| {
            let src = "127.0.0.1:23456".parse().unwrap();
            let dst = "192.168.31.1:21".parse().unwrap();
            event!(ConnectionStarted { socket: (src, dst) }, to_router = true)
        })
    }
}
