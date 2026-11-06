pub mod exporter;
pub mod quic;

use std::collections::HashMap;

use derive_builder::Builder;
use derive_more::{From, Into};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{GroupID, VantagePoint};

pub const QLOG_VERSION: &str = "0.3";

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct QlogFile {
    qlog_version: String,
    #[builder(default = "QlogFileSeq::default_format()")]
    #[serde(default = "QlogFileSeq::default_format")]
    qlog_format: String,
    title: Option<String>,
    description: Option<String>,
    #[builder(default)]
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    summary: HashMap<String, Value>,
    #[builder(default)]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    traces: Vec<Traces>,
}

impl QlogFile {
    pub fn default_format() -> String {
        "JSON".to_string()
    }
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct QlogFileSeq {
    #[builder(default = "QlogFileSeq::default_qlog_version()")]
    #[serde(default = "QlogFileSeq::default_qlog_version")]
    qlog_version: String,
    #[builder(default = "QlogFileSeq::default_format()")]
    #[serde(default = "QlogFileSeq::default_format")]
    qlog_format: String,
    #[builder(default)]
    title: Option<String>,
    #[builder(default)]
    description: Option<String>,
    #[builder(default)]
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    summary: HashMap<String, Value>,
    trace: TraceSeq,
}

impl QlogFileSeq {
    pub fn default_qlog_version() -> String {
        QLOG_VERSION.to_string()
    }

    pub fn default_format() -> String {
        "JSON-SEQ".to_string()
    }
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, From, Into, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Summary {
    #[builder(default)]
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    custom_fields: HashMap<String, Value>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Traces {
    TraceError(TraceError),
    Trace(Trace),
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TraceError {
    error_description: String,
    /// the original URI at which we attempted to find the file
    uri: Option<String>,
    vantage_point: Option<VantagePoint>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Trace {
    title: Option<String>,
    description: Option<String>,
    configuration: Option<Configuration>,
    common_fields: Option<CommonFields>,
    vantage_point: Option<VantagePoint>,
    events: Vec<Event>,
}

#[serde_with::skip_serializing_none]
#[derive(Default, Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct TraceSeq {
    title: Option<String>,
    description: Option<String>,
    configuration: Option<Configuration>,
    common_fields: Option<CommonFields>,
    vantage_point: Option<VantagePoint>,
}

#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Configuration {
    /// time_offset is in milliseconds
    time_offset: f64,
    original_uris: Vec<String>,
    #[builder(default)]
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    custom_fields: HashMap<String, Value>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Event {
    time: f64,
    #[serde(flatten)]
    data: EventData,

    #[builder(default)]
    time_format: Option<TimeFormat>,

    #[builder(default)]
    protocol_type: Option<ProtocolType>,
    #[builder(default)]
    group_id: Option<GroupID>,

    /// events can contain any amount of custom fields
    #[builder(default)]
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    custom_fields: HashMap<String, Value>,
}

#[derive(Debug, Clone, Copy, From, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimeFormat {
    Relative,
    Delta,
    Absolute,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "name", content = "data")]
#[serde(rename_all = "snake_case")]
pub enum EventData {
    // Connectivity
    #[serde(rename = "connectivity:server_listening")]
    ServerListening(quic::ConnectivityServerListening),

    #[serde(rename = "connectivity:connection_started")]
    ConnectionStarted(quic::ConnectivityConnectionStarted),

    #[serde(rename = "connectivity:connection_closed")]
    ConnectionClosed(quic::ConnectivityConnectionClosed),

    #[serde(rename = "connectivity:connection_id_updated")]
    ConnectionIdUpdated(quic::ConnectivityConnectionIdUpdated),

    #[serde(rename = "connectivity:spin_bit_updated")]
    SpinBitUpdated(quic::ConnectivitySpinBitUpdated),

    #[serde(rename = "connectivity:connection_state_updated")]
    ConnectionStateUpdated(quic::ConnectivityConnectionStateUpdated),

    // Security
    #[serde(rename = "security:key_updated")]
    KeyUpdated(quic::SecurityKeyUpdated),

    #[serde(rename = "security:key_retired")]
    KeyDiscarded(quic::SecurityKeyRetired),

    // Transport
    #[serde(rename = "transport:version_information")]
    VersionInformation(quic::TransportVersionInformation),

    #[serde(rename = "transport:alpn_information")]
    AlpnInformation(quic::TransportALPNInformation),

    #[serde(rename = "transport:parameters_set")]
    TransportParametersSet(quic::TransportParametersSet),

    #[serde(rename = "transport:parameters_restored")]
    TransportParametersRestored(quic::TransportParametersRestored),

    #[serde(rename = "transport:datagrams_received")]
    DatagramsReceived(quic::TransportDatagramsReceived),

    #[serde(rename = "transport:datagrams_sent")]
    DatagramsSent(quic::TransportDatagramsSent),

    #[serde(rename = "transport:datagram_dropped")]
    DatagramDropped(quic::TransportDatagramDropped),

    #[serde(rename = "transport:packet_received")]
    PacketReceived(quic::TransportPacketReceived),

    #[serde(rename = "transport:packet_sent")]
    PacketSent(quic::TransportPacketSent),

    #[serde(rename = "transport:packet_dropped")]
    PacketDropped(quic::TransportPacketDropped),

    #[serde(rename = "transport:packet_buffered")]
    PacketBuffered(quic::TransportPacketBuffered),

    #[serde(rename = "transport:packets_acked")]
    PacketsAcked(quic::TransportPacketsAcked),

    #[serde(rename = "transport:stream_state_updated")]
    StreamStateUpdated(quic::TransportStreamStateUpdated),

    #[serde(rename = "transport:frames_processed")]
    FramesProcessed(quic::TransportFramesProcessed),

    #[serde(rename = "transport:data_moved")]
    DataMoved(quic::TransportDataMoved),

    // Recovery
    #[serde(rename = "recovery:parameters_set")]
    RecoveryParametersSet(quic::RecoveryParametersSet),

    #[serde(rename = "recovery:metrics_updated")]
    MetricsUpdated(quic::RecoveryMetricsUpdated),

    #[serde(rename = "recovery:congestion_state_updated")]
    CongestionStateUpdated(quic::RecoveryCongestionStateUpdated),

    #[serde(rename = "recovery:loss_timer_updated")]
    LossTimerUpdated(quic::RecoveryLossTimerUpdated),

    #[serde(rename = "recovery:packet_lost")]
    PacketLost(quic::RecoveryPacketLost),

    #[serde(rename = "recovery:marked_for_retransmit")]
    MarkedForRetransmit(quic::RecoveryMarkedForRetransmit),

    #[serde(rename = "generic:error")]
    GenericError(GenericError),

    #[serde(rename = "generic:warning")]
    GenericWarning(GenericWarning),

    #[serde(rename = "generic:info")]
    GenericInfo(GenericInfo),

    #[serde(rename = "generic:debug")]
    GenericDebug(GenericDebug),

    #[serde(rename = "generic:verbose")]
    GenericVerbose(GenericVerbose),

    #[serde(rename = "simulation:scenario")]
    SimulationScenario(SimulationScenario),

    #[serde(rename = "simulation:marker")]
    SimulationMarker(SimulationMarker),
}

#[derive(Default, Debug, Clone, From, Into, Serialize, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct ProtocolType(Vec<String>);

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct CommonFields {
    time_format: Option<TimeFormat>,
    reference_time: Option<f64>,

    protocol_type: Option<ProtocolType>,
    group_id: Option<GroupID>,

    custom_fields: HashMap<String, Value>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct GenericError {
    code: Option<u64>,
    message: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct GenericWarning {
    code: Option<u64>,
    message: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct GenericInfo {
    message: String,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct GenericDebug {
    message: String,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct GenericVerbose {
    message: String,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct SimulationScenario {
    name: Option<String>,
    #[builder(default)]
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    details: HashMap<String, Value>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct SimulationMarker {
    r#type: Option<String>,
    message: Option<String>,
}

crate::gen_builder_method! {
    QlogFileBuilder => QlogFile;
    QlogFileSeqBuilder => QlogFileSeq;
    SummaryBuilder => Summary;
    TraceErrorBuilder => TraceError;
    TraceBuilder => Trace;
    TraceSeqBuilder => TraceSeq;
    ConfigurationBuilder => Configuration;
    EventBuilder => Event;
    GenericErrorBuilder => GenericError;
    GenericWarningBuilder => GenericWarning;
    GenericInfoBuilder => GenericInfo;
    GenericDebugBuilder => GenericDebug;
    GenericVerboseBuilder => GenericVerbose;
    SimulationScenarioBuilder => SimulationScenario;
    SimulationMarkerBuilder => SimulationMarker;
}
