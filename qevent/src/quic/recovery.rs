use std::collections::HashMap;

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use super::{PacketHeader, PacketNumberSpace, QuicFrame};

/// The recovery_parameters_set event groups initial parameters from both
/// loss detection and congestion control into a single event.  It has
/// Base importance level; see Section 9.2 of [QLOG-MAIN].
///
/// All these settings are typically set once and never change.
/// Implementation that do, for some reason, change these parameters
/// during execution, MAY emit the recovery_parameters_set event more
/// than once
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct RecoveryParametersSet {
    /// Loss detection, see RFC 9002 Appendix A.2
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

    /// congestion control, see RFC 9002 Appendix B.2
    /// in bytes. Note that this could be updated after pmtud
    #[builder(default)]
    max_datagram_size: Option<u32>,

    /// in bytes
    #[builder(default)]
    initial_congestion_window: Option<u64>,

    /// Note that this could change when max_datagram_size changes
    /// in bytes
    #[builder(default)]
    minimum_congestion_window: Option<u64>,
    loss_reduction_factor: Option<f32>,

    /// as PTO multiplier
    #[builder(default)]
    persistent_congestion_threshold: Option<u16>,

    /// Additionally, this event can contain any number of unspecified fields
    /// to support different recovery approaches.
    #[builder(default)]
    #[serde(flatten)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    custom_fields: HashMap<String, serde_json::Value>,
}

/// The recovery_metrics_updated event is emitted when one or more of the
/// observable recovery metrics changes value.  It has Core importance
/// level; see Section 9.2 of [QLOG-MAIN].
///
/// This event SHOULD group all possible metric updates that happen at or
/// around the same time in a single event (e.g., if min_rtt and
/// smoothed_rtt change at the same time, they should be bundled in a
/// single recovery_metrics_updated entry, rather than split out into
/// two).  Consequently, a recovery_metrics_updated event is only
/// guaranteed to contain at least one of the listed metrics.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct RecoveryMetricsUpdated {
    /// Loss detection, see RFC 9002 Appendix A.3
    /// all following rtt fields are expressed in ms
    smoothed_rtt: Option<f32>,
    min_rtt: Option<f32>,
    latest_rtt: Option<f32>,
    rtt_variance: Option<f32>,
    pto_count: Option<u16>,

    /// Congestion control, see RFC 9002 Appendix B.2.
    /// in bytes
    congestion_window: Option<u64>,
    bytes_in_flight: Option<u64>,

    /// in bytes
    ssthresh: Option<u64>,

    /// qlog defined
    /// sum of all packet number spaces
    packets_in_flight: Option<u64>,
    /// in bits per second
    pacing_rate: Option<u64>,

    /// Additionally, the recovery_metrics_updated event can contain any
    /// number of unspecified fields to support different recovery
    /// approaches.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    custom_fields: HashMap<String, serde_json::Value>,
}

/// The congestion_state_updated event indicates when the congestion
/// controller enters a significant new state and changes its behaviour.
/// It has Base importance level; see Section 9.2 of [QLOG-MAIN].
///
/// The values of the event's fields are intentionally unspecified here
/// in order to support different Congestion Control algorithms, as these
/// typically have different states and even different implementations of
/// these states across stacks.  For example, for the algorithm defined
/// in the QUIC Recovery RFC ("enhanced" New Reno), the following states
/// are used: Slow Start, Congestion Avoidance, Application Limited and
/// Recovery.  Similarly, states can be triggered by a variety of events,
/// including detection of Persistent Congestion or receipt of ECN
/// markings.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct CongestionStateUpdated {
    #[builder(default)]
    old: Option<String>,
    new: String,
    #[builder(default)]
    trigger: Option<String>,
}

/// The loss_timer_updated event is emitted when a recovery loss timer
/// changes state.  It has Extra importance level; see Section 9.2 of
/// [QLOG-MAIN].
///
/// The three main event types are:
///
/// *  set: the timer is set with a delta timeout for when it will
/// trigger next
///
/// *  expired: when the timer effectively expires after the delta
/// timeout
///
/// *  cancelled: when a timer is cancelled (e.g., all outstanding
/// packets are acknowledged, start idle period)
///  
/// In order to indicate an active timer's timeout update, a new set
/// event is used.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct LossTimerUpdated {
    /// called "mode" in RFC 9002 A.9.
    #[builder(default)]
    timer_type: Option<TimerType>,
    #[builder(default)]
    packet_number_space: Option<PacketNumberSpace>,
    event_type: EventType,

    /// if event_type === "set": delta time is in ms from
    /// this event's timestamp until when the timer will trigger
    #[builder(default)]
    delta: Option<f32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimerType {
    Ack,
    Pto,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Set,
    Expired,
    Cancelled,
}

/// The packet_lost event is emitted when a packet is deemed lost by loss
/// detection.  It has Core importance level; see Section 9.2 of
/// [QLOG-MAIN].
///
/// It is RECOMMENDED to populate the optional trigger field in order to
/// help disambiguate among the various possible causes of a loss
/// declaration.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct PacketLost {
    /// should include at least the packet_type and packet_number
    header: Option<PacketHeader>,

    /// not all implementations will keep track of full
    /// packets, so these are optional
    frames: Option<Vec<QuicFrame>>,
    is_mtu_probe_packet: bool,
    trigger: Option<PacketLostTrigger>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PacketLostTrigger {
    ReorderingThreshold,
    TimeThreshold,
    /// RFC 9002 Section 6.2.4 paragraph 6, MAY
    PtoExpired,
}

/// The marked_for_retransmit event indicates which data was marked for
/// retransmission upon detection of packet loss (see packet_lost).  It
/// has Extra importance level; see Section 9.2 of [QLOG-MAIN].
///
/// Similar to the reasoning for the frames_processed event, in order to
/// keep the amount of different events low, this signal is grouped into
/// in a single event based on existing QUIC frame definitions for all
/// types of retransmittable data.
///
/// Implementations retransmitting full packets or frames directly can
/// just log the constituent frames of the lost packet here (or do away
/// with this event and use the contents of the packet_lost event
/// instead).  Conversely, implementations that have more complex logic
/// (e.g., marking ranges in a stream's data buffer as in-flight), or
/// that do not track sent frames in full (e.g., only stream offset +
/// length), can translate their internal behaviour into the appropriate
/// frame instance here even if that frame was never or will never be put
/// on the wire.
///
/// Much of this data can be inferred if implementations log packet_sent
/// events (e.g., looking at overlapping stream data offsets and length,
/// one can determine when data was retransmitted).
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into), build_fn(private, name = "fallible_build"))]
pub struct MarkedForRetransmit {
    frames: Vec<QuicFrame>,
}

/// The ecn_state_updated event indicates a progression in the ECN state
/// machine as described in section A.4 of [QUIC-TRANSPORT].  It has
/// Extra importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ECNStateUpdated {
    #[builder(default)]
    old: Option<ECNState>,
    new: ECNState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ECNState {
    /// ECN testing in progress
    Testing,
    /// ECN state unknown, waiting for acknowledgements
    /// for testing packets
    Unknown,
    /// ECN testing failed
    Failed,
    /// testing was successful, the endpoint now
    /// sends packets with ECT(0) marking
    Capable,
}

crate::gen_builder_method! {
    RecoveryParametersSetBuilder  => RecoveryParametersSet;
    RecoveryMetricsUpdatedBuilder => RecoveryMetricsUpdated;
    CongestionStateUpdatedBuilder => CongestionStateUpdated;
    LossTimerUpdatedBuilder       => LossTimerUpdated;
    PacketLostBuilder             => PacketLost;
    MarkedForRetransmitBuilder    => MarkedForRetransmit;
    ECNStateUpdatedBuilder        => ECNStateUpdated;
}

mod rollback {

    use super::*;
    use crate::{build, legacy::quic as legacy};

    impl From<RecoveryParametersSet> for legacy::RecoveryParametersSet {
        fn from(value: RecoveryParametersSet) -> Self {
            build!(legacy::RecoveryParametersSet {
                ?reordering_threshold: value.reordering_threshold,
                ?time_threshold: value.time_threshold,
                timer_granularity: value.timer_granularity,
                ?initial_rtt: value.initial_rtt,
                ?max_datagram_size: value.max_datagram_size,
                ?initial_congestion_window: value.initial_congestion_window,
                ?minimum_congestion_window: value.minimum_congestion_window.map(|v| v as u32),
                ?loss_reduction_factor: value.loss_reduction_factor,
                ?persistent_congestion_threshold: value.persistent_congestion_threshold,
                custom_fields: value.custom_fields,
            })
        }
    }

    impl From<RecoveryMetricsUpdated> for legacy::RecoveryMetricsUpdated {
        fn from(value: RecoveryMetricsUpdated) -> Self {
            build!(legacy::RecoveryMetricsUpdated {
                ?smoothed_rtt: value.smoothed_rtt,
                ?min_rtt: value.min_rtt,
                ?latest_rtt: value.latest_rtt,
                ?rtt_variance: value.rtt_variance,
                ?pto_count: value.pto_count,
                ?congestion_window: value.congestion_window,
                ?bytes_in_flight: value.bytes_in_flight,
                ?ssthresh: value.ssthresh,
                ?packets_in_flight: value.packets_in_flight,
                ?pacing_rate: value.pacing_rate,
                custom_fields: value.custom_fields,
            })
        }
    }

    impl From<CongestionStateUpdated> for legacy::RecoveryCongestionStateUpdated {
        fn from(value: CongestionStateUpdated) -> Self {
            build!(legacy::RecoveryCongestionStateUpdated {
                ?old: value.old,
                new: value.new,
                ?trigger: match value.trigger {
                    Some(s) if s == "persistent_congestion" => Some(legacy::RecoveryCongestionStateUpdatedTrigger::PersistentCongestion),
                    Some(s) if s == "ecn" => Some(legacy::RecoveryCongestionStateUpdatedTrigger::Ecn),
                    _ => None,
                },
            })
        }
    }

    impl From<TimerType> for legacy::LossTimerType {
        #[inline]
        fn from(value: TimerType) -> Self {
            match value {
                TimerType::Ack => legacy::LossTimerType::Ack,
                TimerType::Pto => legacy::LossTimerType::Pto,
            }
        }
    }

    impl From<EventType> for legacy::LossTimerEventType {
        #[inline]
        fn from(value: EventType) -> Self {
            match value {
                EventType::Set => legacy::LossTimerEventType::Set,
                EventType::Expired => legacy::LossTimerEventType::Expired,
                EventType::Cancelled => legacy::LossTimerEventType::Cancelled,
            }
        }
    }

    impl From<LossTimerUpdated> for legacy::RecoveryLossTimerUpdated {
        fn from(value: LossTimerUpdated) -> Self {
            build!(legacy::RecoveryLossTimerUpdated {
                ?timer_type: value.timer_type,
                ?packet_number_space: value.packet_number_space,
                event_type: value.event_type,
                ?delta: value.delta,
            })
        }
    }

    impl From<PacketLostTrigger> for legacy::RecoveryPacketLostTrigger {
        #[inline]
        fn from(value: PacketLostTrigger) -> Self {
            match value {
                PacketLostTrigger::ReorderingThreshold => legacy::RecoveryPacketLostTrigger::ReorderingThreshold,
                PacketLostTrigger::TimeThreshold => legacy::RecoveryPacketLostTrigger::TimeThreshold,
                PacketLostTrigger::PtoExpired => legacy::RecoveryPacketLostTrigger::PtoExpired,
            }
        }
    }

    impl From<PacketLost> for legacy::RecoveryPacketLost {
        fn from(value: PacketLost) -> Self {
            build!(legacy::RecoveryPacketLost {
                ?header: value.header,
                ?frames: value.frames.map(|v| v.into_iter().map(Into::into).collect::<Vec<_>>()),
                ?trigger: value.trigger,
            })
        }
    }

    impl From<MarkedForRetransmit> for legacy::RecoveryMarkedForRetransmit {
        fn from(value: MarkedForRetransmit) -> Self {
            build!(legacy::RecoveryMarkedForRetransmit { frames: value.frames.into_iter().map(Into::into).collect::<Vec<_>>() })
        }
    }
}
