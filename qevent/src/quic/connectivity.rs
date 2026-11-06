use std::net::SocketAddr;

use derive_builder::Builder;
use derive_more::From;
use qbase::{
    error::{AppError, Error, ErrorKind, QuicError},
    frame::{AppCloseFrame, ConnectionCloseFrame, QuicCloseFrame},
};

use super::{ApplicationCode, ConnectionID, CryptoError, IPAddress, IpVersion, Owner, PathEndpointInfo, TransportError};
use crate::{Deserialize, PathID, Serialize};

/// Emitted when the server starts accepting connections. It has Extra
/// importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ServerListening {
    #[builder(default)]
    ip_v4: Option<IPAddress>,
    #[builder(default)]
    ip_v6: Option<IPAddress>,
    #[builder(default)]
    port_v4: Option<u16>,
    #[builder(default)]
    port_v6: Option<u16>,

    /// the server will always answer client initials with a retry
    /// (no 1-RTT connection setups by choice)
    #[builder(default)]
    retry_required: Option<bool>,
}

impl ServerListeningBuilder {
    pub fn address(&mut self, socket_addr: SocketAddr) -> &mut Self {
        match socket_addr {
            SocketAddr::V4(addr) => self.ip_v4(addr.ip().to_string()).port_v4(addr.port()),
            SocketAddr::V6(addr) => self.ip_v6(addr.ip().to_string()).port_v6(addr.port()),
        }
    }
}

/// The connection_started event is used for both attempting (client-
/// perspective) and accepting (server-perspective) new connections. Note
/// that while there is overlap with the connection_state_updated event,
/// this event is separate event in order to capture additional data that
/// can be useful to log. It has Base importance level; see Section 9.2
/// of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ConnectionStarted {
    ip_version: IpVersion,
    src_ip: IPAddress,
    dst_ip: IPAddress,

    // transport layer protocol
    #[builder(default = "ConnectionStarted::default_protocol()")]
    #[serde(default = "ConnectionStarted::default_protocol")]
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

impl ConnectionStartedBuilder {
    /// helper method to set the source and destination socket addresses
    pub fn socket(&mut self, (src, dst): (SocketAddr, SocketAddr)) -> &mut Self {
        debug_assert_eq!(src.is_ipv4(), dst.is_ipv4());
        self.ip_version(if src.is_ipv4() {
            IpVersion::V4
        } else {
            IpVersion::V6
        })
        .src_ip(src.ip().to_string())
        .dst_ip(dst.ip().to_string())
        .src_port(src.port())
        .dst_port(dst.port())
    }
}

impl ConnectionStarted {
    pub fn default_protocol() -> String {
        String::from("QUIC")
    }
}

/// The connection_closed event is used for logging when a connection was
/// closed, typically when an error or timeout occurred.  It has Base
/// importance level; see Section 9.2 of [QLOG-MAIN].
///
/// Note that this event has overlap with the connection_state_updated
/// event, as well as the CONNECTION_CLOSE frame.  However, in practice,
/// when analyzing large deployments, it can be useful to have a single
/// event representing a connection_closed event, which also includes an
/// additional reason field to provide more information.  Furthermore, it
/// is useful to log closures due to timeouts, which are difficult to
/// reflect using the other options.
///
/// The connection_closed event is intended to be logged either when the
/// local endpoint silently discards the connection due to an idle
/// timeout, when a CONNECTION_CLOSE frame is sent (the connection enters
/// the 'closing' state on the sender side), when a CONNECTION_CLOSE
/// frame is received (the connection enters the 'draining' state on the
/// receiver side) or when a Stateless Reset packet is received (the
/// connection is discarded at the receiver side).  Connectivity-related
/// updates after this point (e.g., exiting a 'closing' or 'draining'
/// state), should be logged using the connection_state_updated event
/// instead.
///
/// In QUIC there are two main connection-closing error categories:
/// connection and application errors.  They have well-defined error
/// codes and semantics.  Next to these however, there can be internal
/// errors that occur that may or may not get mapped to the official
/// error codes in implementation-specific ways.  As such, multiple error
/// codes can be set on the same event to reflect this.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ConnectionClosed {
    /// which side closed the connection
    owner: Option<Owner>,
    connection_code: Option<ConnectionCode>,
    application_code: Option<ApplicationCode>,
    internal_code: Option<u32>,
    reason: Option<String>,
    trigger: Option<ConnectionCloseTrigger>,
}

impl ConnectionClosedBuilder {
    pub fn ccf(&mut self, ccf: &ConnectionCloseFrame) -> &mut Self {
        match &ccf {
            ConnectionCloseFrame::Quic(frame) => self.quic_close_frame(frame),
            ConnectionCloseFrame::App(frame) => self.app_close_frame(frame),
        }
    }

    fn quic_close_frame(&mut self, frame: &QuicCloseFrame) -> &mut ConnectionClosedBuilder {
        self.connection_code(frame.error_kind()).reason(frame.reason().to_owned())
    }

    fn app_close_frame(&mut self, frame: &AppCloseFrame) -> &mut ConnectionClosedBuilder {
        self.application_code(frame.error_code() as u32).reason(frame.reason().to_owned())
    }

    pub fn quic_error(&mut self, error: &QuicError) -> &mut Self {
        self.connection_code(error.kind()).reason(error.reason().to_owned())
    }

    pub fn app_error(&mut self, error: &AppError) -> &mut Self {
        self.application_code(error.error_code() as u32).reason(error.reason().to_owned())
    }

    pub fn error(&mut self, error: &Error) {
        match error {
            Error::Quic(quic_error) => self.quic_error(quic_error),
            Error::App(app_error) => self.app_error(app_error),
        };
    }
}

#[derive(Debug, Clone, Copy, From, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ConnectionCode {
    TransportError(TransportError),
    CryptoError(CryptoError),
    Value(u32),
}

impl From<ConnectionCode> for super::ConnectionCloseErrorCode {
    fn from(value: ConnectionCode) -> Self {
        match value {
            ConnectionCode::TransportError(err) => err.into(),
            ConnectionCode::CryptoError(err) => err.into(),
            ConnectionCode::Value(code) => (code as u64).into(),
        }
    }
}

impl From<ErrorKind> for ConnectionCode {
    fn from(kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::None => TransportError::NoError.into(),
            ErrorKind::Internal => TransportError::InternalError.into(),
            ErrorKind::ConnectionRefused => TransportError::ConnectionRefused.into(),
            ErrorKind::FlowControl => TransportError::FlowControlError.into(),
            ErrorKind::StreamLimit => TransportError::StreamLimitError.into(),
            ErrorKind::StreamState => TransportError::StreamStateError.into(),
            ErrorKind::FinalSize => TransportError::FinalSizeError.into(),
            ErrorKind::FrameEncoding => TransportError::FrameEncodingError.into(),
            ErrorKind::TransportParameter => TransportError::TransportParameterError.into(),
            ErrorKind::ConnectionIdLimit => TransportError::ConnectionIdLimitError.into(),
            ErrorKind::ProtocolViolation => TransportError::ProtocolViolation.into(),
            ErrorKind::InvalidToken => TransportError::InvalidToken.into(),
            ErrorKind::Application => TransportError::ApplicationError.into(),
            ErrorKind::CryptoBufferExceeded => TransportError::CryptoBufferExceeded.into(),
            ErrorKind::KeyUpdate => TransportError::KeyUpdateError.into(),
            ErrorKind::AeadLimitReached => TransportError::AeadLimitReached.into(),
            ErrorKind::NoViablePath => TransportError::NoViablePath.into(),
            ErrorKind::Crypto(code) => CryptoError(code).into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionCloseTrigger {
    IdleTimeout,
    Application,
    Error,
    VersionMismatch,
    /// when received from peer
    StatelessReset,
    /// when it is unclear what triggered the CONNECTION_CLOSE
    Unspecified,
}

/// The connection_id_updated event is emitted when either party updates
/// their current Connection ID.  As this typically happens only
/// sparingly over the course of a connection, using this event is more
/// efficient than logging the observed CID with each and every
/// packet_sent or packet_received events.  It has Base importance level;
/// see Section 9.2 of [QLOG-MAIN].
///
/// The connection_id_updated event is viewed from the perspective of the
/// endpoint applying the new ID.  As such, when the endpoint receives a
/// new connection ID from the peer, the owner field will be "remote".
/// When the endpoint updates its own connection ID, the owner field will
/// be "local".
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ConnectionIdUpdated {
    owner: Owner,
    #[builder(default)]
    old: Option<ConnectionID>,
    #[builder(default)]
    new: Option<ConnectionID>,
}

/// The spin_bit_updated event conveys information about the QUIC latency
/// spin bit; see Section 17.4 of [QUIC-TRANSPORT].  The event is emitted
/// when the spin bit changes value, it SHOULD NOT be emitted if the spin
/// bit is set without changing its value.  It has Base importance level;
/// see Section 9.2 of [QLOG-MAIN].
///
/// [QUIC-TRANSPORT]: https://www.rfc-editor.org/rfc/rfc9000
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into), build_fn(private, name = "fallible_build"))]
pub struct SpinBitUpdated {
    state: bool,
}

/// The connection_state_updated event is used to track progress through
/// QUIC's complex handshake and connection close procedures.  It has
/// Base importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QUIC-TRANSPORT] does not contain an exhaustive flow diagram with
/// possible connection states nor their transitions (though some are
/// explicitly mentioned, like the 'closing' and 'draining' states).  As
/// such, this document *non-exhaustively* defines those states that are
/// most likely to be useful for debugging QUIC connections.
///
/// QUIC implementations SHOULD mainly log the simplified
/// BaseConnectionStates, adding the more fine-grained
/// GranularConnectionStates when more in-depth debugging is required.
/// Tools SHOULD be able to deal with both types equally.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
/// [QUIC-TRANSPORT]: https://www.rfc-editor.org/rfc/rfc9000
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct ConnectionStateUpdated {
    #[builder(default)]
    old: Option<ConnectionState>,
    new: ConnectionState,
}

#[derive(Debug, Clone, Copy, From, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ConnectionState {
    Base(BaseConnectionStates),
    Granular(GranularConnectionStates),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BaseConnectionStates {
    /// Initial packet sent/received
    Attempted,
    /// Handshake packet sent/received
    HandshakeStarted,
    /// Both sent a TLS Finished message
    /// and verified the peer's TLS Finished message
    /// 1-RTT packets can be sent
    /// RFC 9001 Section 4.1.1
    HandshakeComplete,
    /// CONNECTION_CLOSE sent/received,
    /// stateless reset received or idle timeout
    Closed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GranularConnectionStates {
    /// RFC 9000 Section 8.1
    /// client sent Handshake packet OR
    /// client used connection ID chosen by the server OR
    /// client used valid address validation token
    PeerValidated,
    /// 1-RTT data can be sent by the server,
    /// but handshake is not done yet
    /// (server has sent TLS Finished; sometimes called 0.5 RTT data)
    EarlyWrite,

    /// HANDSHAKE_DONE sent/received.
    /// RFC 9001 Section 4.1.2
    HandshakeConfirmed,
    /// CONNECTION_CLOSE sent
    Closing,
    /// CONNECTION_CLOSE received
    Draining,
    /// draining or closing period done, connection state discarded
    Closed,
}

/// This event is used to associate a single PathID's value with other
/// parameters that describe a unique network path.
///
/// As described in [QLOG-MAIN], each qlog event can be linked to a
/// single network path by means of the top-level "path" field, whose
/// value is a PathID.  However, since it can be cumbersome to encode
/// additional path metadata (such as IP addresses or Connection IDs)
/// directly into the PathID, this event allows such an association to
/// happen separately.  As such, PathIDs can be short and unique, and can
/// even be updated to be associated with new metadata as the
/// connection's state evolves.
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct PathAssigned {
    path_id: PathID,
    /// the information for traffic going towards the remote receiver
    #[builder(default)]
    path_remote: Option<PathEndpointInfo>,
    /// the information for traffic coming in at the local endpoint
    #[builder(default)]
    path_local: Option<PathEndpointInfo>,
}

/// The mtu_updated event indicates that the estimated Path MTU was
/// updated.  This happens as part of the Path MTU discovery process.  It
/// has Extra importance level; see Section 9.2 of [QLOG-MAIN].
///
/// [QLOG-MAIN]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-09
#[serde_with::skip_serializing_none]
#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct MtuUpdated {
    #[builder(default)]
    old: Option<u32>,
    new: u32,

    /// at some point, MTU discovery stops, as a "good enough"
    /// packet size has been found
    #[builder(default)]
    #[serde(default)]
    done: bool,
}

crate::gen_builder_method! {
    ServerListeningBuilder        => ServerListening;
    ConnectionStartedBuilder      => ConnectionStarted;
    ConnectionClosedBuilder       => ConnectionClosed;
    ConnectionIdUpdatedBuilder    => ConnectionIdUpdated;
    SpinBitUpdatedBuilder         => SpinBitUpdated;
    ConnectionStateUpdatedBuilder => ConnectionStateUpdated;
    PathAssignedBuilder           => PathAssigned;
    MtuUpdatedBuilder             => MtuUpdated;
}

mod rollback {
    use super::*;
    use crate::{build, legacy::quic as legacy};

    impl From<ServerListening> for legacy::ConnectivityServerListening {
        #[inline]
        fn from(value: ServerListening) -> Self {
            build!(legacy::ConnectivityServerListening {
                ?ip_v4: value.ip_v4,
                ?ip_v6: value.ip_v6,
                ?port_v4: value.port_v4,
                ?port_v6: value.port_v6,
                ?retry_required: value.retry_required,
            })
        }
    }

    impl From<ConnectionStarted> for legacy::ConnectivityConnectionStarted {
        #[inline]
        fn from(value: ConnectionStarted) -> Self {
            build!(legacy::ConnectivityConnectionStarted {
                ip_version: value.ip_version,
                src_ip: value.src_ip,
                dst_ip: value.dst_ip,
                protocol: value.protocol,
                ?src_port: value.src_port,
                ?dst_port: value.dst_port,
                ?src_cid: value.src_cid,
                ?dst_cid: value.dst_cid,
            })
        }
    }

    impl From<CryptoError> for legacy::CryptoError {
        #[inline]
        fn from(value: CryptoError) -> Self {
            legacy::CryptoError::from(value.0)
        }
    }

    impl From<ConnectionCode> for legacy::ConnectionCode {
        #[inline]
        fn from(value: ConnectionCode) -> Self {
            match value {
                ConnectionCode::TransportError(err) => legacy::TransportError::from(err).into(),
                ConnectionCode::CryptoError(err) => legacy::CryptoError::from(err).into(),
                ConnectionCode::Value(code) => code.into(),
            }
        }
    }

    // 这两类型的交集有限
    impl TryFrom<ConnectionCloseTrigger> for legacy::ConnectivityConnectionClosedTrigger {
        type Error = ();
        #[inline]
        fn try_from(value: ConnectionCloseTrigger) -> Result<Self, ()> {
            match value {
                ConnectionCloseTrigger::IdleTimeout => Ok(legacy::ConnectivityConnectionClosedTrigger::IdleTimeout),
                ConnectionCloseTrigger::Application => Ok(legacy::ConnectivityConnectionClosedTrigger::Application),
                ConnectionCloseTrigger::Error => Ok(legacy::ConnectivityConnectionClosedTrigger::Error),
                ConnectionCloseTrigger::VersionMismatch => Ok(legacy::ConnectivityConnectionClosedTrigger::VersionMismatch),
                ConnectionCloseTrigger::StatelessReset => Ok(legacy::ConnectivityConnectionClosedTrigger::StatelessReset),
                ConnectionCloseTrigger::Unspecified => Err(()),
            }
        }
    }

    impl From<ConnectionClosed> for legacy::ConnectivityConnectionClosed {
        #[inline]
        fn from(value: ConnectionClosed) -> Self {
            build!(legacy::ConnectivityConnectionClosed {
                ?owner: value.owner,
                ?connection_code: value.connection_code,
                ?application_code: value.application_code,
                ?internal_code: value.internal_code,
                ?reason: value.reason,
                ?trigger: value.trigger.and_then(|v| legacy::ConnectivityConnectionClosedTrigger::try_from(v).ok()),
            })
        }
    }

    impl From<ConnectionIdUpdated> for legacy::ConnectivityConnectionIdUpdated {
        #[inline]
        fn from(value: ConnectionIdUpdated) -> Self {
            build!(legacy::ConnectivityConnectionIdUpdated {
                owner: value.owner,
                ?old: value.old,
                ?new: value.new,
            })
        }
    }

    impl From<SpinBitUpdated> for legacy::ConnectivitySpinBitUpdated {
        #[inline]
        fn from(value: SpinBitUpdated) -> Self {
            build!(legacy::ConnectivitySpinBitUpdated { state: value.state })
        }
    }

    impl From<ConnectionState> for legacy::ConnectionState {
        #[inline]
        fn from(value: ConnectionState) -> Self {
            match value {
                ConnectionState::Base(BaseConnectionStates::Attempted) => legacy::ConnectionState::Attempted,
                ConnectionState::Base(BaseConnectionStates::HandshakeStarted) => legacy::ConnectionState::HandshakeStarted,
                ConnectionState::Base(BaseConnectionStates::HandshakeComplete) => legacy::ConnectionState::HandshakeComplete,
                ConnectionState::Base(BaseConnectionStates::Closed) => legacy::ConnectionState::Closed,
                ConnectionState::Granular(GranularConnectionStates::PeerValidated) => legacy::ConnectionState::PeerValidated,
                ConnectionState::Granular(GranularConnectionStates::EarlyWrite) => legacy::ConnectionState::EarlyWrite,
                ConnectionState::Granular(GranularConnectionStates::HandshakeConfirmed) => legacy::ConnectionState::HandshakeConfirmed,
                ConnectionState::Granular(GranularConnectionStates::Closing) => legacy::ConnectionState::Closing,
                ConnectionState::Granular(GranularConnectionStates::Draining) => legacy::ConnectionState::Draining,
                ConnectionState::Granular(GranularConnectionStates::Closed) => legacy::ConnectionState::Closed,
            }
        }
    }

    impl From<ConnectionStateUpdated> for legacy::ConnectivityConnectionStateUpdated {
        #[inline]
        fn from(value: ConnectionStateUpdated) -> Self {
            build!(legacy::ConnectivityConnectionStateUpdated {
                ?old: value.old,
                new: value.new,
            })
        }
    }

    // event not exist in legacy version
    // impl From<PathAssigned> for

    // event not exist in legacy version
    // impl From<MtuUpdated> for
}
