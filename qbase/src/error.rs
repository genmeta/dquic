use std::{borrow::Cow, fmt::Display};

use derive_more::From;
use thiserror::Error;

use crate::{
    frame::{ConnectionCloseFrame, FrameType},
    varint::VarInt,
};

/// QUIC transport error codes and application error codes.
///
/// See [table-7](https://www.rfc-editor.org/rfc/rfc9000.html#table-7)
/// and [error codes](https://www.rfc-editor.org/rfc/rfc9000.html#name-error-codes)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ErrorKind {
    /// An endpoint uses this with CONNECTION_CLOSE to signal that
    /// the connection is being closed abruptly in the absence of any error.
    None,
    /// The endpoint encountered an internal error and cannot continue with the connection.
    Internal,
    /// The server refused to accept a new connection.
    ConnectionRefused,
    /// An endpoint received more data than it permitted in its advertised data limits.
    FlowControl,
    /// An endpoint received a frame for a stream identifier that
    /// exceeded its advertised stream limit for the corresponding stream type.
    StreamLimit,
    /// An endpoint received a frame for a stream that was not in a state that permitted that frame.
    StreamState,
    /// - An endpoint received a STREAM frame containing data that
    ///   exceeded the previously established final size,
    /// - an endpoint received a STREAM frame or a RESET_STREAM frame containing a final size
    ///   that was lower than the size of stream data that was already received, or
    /// - an endpoint received a STREAM frame or a RESET_STREAM frame containing a different
    ///   final size to the one already established.
    FinalSize,
    /// An endpoint received a frame that was badly formatted.
    FrameEncoding,
    /// An endpoint received transport parameters that were badly formatted, included:
    /// - an invalid value, omitted a mandatory transport parameter
    /// - a forbidden transport parameter
    /// - otherwise in error.
    TransportParameter,
    /// The number of connection IDs provided by the peer exceeds
    /// the advertised active_connection_id_limit.
    ConnectionIdLimit,
    /// An endpoint detected an error with protocol compliance
    /// that was not covered by more specific error codes.
    ProtocolViolation,
    /// A server received a client Initial that contained an invalid Token field.
    InvalidToken,
    /// The application or application protocol caused the connection to be closed.
    Application,
    /// An endpoint has received more data in CRYPTO frames than it can buffer.
    CryptoBufferExceeded,
    /// An endpoint detected errors in performing key updates; see
    /// [Section 6](https://www.rfc-editor.org/rfc/rfc9001#section-6)
    /// of [QUIC-TLS](https://www.rfc-editor.org/rfc/rfc9000.html#QUIC-TLS).
    KeyUpdate,
    /// An endpoint has reached the confidentiality or integrity limit
    /// for the AEAD algorithm used by the given connection.
    AeadLimitReached,
    /// An endpoint has determined that the network path is incapable of supporting QUIC.
    /// An endpoint is unlikely to receive a CONNECTION_CLOSE frame carrying this code
    /// except when the path does not support a large enough MTU.
    NoViablePath,
    /// The cryptographic handshake failed.
    /// A range of 256 values is reserved for carrying error codes specific
    /// to the cryptographic handshake that is used.
    /// Codes for errors occurring when TLS is used for the cryptographic handshake are described
    /// in [Section 4.8](https://www.rfc-editor.org/rfc/rfc9001#section-4.8)
    /// of [QUIC-TLS](https://www.rfc-editor.org/rfc/rfc9000.html#QUIC-TLS).
    Crypto(u8),
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            ErrorKind::None => "No error",
            ErrorKind::Internal => "Implementation error",
            ErrorKind::ConnectionRefused => "Server refuses a connection",
            ErrorKind::FlowControl => "Flow control error",
            ErrorKind::StreamLimit => "Too many streams opened",
            ErrorKind::StreamState => "Frame received in invalid stream state",
            ErrorKind::FinalSize => "Change to final size",
            ErrorKind::FrameEncoding => "Frame encoding error",
            ErrorKind::TransportParameter => "Error in transport parameters",
            ErrorKind::ConnectionIdLimit => "Too many connection IDs received",
            ErrorKind::ProtocolViolation => "Generic protocol violation",
            ErrorKind::InvalidToken => "Invalid Token received",
            ErrorKind::Application => "Application error",
            ErrorKind::CryptoBufferExceeded => "CRYPTO data buffer overflowed",
            ErrorKind::KeyUpdate => "Invalid packet protection update",
            ErrorKind::AeadLimitReached => "Excessive use of packet protection keys",
            ErrorKind::NoViablePath => "No viable network path exists",
            ErrorKind::Crypto(x) => return write!(f, "TLS alert code: {x}"),
        };
        write!(f, "{description}",)
    }
}

/// Invalid error code while parsing.
/// The parsed [`VarInt`] error code exceeds the normal range of error codes.
///
/// See [Initial QUIC Transport Error Codes Registry Entries](https://www.rfc-editor.org/rfc/rfc9000.html#table-7)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Error)]
#[error("Invalid error code {0}")]
pub struct InvalidErrorKind(u64);

impl TryFrom<VarInt> for ErrorKind {
    type Error = InvalidErrorKind;

    fn try_from(value: VarInt) -> Result<Self, Self::Error> {
        Ok(match value.into_u64() {
            0x00 => ErrorKind::None,
            0x01 => ErrorKind::Internal,
            0x02 => ErrorKind::ConnectionRefused,
            0x03 => ErrorKind::FlowControl,
            0x04 => ErrorKind::StreamLimit,
            0x05 => ErrorKind::StreamState,
            0x06 => ErrorKind::FinalSize,
            0x07 => ErrorKind::FrameEncoding,
            0x08 => ErrorKind::TransportParameter,
            0x09 => ErrorKind::ConnectionIdLimit,
            0x0a => ErrorKind::ProtocolViolation,
            0x0b => ErrorKind::InvalidToken,
            0x0c => ErrorKind::Application,
            0x0d => ErrorKind::CryptoBufferExceeded,
            0x0e => ErrorKind::KeyUpdate,
            0x0f => ErrorKind::AeadLimitReached,
            0x10 => ErrorKind::NoViablePath,
            0x0100..=0x01ff => ErrorKind::Crypto((value.into_u64() & 0xff) as u8),
            other => return Err(InvalidErrorKind(other)),
        })
    }
}

impl From<ErrorKind> for VarInt {
    fn from(value: ErrorKind) -> Self {
        match value {
            ErrorKind::None => VarInt::from(0x00u8),
            ErrorKind::Internal => VarInt::from(0x01u8),
            ErrorKind::ConnectionRefused => VarInt::from(0x02u8),
            ErrorKind::FlowControl => VarInt::from(0x03u8),
            ErrorKind::StreamLimit => VarInt::from(0x04u8),
            ErrorKind::StreamState => VarInt::from(0x05u8),
            ErrorKind::FinalSize => VarInt::from(0x06u8),
            ErrorKind::FrameEncoding => VarInt::from(0x07u8),
            ErrorKind::TransportParameter => VarInt::from(0x08u8),
            ErrorKind::ConnectionIdLimit => VarInt::from(0x09u8),
            ErrorKind::ProtocolViolation => VarInt::from(0x0au8),
            ErrorKind::InvalidToken => VarInt::from(0x0bu8),
            ErrorKind::Application => VarInt::from(0x0cu8),
            ErrorKind::CryptoBufferExceeded => VarInt::from(0x0du8),
            ErrorKind::KeyUpdate => VarInt::from(0x0eu8),
            ErrorKind::AeadLimitReached => VarInt::from(0x0fu8),
            ErrorKind::NoViablePath => VarInt::from(0x10u8),
            ErrorKind::Crypto(x) => VarInt::from(0x0100u16 | x as u16),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum ErrorFrameType {
    V1(FrameType),
    Ext(VarInt),
}

/// QUIC transport error.
///
/// Its definition conforms to the usage of [`ConnectionCloseFrame`].
/// A value of 0 (equivalent to the mention of the PADDING frame) is used when the frame type is unknown.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind} in {frame_type:?}, reason: {reason}")]
pub struct QuicError {
    kind: ErrorKind,
    frame_type: ErrorFrameType,
    reason: Cow<'static, str>,
}

impl QuicError {
    /// Create a new error with the given kind, frame type, and reason.
    /// The frame type is the one that triggered this error.
    pub fn new<T: Into<Cow<'static, str>>>(
        kind: ErrorKind,
        frame_type: ErrorFrameType,
        reason: T,
    ) -> Self {
        Self {
            kind,
            frame_type,
            reason: reason.into(),
        }
    }

    /// Create a new error with unknown frame type, and
    /// the [`FrameType::Padding`] type will be used by default.
    pub fn with_default_fty<T: Into<Cow<'static, str>>>(kind: ErrorKind, reason: T) -> Self {
        Self {
            kind,
            frame_type: FrameType::Padding.into(),
            reason: reason.into(),
        }
    }

    /// Return the error kind.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Return the frame type that triggered this error.
    pub fn frame_type(&self) -> ErrorFrameType {
        self.frame_type
    }

    /// Return the reason of this error.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl From<FrameType> for ErrorFrameType {
    fn from(value: FrameType) -> Self {
        Self::V1(value)
    }
}

impl From<ErrorFrameType> for VarInt {
    fn from(val: ErrorFrameType) -> Self {
        match val {
            ErrorFrameType::V1(frame) => frame.into(),
            ErrorFrameType::Ext(value) => value,
        }
    }
}

/// App specific error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("App layer error occur with error code {error_code}, reason: {reason}")]
pub struct AppError {
    error_code: VarInt,
    reason: Cow<'static, str>,
}

impl AppError {
    /// Create a new app error with the given app error code and reason.
    pub fn new(error_code: VarInt, reason: impl Into<Cow<'static, str>>) -> Self {
        Self {
            error_code,
            reason: reason.into(),
        }
    }

    /// Return the error code.
    ///
    /// The error code is an application error code.
    pub fn error_code(&self) -> u64 {
        self.error_code.into_u64()
    }

    /// Return the reason of this error.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error, From)]
pub enum Error {
    #[error(transparent)]
    Quic(QuicError),
    #[error(transparent)]
    App(AppError),
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        match self {
            Error::Quic(e) => e.kind(),
            Error::App(_) => ErrorKind::Application,
        }
    }

    pub fn frame_type(&self) -> ErrorFrameType {
        match self {
            Error::Quic(e) => e.frame_type(),
            Error::App(_) => FrameType::Padding.into(),
        }
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        Self::new(std::io::ErrorKind::BrokenPipe, e)
    }
}

impl From<Error> for ConnectionCloseFrame {
    fn from(e: Error) -> Self {
        match e {
            Error::Quic(e) => Self::new_quic(e.kind, e.frame_type, e.reason),
            Error::App(app_error) => Self::new_app(app_error.error_code, app_error.reason),
        }
    }
}

impl From<AppError> for ConnectionCloseFrame {
    fn from(e: AppError) -> Self {
        Self::new_app(e.error_code, e.reason)
    }
}

impl From<ConnectionCloseFrame> for Error {
    fn from(frame: ConnectionCloseFrame) -> Self {
        match frame {
            ConnectionCloseFrame::Quic(frame) => Self::Quic(QuicError {
                kind: frame.error_kind(),
                frame_type: frame.frame_type(),
                reason: frame.reason().to_owned().into(),
            }),
            ConnectionCloseFrame::App(frame) => Self::App(AppError {
                error_code: VarInt::from_u64(frame.error_code())
                    .expect("error code never overflow"),
                reason: frame.reason().to_owned().into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_kind_conversion() {
        // Test VarInt to ErrorKind
        assert_eq!(
            ErrorKind::try_from(VarInt::from(0x00u8)).unwrap(),
            ErrorKind::None
        );
        assert_eq!(
            ErrorKind::try_from(VarInt::from(0x10u8)).unwrap(),
            ErrorKind::NoViablePath
        );
        assert_eq!(
            ErrorKind::try_from(VarInt::from(0x0100u16)).unwrap(),
            ErrorKind::Crypto(0)
        );

        // Test invalid error code
        assert_eq!(
            ErrorKind::try_from(VarInt::from(0x1000u16)).unwrap_err(),
            InvalidErrorKind(0x1000)
        );

        // Test ErrorKind to VarInt
        assert_eq!(VarInt::from(ErrorKind::None), VarInt::from(0x00u8));
        assert_eq!(VarInt::from(ErrorKind::NoViablePath), VarInt::from(0x10u8));
        assert_eq!(VarInt::from(ErrorKind::Crypto(5)), VarInt::from(0x0105u16));
    }
}
