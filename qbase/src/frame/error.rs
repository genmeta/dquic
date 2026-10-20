use nom::error::ErrorKind as NomErrorKind;
use thiserror::Error;

use super::FrameType;
use crate::{
    error::{ErrorKind as QuicErrorKind, QuicError},
    packet::r#type::Type,
    varint::VarInt,
};

/// Parse errors when decoding QUIC frames.
#[derive(Debug, Clone, Eq, PartialEq, Error)]
pub enum Error {
    #[error("A packet containing no frames")]
    NoFrames,
    #[error("Incomplete frame type: {0}")]
    IncompleteType(String),
    #[error("Invalid frame type from {0}")]
    InvalidType(VarInt),
    #[error("Wrong frame type {0:?}")]
    WrongType(FrameType, Type),
    #[error("Incomplete frame {0:?}: {1}")]
    IncompleteFrame(FrameType, String),
    #[error("Error occurred when parsing frame {0:?}: {1}")]
    ParseError(FrameType, String),
}

impl From<Error> for QuicError {
    fn from(e: Error) -> Self {
        match e {
            // An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION.
            Error::NoFrames => {
                Self::with_default_fty(QuicErrorKind::ProtocolViolation, e.to_string())
            }
            Error::IncompleteType(_) => {
                Self::with_default_fty(QuicErrorKind::FrameEncoding, e.to_string())
            }
            Error::InvalidType(_) => {
                Self::with_default_fty(QuicErrorKind::FrameEncoding, e.to_string())
            }
            Error::WrongType(fty, _) => {
                Self::new(QuicErrorKind::FrameEncoding, fty.into(), e.to_string())
            }
            Error::IncompleteFrame(fty, _) => {
                Self::new(QuicErrorKind::FrameEncoding, fty.into(), e.to_string())
            }
            Error::ParseError(fty, _) => {
                Self::new(QuicErrorKind::FrameEncoding, fty.into(), e.to_string())
            }
        }
    }
}

impl From<Error> for crate::error::Error {
    fn from(value: Error) -> Self {
        Self::Quic(value.into())
    }
}

impl From<nom::Err<Error>> for Error {
    fn from(error: nom::Err<Error>) -> Self {
        match error {
            nom::Err::Incomplete(_needed) => {
                unreachable!("Because the parsing of QUIC packets and frames is not stream-based.")
            }
            nom::Err::Error(err) | nom::Err::Failure(err) => err,
        }
    }
}

impl nom::error::ParseError<&[u8]> for Error {
    fn from_error_kind(_input: &[u8], _kind: NomErrorKind) -> Self {
        debug_assert_eq!(_kind, NomErrorKind::ManyTill);
        unreachable!("QUIC frame parser must always consume")
    }

    fn append(_input: &[u8], _kind: NomErrorKind, source: Self) -> Self {
        // 在解析帧时遇到了source错误，many_till期望通过ManyTill的错误类型告知
        // 这里，源错误更有意义，所以直接返回源错误
        debug_assert_eq!(_kind, NomErrorKind::ManyTill);
        source
    }
}

// TODO: conver DecodingError to quic error
