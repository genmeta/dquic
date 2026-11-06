use nom::error::ErrorKind as NomErrorKind;
use thiserror::Error;

use super::r#type::Type;

/// Parse error of QUIC packet.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum Error {
    #[error("Unsupport version {0}")]
    UnsupportedVersion(u32),
    #[error("Invalid fixed bit in long header")]
    InvalidFixedBit,
    #[error("Incomplete packet type: {0}")]
    IncompleteType(String),
    #[error("Incomplete packet header {0:?}: {1}")]
    IncompleteHeader(Type, String),
    #[error("Incomplete packet body {0:?}: {1}")]
    IncompletePacket(Type, String),
    #[error("Sampling of {0:?} packet content less than 20 bytes, only {1} bytes available")]
    UnderSampling(Type, usize),
    #[error("Fail to remove protection")]
    RemoveProtectionFailure,
    #[error("Invalid reserved bits: {0:05b} & {1:05b} must be 0")]
    InvalidReservedBits(u8, u8),
    #[error("Fail to decrypt packet")]
    DecryptPacketFailure,
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

impl From<Error> for crate::error::QuicError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidReservedBits(_, _) => {
                crate::error::QuicError::with_default_fty(crate::error::ErrorKind::ProtocolViolation, e.to_string())
            }
            _ => unreachable!(),
        }
    }
}
