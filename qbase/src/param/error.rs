use std::ops::RangeInclusive;

use nom::error::ErrorKind as NomErrorKind;
use thiserror::Error;

use crate::{
    error::{ErrorKind as QuicErrorKind, QuicError},
    frame::FrameType,
    param::{ParameterId, ParameterValueType},
    role::Role,
    varint::VarInt,
};

/// Error for QUIC parameters.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum Error {
    #[error("Incomplete parameter id: {0}")]
    IncompleteParameterId(String),
    #[error("Parameter {0} is not defined")]
    UnknownParameterId(VarInt),
    #[error("Duplicate transport parameter {0}")]
    DuplicateParameter(VarInt),
    #[error("Lack {1:?} for {0}")]
    LackParameterId(Role, ParameterId),
    #[error("{0:?} is not belong to {1}")]
    InvalidParameterId(ParameterId, Role),
    #[error("Incomplete value for {0:?}: {1}")]
    IncompleteValue(ParameterId, String),
    #[error("{0:?} is not supported for {1:?}")]
    InvalidValueType(ParameterId, ParameterValueType),
    #[error("{0:?}'s value {1} is out of bounds {2:?}")]
    OutOfBounds(ParameterId, u64, RangeInclusive<u64>),
}

impl From<Error> for QuicError {
    fn from(e: Error) -> Self {
        Self::new(
            QuicErrorKind::TransportParameter,
            FrameType::Crypto.into(),
            e.to_string(),
        )
    }
}

impl nom::error::ParseError<&[u8]> for Error {
    fn from_error_kind(_input: &[u8], _kind: NomErrorKind) -> Self {
        unreachable!("QUIC parameter parser must always consume")
    }

    fn append(_input: &[u8], _kind: NomErrorKind, source: Self) -> Self {
        source
    }
}
