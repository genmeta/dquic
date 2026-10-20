use nom::error::{ErrorKind as NomErrorKind, ParseError};
use qbase::{
    error::{ErrorKind as QuicErrorKind, QuicError},
    frame::{FrameType, error::*},
    packet::r#type::{
        Type,
        long::{Type::V1, Ver1},
    },
    varint::VarInt,
};

#[test]
fn test_error_conversion_to_transport_error() {
    let cases = vec![
        (Error::NoFrames, QuicErrorKind::ProtocolViolation),
        (
            Error::IncompleteType("test".to_string()),
            QuicErrorKind::FrameEncoding,
        ),
        (
            Error::InvalidType(VarInt::from_u32(0x1f)),
            QuicErrorKind::FrameEncoding,
        ),
        (
            Error::WrongType(FrameType::Ping, Type::Long(V1(Ver1::INITIAL))),
            QuicErrorKind::FrameEncoding,
        ),
        (
            Error::IncompleteFrame(FrameType::Ping, "incomplete".to_string()),
            QuicErrorKind::FrameEncoding,
        ),
        (
            Error::ParseError(FrameType::Ping, "parse error".to_string()),
            QuicErrorKind::FrameEncoding,
        ),
    ];

    for (error, expected_kind) in cases {
        let quic_error: QuicError = error.into();
        assert_eq!(quic_error.kind(), expected_kind);
    }
}

#[test]
fn test_nom_error_conversion() {
    let error = Error::NoFrames;
    let nom_error = nom::Err::Error(error.clone());
    let converted: Error = nom_error.into();
    assert_eq!(converted, error);

    let nom_failure = nom::Err::Failure(error.clone());
    let converted: Error = nom_failure.into();
    assert_eq!(converted, error);
}

#[test]
fn test_parse_error_impl() {
    let error = Error::ParseError(FrameType::Ping, "test error".to_string());
    let appended = Error::append(&[], NomErrorKind::ManyTill, error.clone());
    assert_eq!(appended, error);
}

#[test]
#[should_panic(expected = "QUIC frame parser must always consume")]
fn test_parse_error_unreachable() {
    Error::from_error_kind(&[], NomErrorKind::ManyTill);
}

#[test]
fn test_error_display() {
    let error = Error::NoFrames;
    assert_eq!(error.to_string(), "A packet containing no frames");

    let error = Error::IncompleteType("test".to_string());
    assert_eq!(error.to_string(), "Incomplete frame type: test");

    let error = Error::InvalidType(VarInt::from_u32(0x1f));
    assert_eq!(error.to_string(), "Invalid frame type from 31");
}
