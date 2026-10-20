use qbase::{
    error::*,
    frame::{ConnectionCloseFrame, FrameType},
    varint::VarInt,
};

#[test]
fn test_error_kind_display() {
    assert_eq!(ErrorKind::None.to_string(), "No error");
    assert_eq!(ErrorKind::Internal.to_string(), "Implementation error");
    assert_eq!(ErrorKind::Crypto(10).to_string(), "TLS alert code: 10");
}

#[test]
fn test_error_creation() {
    let err = QuicError::new(ErrorKind::Internal, FrameType::Ping.into(), "test error");
    assert_eq!(err.kind(), ErrorKind::Internal);
    assert_eq!(err.frame_type(), FrameType::Ping.into());

    let err = QuicError::with_default_fty(ErrorKind::Application, "default frame type");
    assert_eq!(err.frame_type(), FrameType::Padding.into());
}

#[test]
fn test_error_conversion() {
    let err = Error::Quic(QuicError::new(
        ErrorKind::Internal,
        FrameType::Ping.into(),
        "test conversion",
    ));

    // Test Error to ConnectionCloseFrame
    let frame: ConnectionCloseFrame = err.clone().into();
    match frame {
        ConnectionCloseFrame::Quic(frame) => {
            assert_eq!(frame.error_kind(), err.kind());
            assert_eq!(frame.frame_type(), err.frame_type());
        }
        _ => panic!("unexpected frame type"),
    }

    // Test Error to io::Error
    let io_err: std::io::Error = err.into();
    assert_eq!(io_err.kind(), std::io::ErrorKind::BrokenPipe);
}

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
        ErrorKind::try_from(VarInt::from(0x1000u16))
            .unwrap_err()
            .to_string(),
        "Invalid error code 4096"
    );

    // Test ErrorKind to VarInt
    assert_eq!(VarInt::from(ErrorKind::None), VarInt::from(0x00u8));
    assert_eq!(VarInt::from(ErrorKind::NoViablePath), VarInt::from(0x10u8));
    assert_eq!(VarInt::from(ErrorKind::Crypto(5)), VarInt::from(0x0105u16));
}
