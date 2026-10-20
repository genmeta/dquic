use qbase::{
    error::*,
    frame::{ConnectionCloseFrame, FrameType},
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
