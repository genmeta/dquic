use qbase::frame::{
    EncodeSize, FrameType, GetFrameType, HandshakeDoneFrame,
    io::{WriteFrame, WriteFrameType},
};

#[test]
fn test_handshake_done_frame() {
    assert_eq!(HandshakeDoneFrame.frame_type(), FrameType::HandshakeDone);
    assert_eq!(HandshakeDoneFrame.max_encoding_size(), 1);
    assert_eq!(HandshakeDoneFrame.encoding_size(), 1);
}

#[test]
fn test_write_handshake_done_frame() {
    let mut buf = Vec::new();
    buf.put_frame(&HandshakeDoneFrame);
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::HandshakeDone);
    assert_eq!(buf, expected);
}

#[test]
fn test_read_handshake_done_frame() {
    assert_eq!(
        super::parse_frame(&[0x1e], FrameType::HandshakeDone),
        qbase::frame::Frame::HandshakeDone(HandshakeDoneFrame)
    );
}
