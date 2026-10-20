use qbase::frame::{
    EncodeSize, FrameType, GetFrameType, PingFrame,
    io::{WriteFrame, WriteFrameType},
};

#[test]
fn test_ping_frame() {
    assert_eq!(PingFrame.frame_type(), FrameType::Ping);
    assert_eq!(PingFrame.max_encoding_size(), 1);
    assert_eq!(PingFrame.encoding_size(), 1);
}

#[test]
fn test_write_ping_frame() {
    let mut buf = Vec::new();
    buf.put_frame(&PingFrame);
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::Ping);
    assert_eq!(buf, expected);
}

#[test]
fn test_read_ping_frame() {
    assert_eq!(
        super::parse_frame(&[0x01], FrameType::Ping),
        qbase::frame::Frame::Ping(PingFrame)
    );
}
