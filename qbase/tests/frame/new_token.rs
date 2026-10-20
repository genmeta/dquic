use qbase::frame::{
    EncodeSize, FrameType, GetFrameType,
    io::{WriteFrame, WriteFrameType},
};

#[test]
fn test_new_token_frame() {
    let frame = qbase::frame::NewTokenFrame::new(vec![0x01, 0x02]);
    assert_eq!(frame.frame_type(), FrameType::NewToken);
    assert_eq!(frame.max_encoding_size(), 1 + 1 + 2);
    assert_eq!(frame.encoding_size(), 1 + 1 + 2);
}

#[test]
fn test_write_new_token_frame() {
    let mut buf = Vec::<u8>::new();
    let frame = qbase::frame::NewTokenFrame::from_slice(&[0x01, 0x02]);
    buf.put_frame(&frame);
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::NewToken);
    expected.extend_from_slice(&[0x02, 0x01, 0x02]);
    assert_eq!(buf, expected);
}
