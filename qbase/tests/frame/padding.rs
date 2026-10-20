use qbase::frame::{
    EncodeSize, FrameType, GetFrameType, PaddingFrame,
    io::{WriteFrame, WriteFrameType},
};

#[test]
fn test_padding_frame() {
    assert_eq!(PaddingFrame.frame_type(), FrameType::Padding);
    assert_eq!(PaddingFrame.max_encoding_size(), 1);
    assert_eq!(PaddingFrame.encoding_size(), 1);
}

#[test]
fn test_write_padding_frame() {
    let mut buf = Vec::new();
    buf.put_frame(&PaddingFrame);
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::Padding);
    assert_eq!(buf, expected);
}
