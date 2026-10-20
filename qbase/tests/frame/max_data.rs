use qbase::{
    frame::{
        EncodeSize, FrameType, GetFrameType, MaxDataFrame,
        io::{WriteFrame, WriteFrameType},
    },
    varint::VarInt,
};

#[test]
fn test_max_data_frame() {
    let frame = MaxDataFrame::new(VarInt::from_u32(0x1234));
    assert_eq!(frame.frame_type(), FrameType::MaxData);
    assert_eq!(frame.max_encoding_size(), 1 + 8);
    assert_eq!(frame.encoding_size(), 1 + 2);
}

#[test]
fn test_write_max_data_frame() {
    let mut buf = Vec::new();
    buf.put_frame(&MaxDataFrame::new(VarInt::from_u32(0x1234)));
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::MaxData);
    expected.extend_from_slice(&[0x52, 0x34]);
    assert_eq!(buf, expected);
}

#[test]
fn test_read_max_data_frame() {
    assert_eq!(
        super::parse_frame(&[0x10, 0x52, 0x34], FrameType::MaxData),
        qbase::frame::Frame::MaxData(MaxDataFrame::new(VarInt::from_u32(0x1234)))
    );
}
