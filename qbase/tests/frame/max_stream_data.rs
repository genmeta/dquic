use qbase::{
    frame::{
        EncodeSize, FrameType, GetFrameType, MaxStreamDataFrame,
        io::{WriteFrame, WriteFrameType},
    },
    varint::VarInt,
};

#[test]
fn test_max_stream_data_frame() {
    let frame = MaxStreamDataFrame::new(VarInt::from_u32(0x1234).into(), VarInt::from_u32(0x5678));
    assert_eq!(frame.stream_id(), VarInt::from_u32(0x1234).into());
    assert_eq!(frame.max_stream_data(), 0x5678);
    assert_eq!(frame.frame_type(), FrameType::MaxStreamData);
    assert_eq!(frame.max_encoding_size(), 1 + 8 + 8);
    assert_eq!(frame.encoding_size(), 1 + 2 + 4);
}

#[test]
fn test_write_max_stream_data_frame() {
    let mut buf = Vec::new();
    buf.put_frame(&MaxStreamDataFrame::new(
        VarInt::from_u32(0x1234).into(),
        VarInt::from_u32(0x5678),
    ));
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::MaxStreamData);
    expected.extend_from_slice(&[0x52, 0x34, 0x80, 0, 0x56, 0x78]);
    assert_eq!(buf, expected);
}
