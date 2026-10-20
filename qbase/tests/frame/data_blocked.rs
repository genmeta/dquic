use qbase::{
    frame::{DataBlockedFrame, EncodeSize, FrameType, GetFrameType, io::WriteFrame},
    varint::VarInt,
};

#[test]
fn test_data_blocked_frame() {
    let frame = DataBlockedFrame::new(VarInt::from_u32(0x1234));
    assert_eq!(frame.frame_type(), FrameType::DataBlocked);
    assert_eq!(frame.max_encoding_size(), 1 + 8);
    assert_eq!(frame.encoding_size(), 1 + 2);
}

#[test]
fn test_write_data_blocked_frame() {
    let mut buf = Vec::new();
    buf.put_frame(&DataBlockedFrame::new(VarInt::from_u32(0x1234)));
    let frame_type: VarInt = FrameType::DataBlocked.into();
    assert_eq!(buf, vec![frame_type.into_u64() as u8, 0x52, 0x34]);
}
