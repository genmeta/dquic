use qbase::{
    frame::{
        EncodeSize, FrameType, GetFrameType, RetireConnectionIdFrame,
        io::{WriteFrame, WriteFrameType},
    },
    varint::VarInt,
};

#[test]
fn test_retire_connection_id_frame() {
    let frame = RetireConnectionIdFrame::new(VarInt::from_u32(0x1234));
    assert_eq!(frame.frame_type(), FrameType::RetireConnectionId);
    assert_eq!(frame.max_encoding_size(), 1 + 8);
    assert_eq!(frame.encoding_size(), 1 + 2);
    assert_eq!(frame.sequence(), 0x1234);
}

#[test]
fn test_write_retire_connection_id_frame() {
    let mut buf = Vec::new();
    let frame = RetireConnectionIdFrame::new(VarInt::from_u32(0x1234));
    buf.put_frame(&frame);
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::RetireConnectionId);
    expected.extend_from_slice(&[0x52, 0x34]);
    assert_eq!(buf, expected);
}
