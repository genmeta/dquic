use qbase::{
    frame::{
        EncodeSize, FrameType, GetFrameType, ResetStreamError, ResetStreamFrame,
        io::{WriteFrame, WriteFrameType},
    },
    varint::VarInt,
};

#[test]
fn test_reset_stream_frame() {
    let frame = ResetStreamFrame::new(
        VarInt::from_u32(0x1234).into(),
        VarInt::from_u32(0x5678),
        VarInt::from_u32(0x9abc),
    );
    assert_eq!(frame.frame_type(), FrameType::ResetStream);
    assert_eq!(frame.max_encoding_size(), 1 + 8 + 8 + 8);
    assert_eq!(frame.encoding_size(), 1 + 2 + 4 + 4);
    assert_eq!(frame.stream_id(), VarInt::from_u32(0x1234).into());
    assert_eq!(frame.app_error_code(), 0x5678);
    assert_eq!(frame.final_size(), 0x9abc);

    let reset_stream_error: ResetStreamError = (&frame).into();
    assert_eq!(
        reset_stream_error,
        ResetStreamError::new(VarInt::from_u32(0x5678), VarInt::from_u32(0x9abc))
    );
}

#[test]
fn test_write_reset_stream_frame() {
    let mut buf = Vec::new();
    buf.put_frame(&ResetStreamFrame::new(
        VarInt::from_u32(0x1234).into(),
        // 0x5678 = 0b01010110 01111000 => 0b10000000 0x00 0x56 0x78
        VarInt::from_u32(0x5678),
        // 0x9abc = 0b10011010 10111100 => 0b10000000 0x00 0x9a 0xbc
        VarInt::from_u32(0x9abc),
    ));
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::ResetStream);
    expected.extend_from_slice(&[0x52, 0x34, 0x80, 0, 0x56, 0x78, 0x80, 0, 0x9a, 0xbc]);
    assert_eq!(buf, expected);
}
