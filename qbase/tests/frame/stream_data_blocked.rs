use qbase::{
    frame::{
        EncodeSize, FrameType, GetFrameType, StreamDataBlockedFrame,
        io::{WriteFrame, WriteFrameType},
    },
    varint::VarInt,
};

#[test]
fn test_stream_data_blocked_frame() {
    let frame =
        StreamDataBlockedFrame::new(VarInt::from_u32(0x1234).into(), VarInt::from_u32(0x5678));
    assert_eq!(frame.frame_type(), FrameType::StreamDataBlocked);
    assert_eq!(frame.max_encoding_size(), 1 + 8 + 8);
    assert_eq!(frame.encoding_size(), 1 + 2 + 4);
    assert_eq!(frame.stream_id(), VarInt::from_u32(0x1234).into());
    assert_eq!(frame.maximum_stream_data(), 0x5678);
}

#[test]
fn test_write_stream_data_blocked_frame() {
    let mut buf = Vec::new();
    buf.put_frame(&StreamDataBlockedFrame::new(
        VarInt::from_u32(0x1234).into(),
        VarInt::from_u32(0x5678),
    ));
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::StreamDataBlocked);
    expected.extend_from_slice(&[0x52, 0x34, 0x80, 0, 0x56, 0x78]);
    assert_eq!(buf, expected);
}

#[test]
fn test_read_stream_data_blocked() {
    assert_eq!(
        super::parse_frame(
            &[0x15, 0x52, 0x34, 0x80, 0, 0x56, 0x78],
            FrameType::StreamDataBlocked
        ),
        qbase::frame::Frame::StreamCtl(qbase::frame::StreamCtlFrame::StreamDataBlocked(
            StreamDataBlockedFrame::new(VarInt::from_u32(0x1234).into(), VarInt::from_u32(0x5678))
        ))
    );
}
