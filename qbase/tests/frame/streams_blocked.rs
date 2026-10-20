use qbase::{
    frame::{
        EncodeSize, FrameType, GetFrameType, StreamsBlockedFrame,
        io::{WriteFrame, WriteFrameType},
    },
    sid::Dir,
    varint::VarInt,
};

#[test]
fn test_stream_data_blocked_frame() {
    let frame = StreamsBlockedFrame::Bi(VarInt::from_u32(0x1234));
    assert_eq!(frame.frame_type(), FrameType::StreamsBlocked(Dir::Bi));
    assert_eq!(frame.max_encoding_size(), 1 + 8);
    assert_eq!(frame.encoding_size(), 1 + 2);

    let frame = StreamsBlockedFrame::Uni(VarInt::from_u32(0x1234));
    assert_eq!(frame.frame_type(), FrameType::StreamsBlocked(Dir::Uni));
    assert_eq!(frame.max_encoding_size(), 1 + 8);
    assert_eq!(frame.encoding_size(), 1 + 2);
}

#[test]
fn test_write_streams_blocked_frame() {
    let mut buf = Vec::new();
    buf.put_frame(&StreamsBlockedFrame::Bi(VarInt::from_u32(0x1234)));
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::StreamsBlocked(Dir::Bi));
    expected.extend_from_slice(&[0x52, 0x34]);
    assert_eq!(buf, expected);
    let mut buf = Vec::new();
    buf.put_frame(&StreamsBlockedFrame::Uni(VarInt::from_u32(0x1234)));
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::StreamsBlocked(Dir::Uni));
    expected.extend_from_slice(&[0x52, 0x34]);
    assert_eq!(buf, expected);
}
