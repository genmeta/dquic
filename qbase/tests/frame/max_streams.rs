use qbase::{
    frame::{
        EncodeSize, FrameType, GetFrameType, MaxStreamsFrame,
        io::{WriteFrame, WriteFrameType},
    },
    sid::Dir,
    varint::VarInt,
};

#[test]
fn test_max_streams_frame() {
    let frame = MaxStreamsFrame::Bi(VarInt::from_u32(0x1234));
    assert_eq!(frame.frame_type(), FrameType::MaxStreams(Dir::Bi));
    assert_eq!(frame.max_encoding_size(), 1 + 8);
    assert_eq!(frame.encoding_size(), 1 + 2);

    let frame = MaxStreamsFrame::Uni(VarInt::from_u32(0x1236));
    assert_eq!(frame.frame_type(), FrameType::MaxStreams(Dir::Uni));
    assert_eq!(frame.max_encoding_size(), 1 + 8);
    assert_eq!(frame.encoding_size(), 1 + 2);
}

#[test]
fn test_write_max_streams_frame() {
    let mut buf = Vec::new();
    buf.put_frame(&MaxStreamsFrame::Bi(VarInt::from_u32(0x1234)));
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::MaxStreams(Dir::Bi));
    expected.extend_from_slice(&[0x52, 0x34]);
    assert_eq!(buf, expected);
    buf.clear();
    buf.put_frame(&MaxStreamsFrame::Uni(VarInt::from_u32(0x1236)));
    expected.clear();
    expected.put_frame_type(FrameType::MaxStreams(Dir::Uni));
    expected.extend_from_slice(&[0x52, 0x36]);
    assert_eq!(buf, expected);
}

#[test]
fn test_read_max_streams_frame() {
    assert_eq!(
        super::parse_frame(&[18, 0x52, 52], FrameType::MaxStreams(Dir::Bi)),
        qbase::frame::Frame::StreamCtl(qbase::frame::StreamCtlFrame::MaxStreams(
            MaxStreamsFrame::Bi(VarInt::from_u32(4660))
        ))
    );
    assert_eq!(
        super::parse_frame(&[19, 0x52, 54], FrameType::MaxStreams(Dir::Uni)),
        qbase::frame::Frame::StreamCtl(qbase::frame::StreamCtlFrame::MaxStreams(
            MaxStreamsFrame::Uni(VarInt::from_u32(4662))
        ))
    );
}

#[test]
fn test_read_too_large_max_streams_frame() {
    let buf = bytes::Bytes::from_static(&[0x12, 0xd0, 0x34, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80]);
    assert_eq!(
        qbase::frame::io::be_frame(&buf, super::Type::Short(super::OneRtt(0.into()))),
        Err(qbase::frame::Error::ParseError(
            FrameType::MaxStreams(Dir::Bi),
            nom::error::ErrorKind::TooLarge.description().to_owned()
        ))
    );
}
