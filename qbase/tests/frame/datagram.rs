use qbase::{
    frame::{EncodeSize, io::WriteDataFrame, *},
    varint::VarInt,
};

#[test]
fn test_datagram_frame() {
    let frame = DatagramFrame::new(true, VarInt::from_u32(3));
    assert_eq!(frame.frame_type(), FrameType::Datagram(1));
    assert_eq!(frame.max_encoding_size(), 1 + 8);
    assert_eq!(frame.encoding_size(), 1 + 1);
}

#[test]
fn test_put_datagram_frame_with_length() {
    let frame = DatagramFrame::new(true, VarInt::from_u32(3));
    let mut buf = Vec::new();
    buf.put_data_frame(&frame, &[0x01, 0x02, 0x03]);
    assert_eq!(&buf, &[0x31, 0x03, 0x01, 0x02, 0x03]);
}

#[test]
fn test_put_datagram_frame_no_length() {
    let frame = DatagramFrame::new(false, VarInt::from_u32(3));
    let mut buf = Vec::new();
    buf.put_data_frame(&frame, &[0x01, 0x02, 0x03]);
    assert_eq!(&buf, &[0x30, 0x01, 0x02, 0x03]);
}

#[test]
fn test_datagram_frame_with_flag() {
    assert_eq!(
        super::parse_frame(&[0x31, 5, 0, 0, 0, 0, 0], FrameType::Datagram(1)),
        Frame::Datagram(
            DatagramFrame::new(true, VarInt::from_u32(5)),
            bytes::Bytes::from_static(&[0; 5])
        )
    );
}

#[test]
fn test_datagram_frame_with_flag_no_length() {
    assert_eq!(
        super::parse_frame(
            &[0x30, b'1', b'1', b'4', b'5', b'1', b'4'],
            FrameType::Datagram(0)
        ),
        Frame::Datagram(
            DatagramFrame::new(false, VarInt::from_u32(6)),
            bytes::Bytes::from_static(b"114514")
        )
    );
}
