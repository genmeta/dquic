use qbase::{
    frame::{EncodeSize, FrameType, GetFrameType, io::WriteDataFrame, *},
    varint::VarInt,
};

#[test]
fn test_stream_frame() {
    let mut stream_frame = StreamFrame::new(VarInt::from_u32(0x1234).into(), 0x1234, 11);
    stream_frame.set_len_bit(Len::Explicit);
    stream_frame.set_eos_flag(false);
    assert_eq!(
        stream_frame.frame_type(),
        FrameType::Stream(Offset::NonZero, Len::Explicit, Fin::No)
    );
    assert_eq!(stream_frame.max_encoding_size(), 1 + 8 + 8 + 8);
    assert_eq!(stream_frame.encoding_size(), 1 + 2 + 2 + 1);
}

#[test]
fn test_write_initial_stream_frame() {
    let mut buf = Vec::new();
    let mut frame = StreamFrame::new(VarInt::from_u32(0x1234).into(), 0, 11);
    frame.set_len_bit(Len::Explicit);
    frame.set_eos_flag(true);
    buf.put_data_frame(&frame, b"hello world");
    assert_eq!(
        buf,
        vec![
            0xb, 0x52, 0x34, 0x0b, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd'
        ]
    );
}

#[test]
fn test_write_last_stream_frame() {
    let mut buf = Vec::new();
    let mut frame = StreamFrame::new(VarInt::from_u32(0x1234).into(), 0, 11);
    frame.set_len_bit(Len::Omit);
    frame.set_eos_flag(true);
    buf.put_data_frame(&frame, b"hello world");
    assert_eq!(
        buf,
        vec![
            0x9, 0x52, 0x34, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd'
        ]
    );
}

#[test]
fn test_write_eos_frame() {
    let mut buf = Vec::new();
    let mut frame = StreamFrame::new(VarInt::from_u32(0x1234).into(), 0x1234, 11);
    frame.set_len_bit(Len::Explicit);
    frame.set_eos_flag(true);
    buf.put_data_frame(&frame, b"hello world");
    assert_eq!(
        buf,
        vec![
            0x0f, 0x52, 0x34, 0x52, 0x34, 0x0b, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o',
            b'r', b'l', b'd'
        ]
    );
}

#[test]
fn test_write_unfinished_stream_frame() {
    let mut buf = Vec::new();
    let mut frame = StreamFrame::new(VarInt::from_u32(0x1234).into(), 0x1234, 11);
    frame.set_len_bit(Len::Explicit);
    frame.set_eos_flag(false);
    buf.put_data_frame(&frame, b"hello world");
    assert_eq!(
        buf,
        vec![
            0x0e, 0x52, 0x34, 0x52, 0x34, 0x0b, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o',
            b'r', b'l', b'd'
        ]
    );
}

#[test]
fn test_read_stream_frame() {
    let mut buf = vec![0x0e, 0x52, 0x34, 0x52, 0x34, 0x0b];
    buf.extend_from_slice(b"hello world");
    buf.push(0);
    let raw = bytes::Bytes::from(buf);
    let (consumed, frame, frame_type) =
        io::be_frame(&raw, super::Type::Short(super::OneRtt(0.into()))).unwrap();
    let mut expected = StreamFrame::new(VarInt::from_u32(0x1234).into(), 0x1234, 11);
    expected.set_len_bit(Len::Explicit);
    expected.set_eos_flag(false);
    assert_eq!(frame_type, expected.frame_type());
    assert_eq!(
        frame,
        Frame::Stream(expected, bytes::Bytes::from_static(b"hello world"))
    );
    assert_eq!(&raw[consumed..], &[0]);
}

#[test]
fn test_read_last_stream_frame() {
    let mut buf = vec![0x0c, 0x52, 0x34, 0x52, 0x34];
    buf.extend_from_slice(b"hello world");
    let raw = bytes::Bytes::from(buf);
    let (consumed, frame, frame_type) =
        io::be_frame(&raw, super::Type::Short(super::OneRtt(0.into()))).unwrap();
    let mut expected = StreamFrame::new(VarInt::from_u32(0x1234).into(), 0x1234, 11);
    expected.set_len_bit(Len::Omit);
    expected.set_eos_flag(false);
    assert_eq!(frame_type, expected.frame_type());
    assert_eq!(
        frame,
        Frame::Stream(expected, bytes::Bytes::from_static(b"hello world"))
    );
    assert_eq!(&raw[consumed..], &[]);
}
