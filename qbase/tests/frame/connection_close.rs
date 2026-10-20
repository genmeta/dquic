use qbase::{
    error::ErrorKind,
    frame::{
        EncodeSize, Fin, FrameType, GetFrameType, Len, Offset,
        io::{WriteFrame, WriteFrameType},
        *,
    },
    varint::VarInt,
};

#[test]
fn test_connection_close_frame() {
    let frame = ConnectionCloseFrame::new_app(VarInt::from_u32(0x1234), "wrong");
    assert_eq!(frame.frame_type(), FrameType::ConnectionClose(Layer::App));
    assert_eq!(frame.max_encoding_size(), 1 + 8 + 2 + 5);
    assert_eq!(frame.encoding_size(), 1 + 2 + 1 + 5);
}

#[test]
fn test_write_connection_close_frame() {
    use qbase::frame::FrameType;
    let mut buf = Vec::<u8>::new();
    let frame = ConnectionCloseFrame::new_quic(
        ErrorKind::FlowControl,
        FrameType::Stream(Offset::NonZero, Len::Explicit, Fin::No).into(),
        "wrong",
    );
    buf.put_frame(&frame);
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::ConnectionClose(Layer::Quic));
    expected.extend_from_slice(&[0x03, 0xe, 5, b'w', b'r', b'o', b'n', b'g']);
    assert_eq!(buf, expected);
}

#[test]
fn test_read_connection_close_frame() {
    assert_eq!(
        super::parse_frame(
            &[0x1d, 0x0c, 5, b'w', b'r', b'o', b'n', b'g'],
            FrameType::ConnectionClose(Layer::App)
        ),
        qbase::frame::Frame::Close(ConnectionCloseFrame::new_app(
            VarInt::from_u32(0x0c),
            "wrong"
        ))
    );
}
