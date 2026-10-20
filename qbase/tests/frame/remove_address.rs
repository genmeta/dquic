use qbase::{
    frame::{io::WriteFrame, *},
    varint::VarInt,
};
#[test]
fn test_remove_address_frame() {
    let frame = RemoveAddressFrame {
        seq_num: VarInt::from_u32(0x1234),
    };
    assert_eq!(frame.max_encoding_size(), 12);
    assert_eq!(frame.encoding_size(), 6);
    let mut buf = bytes::BytesMut::new();
    buf.put_frame(&frame);
    assert_eq!(
        super::parse_frame(&buf, frame.frame_type()),
        Frame::RemoveAddress(frame)
    );
}
