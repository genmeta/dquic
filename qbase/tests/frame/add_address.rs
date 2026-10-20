use qbase::frame::{io::WriteFrame, *};
#[test]
fn test_add_address_frame() {
    let frame = AddAddressFrame::new(
        1,
        "127.0.0.1:8080".parse().unwrap(),
        1,
        qbase::net::NatType::FullCone,
    );
    let mut buf = bytes::BytesMut::new();
    buf.put_frame(&frame);
    assert_eq!(
        super::parse_frame(&buf, frame.frame_type()),
        Frame::AddAddress(frame)
    );
}
