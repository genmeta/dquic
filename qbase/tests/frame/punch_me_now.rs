use qbase::frame::{io::WriteFrame, *};
#[test]
fn test_punch_me_now_frame() {
    let frame = PunchMeNowFrame::new(
        1,
        2,
        "127.0.0.1:12345".parse().unwrap(),
        1,
        qbase::net::NatType::FullCone,
    );
    let mut buf = bytes::BytesMut::new();
    buf.put_frame(&frame);
    assert_eq!(
        super::parse_frame(&buf, frame.frame_type()),
        Frame::PunchMeNow(frame)
    );
}
