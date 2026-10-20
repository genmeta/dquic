use qbase::frame::{
    EncodeSize, FrameType, GetFrameType,
    io::{WriteFrame, WriteFrameType},
    *,
};

#[test]
fn test_path_response_frame() {
    let frame = PathResponseFrame::from(PathChallengeFrame::from_slice(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ]));
    assert_eq!(frame.frame_type(), FrameType::PathResponse);
    assert_eq!(frame.max_encoding_size(), 1 + 8);
    assert_eq!(frame.encoding_size(), 1 + 8);
}

#[test]
fn test_write_path_response_frame() {
    let mut buf = Vec::<u8>::new();
    let frame = PathResponseFrame::from(PathChallengeFrame::from_slice(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ]));
    buf.put_frame(&frame);
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::PathResponse);
    expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    assert_eq!(buf, expected);
}

#[test]
fn test_read_path_response_frame() {
    assert_eq!(
        super::parse_frame(&[0x1b, 1, 2, 3, 4, 5, 6, 7, 8], FrameType::PathResponse),
        qbase::frame::Frame::PathResponse(PathResponseFrame::from(PathChallengeFrame::from_slice(
            &[1, 2, 3, 4, 5, 6, 7, 8]
        )))
    );
}
