use qbase::frame::{
    EncodeSize, FrameType, GetFrameType,
    io::{WriteFrame, WriteFrameType},
};
#[test]
fn test_path_challenge_frame() {
    let frame = qbase::frame::PathChallengeFrame::from_slice(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ]);
    assert_eq!(frame.frame_type(), FrameType::PathChallenge);
    assert_eq!(frame.max_encoding_size(), 1 + 8);
    assert_eq!(frame.encoding_size(), 1 + 8);
}

#[test]
fn test_write_path_challenge_frame() {
    let mut buf = Vec::new();
    let frame = qbase::frame::PathChallengeFrame::from_slice(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ]);
    buf.put_frame(&frame);
    let mut expected = Vec::new();
    expected.put_frame_type(FrameType::PathChallenge);
    expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    assert_eq!(buf, expected);
}
