use qbase::frame::{AckFrame, EncodeSize};
use qevent::quic::QuicFrame;

#[test]
fn ack() {
    // 123 56 9
    let frame = AckFrame::new(
        9u32.into(),
        1000u32.into(),
        0u32.into(),
        vec![(1u32.into(), 1u32.into()), (0u32.into(), 2u32.into())],
        None,
    );

    let encoding_size = frame.encoding_size();

    let quic_frame: QuicFrame = (&frame).into();
    assert_eq!(
        quic_frame,
        QuicFrame::Ack {
            ack_delay: Some(1.0),
            acked_ranges: vec![[9, 9], [5, 6], [1, 3]],
            ect1: None,
            ect0: None,
            ce: None,
            length: Some(encoding_size as u32),
            payload_length: None,
        }
    );
}
