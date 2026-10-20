use crate::frame::{GetFrameType, io::WriteFrameType};
/// PADDING Frame.
///
/// ```text
/// PADDING Frame {
///   Type (i) = 0x00,
/// }
/// ```
///
/// See [PADDING Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-padding-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PaddingFrame;

impl super::GetFrameType for PaddingFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Padding
    }
}

impl super::EncodeSize for PaddingFrame {}

/// Parse a PADDING frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
#[allow(dead_code)]
pub fn be_padding_frame(input: &[u8]) -> nom::IResult<&[u8], PaddingFrame> {
    Ok((input, PaddingFrame))
}

impl<T: bytes::BufMut> super::io::WriteFrame<PaddingFrame> for T {
    fn put_frame(&mut self, frame: &PaddingFrame) {
        self.put_frame_type(frame.frame_type());
    }
}
