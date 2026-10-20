use super::EncodeSize;
use crate::frame::{GetFrameType, io::WriteFrameType};
/// HandshakeDone frame
///
/// ```text
/// HANDSHAKE_DONE Frame {
///   Type (i) = 0x1e,
/// }
/// ```
///
/// See [HANDSHAKE_DONE Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-handshake_done-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandshakeDoneFrame;

impl super::GetFrameType for HandshakeDoneFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::HandshakeDone
    }
}

impl EncodeSize for HandshakeDoneFrame {}

/// Parse a HANDSHAKE_DONE frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
#[allow(unused)]
pub fn be_handshake_done_frame(input: &[u8]) -> nom::IResult<&[u8], HandshakeDoneFrame> {
    Ok((input, HandshakeDoneFrame))
}

impl<T: bytes::BufMut> super::io::WriteFrame<HandshakeDoneFrame> for T {
    fn put_frame(&mut self, frame: &HandshakeDoneFrame) {
        self.put_frame_type(frame.frame_type());
    }
}
