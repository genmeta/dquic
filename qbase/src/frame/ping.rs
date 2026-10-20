use crate::frame::{GetFrameType, io::WriteFrameType};
/// PING Frame.
///
/// ```text
/// PING Frame {
///   Type (i) = 0x01,
/// }
/// ```
///
/// See [PING Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-ping-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PingFrame;

impl super::GetFrameType for PingFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Ping
    }
}

impl super::EncodeSize for PingFrame {}

/// Parse a PING frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
#[allow(unused)]
pub fn be_ping_frame(input: &[u8]) -> nom::IResult<&[u8], PingFrame> {
    Ok((input, PingFrame))
}

impl<T: bytes::BufMut> super::io::WriteFrame<PingFrame> for T {
    fn put_frame(&mut self, frame: &PingFrame) {
        self.put_frame_type(frame.frame_type());
    }
}
#[cfg(test)]
mod tests {
    use super::PingFrame;
    use crate::{frame::FrameType, varint::VarInt};

    #[test]
    fn test_read_ping_frame() {
        use nom::{Parser, combinator::flat_map};

        use super::be_ping_frame;
        use crate::varint::be_varint;
        let ping_frame_type = VarInt::from(FrameType::Ping);
        let buf = vec![ping_frame_type.into_u64() as u8];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type == ping_frame_type {
                be_ping_frame
            } else {
                panic!("wrong frame type: {frame_type}")
            }
        })
        .parse(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(frame, PingFrame);
    }
}
