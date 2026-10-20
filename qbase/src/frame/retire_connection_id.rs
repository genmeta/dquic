use crate::{
    frame::{GetFrameType, io::WriteFrameType},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// RETIRE_CONNECTION_ID frame.
///
/// ```text
/// RETIRE_CONNECTION_ID Frame {
///   Type (i) = 0x19,
///   Sequence Number (i),
/// }
/// ```
///
/// See [RETIRE_CONNECTION_ID Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-retire_connection_id-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetireConnectionIdFrame {
    sequence: VarInt,
}

impl super::GetFrameType for RetireConnectionIdFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::RetireConnectionId
    }
}

impl super::EncodeSize for RetireConnectionIdFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.sequence.encoding_size()
    }
}

impl RetireConnectionIdFrame {
    /// Create a new [`RetireConnectionIdFrame`].
    pub fn new(sequence: VarInt) -> Self {
        Self { sequence }
    }

    /// Return the sequence number of the frame.
    pub fn sequence(&self) -> u64 {
        self.sequence.into_u64()
    }
}

/// Parse a RETIRE_CONNECTION_ID frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_retire_connection_id_frame(input: &[u8]) -> nom::IResult<&[u8], RetireConnectionIdFrame> {
    use nom::{Parser, combinator::map};
    map(be_varint, RetireConnectionIdFrame::new).parse(input)
}

impl<T: bytes::BufMut> super::io::WriteFrame<RetireConnectionIdFrame> for T {
    fn put_frame(&mut self, frame: &RetireConnectionIdFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_varint(&frame.sequence);
    }
}

#[cfg(test)]
mod tests {
    use super::{RetireConnectionIdFrame, be_retire_connection_id_frame};
    use crate::varint::VarInt;

    #[test]
    fn test_read_retire_connection_id_frame() {
        let buf = vec![0x52, 0x34];
        let (remain, frame) = be_retire_connection_id_frame(&buf).unwrap();
        assert!(remain.is_empty());
        assert_eq!(
            frame,
            RetireConnectionIdFrame::new(VarInt::from_u32(0x1234))
        );
    }
}
