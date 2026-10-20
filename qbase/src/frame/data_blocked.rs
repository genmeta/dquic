use crate::{
    frame::{GetFrameType, io::WriteFrameType},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// DATA_BLOCKED Frame
///
/// ```text
/// DATA_BLOCKED Frame {
///   Type (i) = 0x14,
///   Maximum Data (i),
/// }
/// ```
///
/// See [data-blocked frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-data_blocked-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DataBlockedFrame {
    limit: VarInt,
}

impl super::GetFrameType for DataBlockedFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::DataBlocked
    }
}

impl super::EncodeSize for DataBlockedFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.limit.encoding_size()
    }
}

impl DataBlockedFrame {
    /// Create a new [`DataBlockedFrame`] with the given limit.
    pub fn new(limit: VarInt) -> Self {
        Self { limit }
    }

    /// Return the limit of the frame.
    pub fn limit(&self) -> u64 {
        self.limit.into_u64()
    }
}

/// Parse a DATA_BLOCKED frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_data_blocked_frame(input: &[u8]) -> nom::IResult<&[u8], DataBlockedFrame> {
    use nom::{Parser, combinator::map};
    map(be_varint, DataBlockedFrame::new).parse(input)
}

impl<T: bytes::BufMut> super::io::WriteFrame<DataBlockedFrame> for T {
    fn put_frame(&mut self, frame: &DataBlockedFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_varint(&frame.limit);
    }
}
