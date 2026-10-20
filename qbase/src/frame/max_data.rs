use crate::{
    frame::{GetFrameType, io::WriteFrameType},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// MAX_DATA Frame
///
/// ```text
/// MAX_DATA Frame {
///   Type (i) = 0x10,
///   Maximum Data (i),
/// }
/// ```
///
/// See [MAX_DATA Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-max_data-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaxDataFrame {
    max_data: VarInt,
}

impl super::GetFrameType for MaxDataFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::MaxData
    }
}

impl super::EncodeSize for MaxDataFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.max_data.encoding_size()
    }
}

impl MaxDataFrame {
    /// Create a new [`MaxDataFrame`] with the given maximum data.
    pub fn new(max_data: VarInt) -> Self {
        Self { max_data }
    }

    /// Return the maximum data of the frame.
    pub fn max_data(&self) -> u64 {
        self.max_data.into_u64()
    }
}

/// Parse a MAX_DATA frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_max_data_frame(input: &[u8]) -> nom::IResult<&[u8], MaxDataFrame> {
    use nom::{Parser, combinator::map};
    map(be_varint, MaxDataFrame::new).parse(input)
}

impl<T: bytes::BufMut> super::io::WriteFrame<MaxDataFrame> for T {
    fn put_frame(&mut self, frame: &MaxDataFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_varint(&frame.max_data);
    }
}
