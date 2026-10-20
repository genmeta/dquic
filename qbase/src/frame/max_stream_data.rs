use crate::{
    frame::{GetFrameType, io::WriteFrameType},
    sid::{StreamId, WriteStreamId, be_streamid},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// MAX_STREAM_DATA frame.
///
/// ```text
/// MAX_STREAM_DATA Frame {
///   Type (i) = 0x11,
///   Stream ID (i),
///   Maximum Stream Data (i),
/// }
/// ```
///
/// See [MAX_STREAM_DATA Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-max_stream_data-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxStreamDataFrame {
    stream_id: StreamId,
    max_stream_data: VarInt,
}

impl MaxStreamDataFrame {
    /// Create a new [`MaxStreamDataFrame`].
    pub fn new(stream_id: StreamId, max_stream_data: VarInt) -> Self {
        Self {
            stream_id,
            max_stream_data,
        }
    }

    /// Return the stream ID of the frame.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Return the maximum stream data of the frame.
    pub fn max_stream_data(&self) -> u64 {
        self.max_stream_data.into_u64()
    }
}

impl super::GetFrameType for MaxStreamDataFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::MaxStreamData
    }
}

impl super::EncodeSize for MaxStreamDataFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.stream_id.encoding_size() + self.max_stream_data.encoding_size()
    }
}

/// Parse a MAX_STREAM_DATA frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_max_stream_data_frame(input: &[u8]) -> nom::IResult<&[u8], MaxStreamDataFrame> {
    use nom::{Parser, combinator::map, sequence::pair};
    map(
        pair(be_streamid, be_varint),
        |(stream_id, max_stream_data)| MaxStreamDataFrame {
            stream_id,
            max_stream_data,
        },
    )
    .parse(input)
}

impl<T: bytes::BufMut> super::io::WriteFrame<MaxStreamDataFrame> for T {
    fn put_frame(&mut self, frame: &MaxStreamDataFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_streamid(&frame.stream_id);
        self.put_varint(&frame.max_stream_data);
    }
}
