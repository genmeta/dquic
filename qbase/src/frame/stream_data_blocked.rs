use crate::{
    frame::{GetFrameType, io::WriteFrameType},
    sid::{StreamId, WriteStreamId, be_streamid},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// STREAM_DATA_BLOCKED frame.
///
/// ```text
/// STREAM_DATA_BLOCKED Frame {
///   Type (i) = 0x15,
///   Stream ID (i),
///   Maximum Stream Data (i),
/// }
/// ```
///
/// See [STREAM_DATA_BLOCKED Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-stream_data_blocked-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamDataBlockedFrame {
    stream_id: StreamId,
    maximum_stream_data: VarInt,
}

impl super::GetFrameType for StreamDataBlockedFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::StreamDataBlocked
    }
}

impl super::EncodeSize for StreamDataBlockedFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.stream_id.encoding_size() + self.maximum_stream_data.encoding_size()
    }
}

impl StreamDataBlockedFrame {
    /// Create a new [`StreamDataBlockedFrame`].
    pub fn new(stream_id: StreamId, maximum_stream_data: VarInt) -> Self {
        Self {
            stream_id,
            maximum_stream_data,
        }
    }

    /// Return the stream ID of the frame.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Return the maximum stream data of the frame.
    pub fn maximum_stream_data(&self) -> u64 {
        self.maximum_stream_data.into_u64()
    }
}

/// Parse a STREAM_DATA_BLOCKED frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_stream_data_blocked_frame(input: &[u8]) -> nom::IResult<&[u8], StreamDataBlockedFrame> {
    let (input, stream_id) = be_streamid(input)?;
    let (input, maximum_stream_data) = be_varint(input)?;
    Ok((
        input,
        StreamDataBlockedFrame {
            stream_id,
            maximum_stream_data,
        },
    ))
}

impl<T: bytes::BufMut> super::io::WriteFrame<StreamDataBlockedFrame> for T {
    fn put_frame(&mut self, frame: &StreamDataBlockedFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_streamid(&frame.stream_id);
        self.put_varint(&frame.maximum_stream_data);
    }
}
