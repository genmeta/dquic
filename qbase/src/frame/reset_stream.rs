use thiserror::Error;

use crate::{
    frame::{GetFrameType, io::WriteFrameType},
    sid::{StreamId, WriteStreamId, be_streamid},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// RESET_STREAM frame.
///
/// ```text
/// RESET_STREAM Frame {
///   Type (i) = 0x04,
///   Stream ID (i),
///   Application Protocol Error Code (i),
///   Final Size (i),
/// }
/// ```
///
/// See [RESET_STREAM Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetStreamFrame {
    stream_id: StreamId,
    app_error_code: VarInt,
    final_size: VarInt,
}

impl super::GetFrameType for ResetStreamFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::ResetStream
    }
}

impl super::EncodeSize for ResetStreamFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.stream_id.encoding_size()
            + self.app_error_code.encoding_size()
            + self.final_size.encoding_size()
    }
}

impl ResetStreamFrame {
    /// Create a new [`ResetStreamFrame`].
    pub fn new(stream_id: StreamId, app_error_code: VarInt, final_size: VarInt) -> Self {
        Self {
            stream_id,
            app_error_code,
            final_size,
        }
    }

    /// Return the stream ID of the frame.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Return the application protocol error code of the frame.
    pub fn app_error_code(&self) -> u64 {
        self.app_error_code.into_u64()
    }

    /// Return the final size of the frame.
    pub fn final_size(&self) -> u64 {
        self.final_size.into_u64()
    }
}

/// Parse a RESET_STREAM frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_reset_stream_frame(input: &[u8]) -> nom::IResult<&[u8], ResetStreamFrame> {
    use nom::{Parser, combinator::map};
    map(
        (be_streamid, be_varint, be_varint),
        |(stream_id, app_error_code, final_size)| ResetStreamFrame {
            stream_id,
            app_error_code,
            final_size,
        },
    )
    .parse(input)
}

impl<T: bytes::BufMut> super::io::WriteFrame<ResetStreamFrame> for T {
    fn put_frame(&mut self, frame: &ResetStreamFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_streamid(&frame.stream_id);
        self.put_varint(&frame.app_error_code);
        self.put_varint(&frame.final_size);
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("The stream was reset with app error code: {app_error_code}, final size: {final_size}")]
pub struct ResetStreamError {
    app_error_code: VarInt,
    final_size: VarInt,
}

impl ResetStreamError {
    pub fn new(app_error_code: VarInt, final_size: VarInt) -> Self {
        Self {
            app_error_code,
            final_size,
        }
    }

    pub fn error_code(&self) -> u64 {
        self.app_error_code.into_u64()
    }

    pub fn combine(self, sid: StreamId) -> ResetStreamFrame {
        ResetStreamFrame {
            stream_id: sid,
            app_error_code: self.app_error_code,
            final_size: self.final_size,
        }
    }
}

impl From<&ResetStreamFrame> for ResetStreamError {
    fn from(frame: &ResetStreamFrame) -> Self {
        Self {
            app_error_code: frame.app_error_code,
            final_size: frame.final_size,
        }
    }
}
