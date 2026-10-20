use crate::{
    frame::{GetFrameType, io::WriteFrameType},
    sid::{StreamId, WriteStreamId, be_streamid},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// STOP_SENDING frame.
///
/// ```text
/// STOP_SENDING Frame {
///   Type (i) = 0x05,
///   Stream ID (i),
///   Application Protocol Error Code (i),
/// }
/// ```
///
/// See [STOP_SENDING Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopSendingFrame {
    stream_id: StreamId,
    app_err_code: VarInt,
}

impl StopSendingFrame {
    /// Create a new [`StopSendingFrame`].
    pub fn new(stream_id: StreamId, app_err_code: VarInt) -> Self {
        Self {
            stream_id,
            app_err_code,
        }
    }

    /// Return the stream ID of the frame.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Return the application protocol error code of the frame.
    pub fn app_err_code(&self) -> u64 {
        self.app_err_code.into_u64()
    }

    /// Compose a RESET_STREAM frame from the STOP_SENDING frame with the given final size.
    pub fn reset_stream(&self, final_size: VarInt) -> super::ResetStreamFrame {
        super::ResetStreamFrame::new(self.stream_id, self.app_err_code, final_size)
    }
}

impl super::GetFrameType for StopSendingFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::StopSending
    }
}

impl super::EncodeSize for StopSendingFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.stream_id.encoding_size() + self.app_err_code.encoding_size()
    }
}

/// Parse a STOP_SENDING frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_stop_sending_frame(input: &[u8]) -> nom::IResult<&[u8], StopSendingFrame> {
    use nom::{Parser, combinator::map};
    map((be_streamid, be_varint), |(stream_id, app_err_code)| {
        StopSendingFrame {
            stream_id,
            app_err_code,
        }
    })
    .parse(input)
}

impl<T: bytes::BufMut> super::io::WriteFrame<StopSendingFrame> for T {
    fn put_frame(&mut self, frame: &StopSendingFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_streamid(&frame.stream_id);
        self.put_varint(&frame.app_err_code);
    }
}
