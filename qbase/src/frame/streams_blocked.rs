use crate::{
    frame::{GetFrameType, io::WriteFrameType},
    sid::Dir,
    varint::{VarInt, WriteVarInt, be_varint},
};

/// STREAMS_BLOCKED frame.
///
/// ```text
/// STREAMS_BLOCKED Frame {
///   Type (i) = 0x16..0x17,
///   Maximum Streams (i),
/// }
/// ```
///
/// See [STREAMS_BLOCKED Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-streams_blocked-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamsBlockedFrame {
    Bi(VarInt),
    Uni(VarInt),
}

impl StreamsBlockedFrame {
    pub fn with(dir: Dir, max_streams: VarInt) -> Self {
        match dir {
            Dir::Bi => StreamsBlockedFrame::Bi(max_streams),
            Dir::Uni => StreamsBlockedFrame::Uni(max_streams),
        }
    }
}

impl super::GetFrameType for StreamsBlockedFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::StreamsBlocked(match self {
            StreamsBlockedFrame::Bi(_) => Dir::Bi,
            StreamsBlockedFrame::Uni(_) => Dir::Uni,
        })
    }
}

impl super::EncodeSize for StreamsBlockedFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + match self {
            StreamsBlockedFrame::Bi(stream_id) => stream_id.encoding_size(),
            StreamsBlockedFrame::Uni(stream_id) => stream_id.encoding_size(),
        }
    }
}

/// Return a parser for STREAMS_BLOCKED frame with the given direction,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn streams_blocked_frame_with_dir(
    dir: Dir,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], StreamsBlockedFrame> {
    move |input: &[u8]| {
        let (input, max_streams) = be_varint(input)?;
        Ok((
            input,
            match dir {
                Dir::Bi => StreamsBlockedFrame::Bi(max_streams),
                Dir::Uni => StreamsBlockedFrame::Uni(max_streams),
            },
        ))
    }
}

impl<T: bytes::BufMut> super::io::WriteFrame<StreamsBlockedFrame> for T {
    fn put_frame(&mut self, frame: &StreamsBlockedFrame) {
        match frame {
            StreamsBlockedFrame::Bi(max_streams) => {
                self.put_frame_type(frame.frame_type());
                self.put_varint(max_streams);
            }
            StreamsBlockedFrame::Uni(max_streams) => {
                self.put_frame_type(frame.frame_type());
                self.put_varint(max_streams);
            }
        }
    }
}
