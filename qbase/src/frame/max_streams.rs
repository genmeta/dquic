use crate::{
    frame::{GetFrameType, io::WriteFrameType},
    sid::{Dir, MAX_STREAMS_LIMIT},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// MAX_STREAMS frame.
///
/// ```text
/// MAX_STREAMS Frame {
///   Type (i) = 0x12..0x13,
///   Maximum Streams (i),
/// }
/// ```
///
/// See [MAX_STREAMS Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-max_streams-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxStreamsFrame {
    Bi(VarInt),
    Uni(VarInt),
}

impl MaxStreamsFrame {
    pub fn with(dir: Dir, max_streams: VarInt) -> Self {
        match dir {
            Dir::Bi => MaxStreamsFrame::Bi(max_streams),
            Dir::Uni => MaxStreamsFrame::Uni(max_streams),
        }
    }
}

impl super::GetFrameType for MaxStreamsFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::MaxStreams(match self {
            MaxStreamsFrame::Bi(_) => Dir::Bi,
            MaxStreamsFrame::Uni(_) => Dir::Uni,
        })
    }
}

impl super::EncodeSize for MaxStreamsFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + match self {
            MaxStreamsFrame::Bi(max_streams) => max_streams.encoding_size(),
            MaxStreamsFrame::Uni(max_streams) => max_streams.encoding_size(),
        }
    }
}

/// Returns a parser for MAX_STREAMS frame with the given direction,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn max_streams_frame_with_dir(
    dir: Dir,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], MaxStreamsFrame> {
    move |input: &[u8]| {
        let (remain, max_streams) = be_varint(input)?;
        if max_streams > MAX_STREAMS_LIMIT {
            Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            )))
        } else {
            Ok((
                remain,
                match dir {
                    Dir::Bi => MaxStreamsFrame::Bi(max_streams),
                    Dir::Uni => MaxStreamsFrame::Uni(max_streams),
                },
            ))
        }
    }
}

impl<T: bytes::BufMut> super::io::WriteFrame<MaxStreamsFrame> for T {
    fn put_frame(&mut self, frame: &MaxStreamsFrame) {
        match frame {
            MaxStreamsFrame::Bi(max_streams) => {
                // self.put_frame_type(frame.frame_type());
                self.put_frame_type(frame.frame_type());
                self.put_varint(max_streams);
            }
            MaxStreamsFrame::Uni(max_streams) => {
                self.put_frame_type(frame.frame_type());
                self.put_varint(max_streams);
            }
        }
    }
}
