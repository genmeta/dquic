use std::ops::Range;

use super::GetFrameType;
use crate::{
    frame::EncodeSize,
    sid::{StreamId, WriteStreamId, be_streamid},
    util::{Buffer, WriteData},
    varint::{VARINT_MAX, VarInt, WriteVarInt, be_varint},
};

/// Offset flag for STREAM frames
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Offset {
    /// Offset field is zero (not present in frame)
    Zero,
    /// Offset field is non-zero (present in frame)
    NonZero,
}

impl From<Offset> for u8 {
    fn from(offset: Offset) -> u8 {
        match offset {
            Offset::Zero => 0,
            Offset::NonZero => 0x04,
        }
    }
}

impl From<u64> for Offset {
    fn from(value: u64) -> Self {
        match value & 0x04 {
            0 => Offset::Zero,
            _ => Offset::NonZero,
        }
    }
}

/// Length flag for STREAM frames
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Len {
    /// Length field is present
    Explicit,
    /// Length field is omitted (extends to end of packet)
    Omit,
}

impl From<Len> for u8 {
    fn from(length: Len) -> u8 {
        match length {
            Len::Explicit => 0x02,
            Len::Omit => 0,
        }
    }
}

impl From<u64> for Len {
    fn from(value: u64) -> Self {
        match value & 0x02 {
            0 => Len::Omit,
            _ => Len::Explicit,
        }
    }
}

/// Fin flag for STREAM frames
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Fin {
    /// Stream is finished
    Yes,
    /// Stream is not finished
    No,
}

impl From<Fin> for u8 {
    fn from(fin: Fin) -> u8 {
        match fin {
            Fin::Yes => 0x01,
            Fin::No => 0,
        }
    }
}

impl From<u64> for Fin {
    fn from(value: u64) -> Self {
        match value & 0x01 {
            0 => Fin::No,
            _ => Fin::Yes,
        }
    }
}

/// STREAM frame.
///
/// ```text
/// STREAM Frame {
///   Type (i) = 0x08..0x0f,
///   Stream ID (i),
///   [Offset (i)],
///   [Length (i)],
///   Stream Data (..),
/// }
/// ```
///
/// The lower 3 bits of the frame type are used to indicate the presence of the following fields:
/// - OFF bit: 0x04
/// - LEN bit: 0x02
/// - FIN bit: 0x01
///
/// See [STREAM Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-stream-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFrame {
    id: StreamId,
    offset: VarInt,
    length: usize,
    len_bit: Len,
    fin_bit: Fin,
}

pub const STREAM_FRAME_MAX_ENCODING_SIZE: usize = 1 + 8 + 8 + 8;

impl GetFrameType for StreamFrame {
    fn frame_type(&self) -> super::FrameType {
        let offset = if self.offset == 0 {
            Offset::Zero
        } else {
            Offset::NonZero
        };
        super::FrameType::Stream(offset, self.len_bit, self.fin_bit)
    }
}

impl super::EncodeSize for StreamFrame {
    fn max_encoding_size(&self) -> usize {
        STREAM_FRAME_MAX_ENCODING_SIZE
    }

    fn encoding_size(&self) -> usize {
        1 + self.id.encoding_size()
            + if self.offset.into_u64() != 0 {
                self.offset.encoding_size()
            } else {
                0
            }
            + if self.len_bit == Len::Explicit {
                VarInt::from_u64(self.length as u64)
                    .expect("msg length must be less than 2^62")
                    .encoding_size()
            } else {
                0
            }
    }
}

/// Efficient strategies for encoding stream frames
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodingStrategy {
    len_bit: Len,
    pre_padding: usize,
}

impl EncodingStrategy {
    /// Cound the stream frame carry its data's length.
    pub fn len_bit(&self) -> Len {
        self.len_bit
    }

    /// How many padding frames should be put before the stream frame.
    pub fn pre_padding(&self) -> usize {
        self.pre_padding
    }
}

impl StreamFrame {
    /// Create a new stream frame with the given stream id, offset, and length.
    pub fn new(id: StreamId, offset: u64, length: usize) -> Self {
        assert!(offset <= VARINT_MAX);
        Self {
            id,
            offset: VarInt::from_u64(offset)
                .expect("offset of stream frame must be less than 2^62"),
            length,
            len_bit: Len::Omit,
            fin_bit: Fin::No,
        }
    }

    /// Return the stream id of this stream frame.
    pub fn stream_id(&self) -> StreamId {
        self.id
    }

    /// Return whether this stream frame is the end of the stream.
    pub fn is_fin(&self) -> bool {
        self.fin_bit == Fin::Yes
    }

    /// Return the offset of this stream frame.
    pub fn offset(&self) -> u64 {
        self.offset.into_u64()
    }

    /// Return the length of this stream frame.
    pub fn len(&self) -> usize {
        self.length
    }

    /// Return whether this stream frame is empty.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Return the range of this stream frame covered.
    pub fn range(&self) -> Range<u64> {
        self.offset.into_u64()..self.offset.into_u64() + self.length as u64
    }

    /// Set the end of stream flag of this stream frame.
    pub fn set_eos_flag(&mut self, is_eos: bool) {
        if is_eos {
            self.fin_bit = Fin::Yes;
        } else {
            self.fin_bit = Fin::No;
        }
    }

    /// Set the length bit of this stream frame.
    pub fn set_len_bit(&mut self, len_bit: Len) {
        self.len_bit = len_bit;
    }

    /// Returns the most efficient stream frame encoding strategy.
    ///
    /// By default, a stream frame is considered the last frame within a data packet,
    /// allowing it to carry data up to the maximum payload capacity. However, if the
    ///  data does not fill the entire frame and there is sufficient space remaining
    /// in the packet, other data frames can be carried after it. In this case, the
    /// frame is designated as carrying length. However, when a stream frame with a length
    /// is put into the data packet, the remaining space may be too small to put another
    /// stream frame. Filling the remaining space is sometimes more beneficial to taking
    /// advantage of GSO features.
    pub fn encoding_strategy(&self, capacity: usize) -> EncodingStrategy {
        // this method is used to determine the encoding strategy of the stream frame
        debug_assert_eq!(self.len_bit, Len::Omit);

        let encoding_size_without_length = self.encoding_size() + self.length;
        assert!(encoding_size_without_length <= capacity);

        let len_encoding_size = VarInt::try_from(self.length)
            .expect("length of stream frame must be less than 2^62")
            .encoding_size();

        let remaining = capacity - encoding_size_without_length;
        if remaining >= len_encoding_size {
            let remaining = remaining - len_encoding_size;
            // TODO: It doesn't make sense, STREAM_FRAME_MAX_ENCODING_SIZE is 25 bytes
            // but the minium stream size can be as small as 3 bytes
            // with stream id less than 64 and offset 0 and without length
            if remaining < STREAM_FRAME_MAX_ENCODING_SIZE {
                EncodingStrategy {
                    len_bit: Len::Explicit,
                    pre_padding: remaining,
                }
            } else {
                EncodingStrategy {
                    len_bit: Len::Explicit,
                    pre_padding: 0,
                }
            }
        } else {
            EncodingStrategy {
                len_bit: Len::Omit,
                pre_padding: remaining,
            }
        }
    }

    /// Estimate the maximum capacity that one stream frame with the given capacity,
    /// stream id, and offset can carry.
    pub fn estimate_max_capacity(capacity: usize, sid: StreamId, offset: u64) -> Option<usize> {
        assert!(offset <= VARINT_MAX);
        let mut least = 1 + sid.encoding_size();
        if offset != 0 {
            least += VarInt::from_u64(offset).unwrap().encoding_size();
        }
        if capacity <= least {
            None
        } else {
            Some(capacity - least)
        }
    }
}

/// Return a parser for a stream frame with the given flag,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn stream_frame_with_flag(
    offset: Offset,
    len: Len,
    fin: Fin,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], StreamFrame> {
    move |input| {
        let (remain, id) = be_streamid(input)?;
        let (remain, offset) = if offset == Offset::NonZero {
            be_varint(remain)?
        } else {
            (remain, VarInt::default())
        };
        let (remain, length) = if len == Len::Explicit {
            let (remain, length) = be_varint(remain)?;
            (remain, length.into_u64() as usize)
        } else {
            (remain, remain.len())
        };
        if offset.into_u64() + length as u64 > VARINT_MAX {
            return Err(nom::Err::Error(nom::error::make_error(
                input,
                nom::error::ErrorKind::TooLarge,
            )));
        }
        Ok((
            remain,
            StreamFrame {
                id,
                offset,
                length,
                len_bit: len,
                fin_bit: fin,
            },
        ))
    }
}

impl<T, D> super::io::WriteDataFrame<StreamFrame, D> for T
where
    T: bytes::BufMut + WriteData<D>,
    D: Buffer,
{
    fn put_data_frame(&mut self, frame: &StreamFrame, data: &D) {
        use crate::frame::io::WriteFrameType;
        self.put_frame_type(frame.frame_type());
        self.put_streamid(&frame.id);
        if frame.offset.into_u64() != 0 {
            self.put_varint(&frame.offset);
        }
        if frame.len_bit == Len::Explicit {
            // Generally, a data frame will not exceed 4GB.
            self.put_varint(&VarInt::from_u32(frame.length as u32));
        }
        self.put_data(data);
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use nom::{Parser, combinator::flat_map};

    use super::*;
    use crate::{
        frame::{EncodeSize, FrameType, GetFrameType, io::WriteDataFrame},
        varint::{VarInt, be_varint},
    };

    #[test]
    fn test_stream_frame() {
        let stream_frame = StreamFrame {
            id: VarInt::from_u32(0x1234).into(),
            offset: VarInt::from_u32(0x1234),
            length: 11,
            len_bit: Len::Explicit,
            fin_bit: Fin::No,
        };
        assert_eq!(
            stream_frame.frame_type(),
            FrameType::Stream(Offset::NonZero, Len::Explicit, Fin::No)
        );
        assert_eq!(stream_frame.max_encoding_size(), 1 + 8 + 8 + 8);
        assert_eq!(stream_frame.encoding_size(), 1 + 2 + 2 + 1);
    }

    #[test]
    fn test_read_stream_frame() {
        let raw = Bytes::from_static(&[
            0x0e, 0x52, 0x34, 0x52, 0x34, 0x0b, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o',
            b'r', b'l', b'd', 0,
        ]);
        let input = raw.as_ref();
        let (input, frame) = flat_map(be_varint, |frame_type| {
            let stream_frame_type: VarInt =
                FrameType::Stream(Offset::NonZero, Len::Explicit, Fin::No).into();
            assert_eq!(frame_type, stream_frame_type);
            stream_frame_with_flag(Offset::NonZero, Len::Explicit, Fin::No)
        })
        .parse(input)
        .unwrap();

        assert_eq!(
            input,
            &[
                b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd', 0,
            ][..]
        );
        assert_eq!(
            frame,
            StreamFrame {
                id: VarInt::from_u32(0x1234).into(),
                offset: VarInt::from_u32(0x1234),
                length: 11,
                len_bit: Len::Explicit,
                fin_bit: Fin::No,
            }
        );
    }

    #[test]
    fn test_read_last_stream_frame() {
        let raw = Bytes::from_static(&[
            0x0c, 0x52, 0x34, 0x52, 0x34, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r',
            b'l', b'd',
        ]);
        let input = raw.as_ref();
        let (input, frame) = flat_map(be_varint, |frame_type| {
            let stream_frame_type: VarInt =
                FrameType::Stream(Offset::NonZero, Len::Omit, Fin::No).into();
            assert_eq!(frame_type, stream_frame_type);
            stream_frame_with_flag(Offset::NonZero, Len::Omit, Fin::No)
        })
        .parse(input)
        .unwrap();

        assert_eq!(
            input,
            &[
                b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd',
            ][..]
        );
        assert_eq!(
            frame,
            StreamFrame {
                id: VarInt::from_u32(0x1234).into(),
                offset: VarInt::from_u32(0x1234),
                length: 11,
                len_bit: Len::Omit,
                fin_bit: Fin::No,
            }
        );
    }

    #[test]
    fn test_write_initial_stream_frame() {
        let mut buf = Vec::new();
        let frame = StreamFrame {
            id: VarInt::from_u32(0x1234).into(),
            offset: VarInt::from_u32(0),
            length: 11,
            len_bit: Len::Explicit,
            fin_bit: Fin::Yes,
        };
        buf.put_data_frame(&frame, b"hello world");
        assert_eq!(
            buf,
            vec![
                0xb, 0x52, 0x34, 0x0b, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l',
                b'd'
            ]
        );
    }

    #[test]
    fn test_write_last_stream_frame() {
        let mut buf = Vec::new();
        let frame = StreamFrame {
            id: VarInt::from_u32(0x1234).into(),
            offset: VarInt::from_u32(0),
            length: 11,
            len_bit: Len::Omit,
            fin_bit: Fin::Yes,
        };
        buf.put_data_frame(&frame, b"hello world");
        assert_eq!(
            buf,
            vec![
                0x9, 0x52, 0x34, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd'
            ]
        );
    }

    #[test]
    fn test_write_eos_frame() {
        let mut buf = Vec::new();
        let frame = StreamFrame {
            id: VarInt::from_u32(0x1234).into(),
            offset: VarInt::from_u32(0x1234),
            length: 11,
            len_bit: Len::Explicit,
            fin_bit: Fin::Yes,
        };
        buf.put_data_frame(&frame, b"hello world");
        assert_eq!(
            buf,
            vec![
                0x0f, 0x52, 0x34, 0x52, 0x34, 0x0b, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o',
                b'r', b'l', b'd'
            ]
        );
    }

    #[test]
    fn test_write_unfinished_stream_frame() {
        let mut buf = Vec::new();
        let frame = StreamFrame {
            id: VarInt::from_u32(0x1234).into(),
            offset: VarInt::from_u32(0x1234),
            length: 11,
            len_bit: Len::Explicit,
            fin_bit: Fin::No,
        };
        buf.put_data_frame(&frame, b"hello world");
        assert_eq!(
            buf,
            vec![
                0x0e, 0x52, 0x34, 0x52, 0x34, 0x0b, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o',
                b'r', b'l', b'd'
            ]
        );
    }
}
