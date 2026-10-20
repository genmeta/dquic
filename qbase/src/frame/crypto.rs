use std::ops::Range;

use nom::Parser;

use crate::{
    frame::{GetFrameType, io::WriteFrameType},
    util::{Buffer, WriteData},
    varint::{VARINT_MAX, VarInt, WriteVarInt, be_varint},
};

/// CRYPTO Frame
///
/// ```text
/// CRYPTO Frame {
///   Type (i) = 0x06,
///   Offset (i),
///   Length (i),
///   Crypto Data (..),
/// }
/// ```
///
/// See [crypto frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-crypto-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoFrame {
    offset: VarInt,
    length: VarInt,
}

impl super::GetFrameType for CryptoFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Crypto
    }
}

impl super::EncodeSize for CryptoFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.offset.encoding_size() + self.length.encoding_size()
    }
}

impl CryptoFrame {
    /// Create a new [`CryptoFrame`] with the given offset and length.
    pub fn new(offset: VarInt, length: VarInt) -> Self {
        Self { offset, length }
    }

    /// Return the offset of the frame.
    pub fn offset(&self) -> u64 {
        self.offset.into_u64()
    }

    /// Return the length of the frame.
    pub fn len(&self) -> u64 {
        self.length.into_u64()
    }

    /// Evaluate the maximum number of bytes of data that can be accommodated,
    /// starting from a certain offset, within a given capacity. If it cannot
    /// accommodate a CryptoFrame header or can only accommodate 0 bytes, return None.
    ///
    /// Note: Panic if the offset exceeds 2^62-1, or the the capacity is too large
    /// (about 2^32. It is impossible to have so much crypto stream data)
    pub fn estimate_max_capacity(capacity: usize, offset: u64) -> Option<usize> {
        assert!(offset <= VARINT_MAX);
        capacity
            // Must accommodate at least one byte, 'len' takes up 1 byte,
            // content takes up 1 byte. If these are not satisfied, return None.
            .checked_sub(1 + VarInt::from_u64(offset).unwrap().encoding_size() + 2)
            .map(|remaining| match remaining {
                // Including the 1 byte already considered in check_sub,
                // 'length' still takes up 1 byte.
                value @ 0..=62 => value + 1,
                // The encoding of 'length' directly takes up 2 bytes, the final 2 bytes
                // subtracted in 'check_sub' are all occupied by the encoding of 'length'.
                // Interestingly, if only 65 bytes are left after removing the encoding of
                // Type and Offset, whether the encoding of 'length' takes up 1 byte or 2
                // bytes, only 63 bytes of data can be carried.
                value @ 0x3F..=0x3F_FF => value,
                // For the following lengths, the encoding of 'length' needs to occupy 4 bytes.
                // When the buffer capacity is 0x4000 or 0x40001, the encoding of 'length'
                // changes to 4 bytes, but the capacity is not enough, so it needs to be rolled back.
                0x40_00..=0x40_01 => 0x3FFF,
                value @ 0x40_02..=0x40_00_00_01 => value - 2,
                // Any longer, a packet exceeding 100 million bytes is already impossible.
                _ => unreachable!("crypto frame length could not be too large"),
            })
    }

    /// Return the range of bytes that this frame covers.
    pub fn range(&self) -> Range<u64> {
        let start = self.offset.into_u64();
        let end = start + self.length.into_u64();
        start..end
    }
}

/// Parse a CRYPTO frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_crypto_frame(input: &[u8]) -> nom::IResult<&[u8], CryptoFrame> {
    let (remain, (offset, length)) = (be_varint, be_varint).parse(input)?;
    if offset.into_u64() + offset.into_u64() > VARINT_MAX {
        return Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::TooLarge,
        )));
    }
    Ok((remain, CryptoFrame { offset, length }))
}

impl<T, D> super::io::WriteDataFrame<CryptoFrame, D> for T
where
    T: bytes::BufMut + WriteData<D>,
    D: Buffer,
{
    fn put_data_frame(&mut self, frame: &CryptoFrame, data: &D) {
        assert_eq!(frame.length.into_u64(), data.len() as u64);
        self.put_frame_type(frame.frame_type());
        self.put_varint(&frame.offset);
        self.put_varint(&frame.length);
        self.put_data(data);
    }
}

#[cfg(test)]
mod tests {
    use super::CryptoFrame;
    use crate::varint::VarInt;

    #[test]
    fn test_read_crypto_frame() {
        use super::be_crypto_frame;
        let buf = vec![0x52, 0x34, 0x80, 0x00, 0x56, 0x78];
        let (remain, frame) = be_crypto_frame(&buf).unwrap();
        assert_eq!(remain, &[]);
        assert_eq!(
            frame,
            CryptoFrame::new(VarInt::from_u32(0x1234), VarInt::from_u32(0x5678))
        );
    }
}
