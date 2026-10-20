use std::{cmp::Ordering, convert::TryFrom, fmt};

/// An integer less than 2^62
///
/// Values of this type are suitable for encoding as QUIC variable-length integer.
/// It would be neat if we could express to Rust that the top two bits are available for use as enum
/// discriminants
///
/// See [variable-length integers](https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VarInt(u64);

/// The maximum value that can be represented by a QUIC variable-length integer.
pub const VARINT_MAX: u64 = 0x3fff_ffff_ffff_ffff;

/// The number of bytes that a QUIC variable-length integer can be encoded in.
///
/// [`VarInt`] doesn't need to be encoded on the minimum number of bytes necessary,
/// with the sole exception of the Frame Type field.
pub enum EncodeBytes {
    One = 1,
    Two = 2,
    Four = 4,
    Eight = 8,
}

impl VarInt {
    /// The largest representable value
    pub const MAX: Self = Self(VARINT_MAX);
    /// The largest encoded value length
    pub const MAX_SIZE: usize = 8;

    /// Construct a `VarInt` from a [`u32`].
    pub const fn from_u32(x: u32) -> Self {
        Self(x as u64)
    }

    /// Construct a `VarInt` from a [`u64`].
    /// Succeeds if `x` < 2^62.
    pub const fn from_u64(x: u64) -> Result<Self, err::Overflow> {
        if x < (1 << 62) {
            Ok(Self(x))
        } else {
            Err(err::Overflow(x as _))
        }
    }

    /// Create a VarInt from a [`u64`] without ensuring it's in range
    ///
    /// # Safety
    ///
    /// `x` must be less than 2^62.
    pub unsafe fn from_u64_unchecked(x: u64) -> Self {
        Self(x)
    }

    /// Construct a `VarInt` from a [`u128`].
    /// Succeeds if `x` < 2^62.
    pub fn from_u128(x: u128) -> Result<Self, err::Overflow> {
        if x < (1 << 62) {
            Ok(Self(x as _))
        } else {
            Err(err::Overflow(x))
        }
    }

    /// Extract the integer value
    pub fn into_u64(self) -> u64 {
        self.0
    }

    /// Compute the number of bytes needed to encode this value
    pub fn encoding_size(self) -> usize {
        let x = self.0;
        if x < (1 << 6) {
            1
        } else if x < (1 << 14) {
            2
        } else if x < (1 << 30) {
            4
        } else if x < (1 << 62) {
            8
        } else {
            unreachable!("malformed VarInt");
        }
    }
}

impl From<VarInt> for u64 {
    fn from(x: VarInt) -> Self {
        x.0
    }
}

impl From<u8> for VarInt {
    fn from(x: u8) -> Self {
        Self(x.into())
    }
}

impl From<u16> for VarInt {
    fn from(x: u16) -> Self {
        Self(x.into())
    }
}

impl From<u32> for VarInt {
    fn from(x: u32) -> Self {
        Self(x.into())
    }
}

impl TryFrom<u128> for VarInt {
    type Error = err::Overflow;

    fn try_from(x: u128) -> Result<Self, Self::Error> {
        Self::from_u128(x)
    }
}

impl TryFrom<u64> for VarInt {
    type Error = err::Overflow;

    /// Succeeds if `x` < 2^62
    fn try_from(x: u64) -> Result<Self, Self::Error> {
        Self::from_u64(x)
    }
}

impl TryFrom<usize> for VarInt {
    type Error = err::Overflow;

    /// Succeeds if `x` < 2^62
    fn try_from(x: usize) -> Result<Self, Self::Error> {
        Self::try_from(x as u64)
    }
}

impl nom::ToUsize for VarInt {
    fn to_usize(&self) -> usize {
        self.0 as usize
    }
}

impl PartialEq<u64> for VarInt {
    fn eq(&self, other: &u64) -> bool {
        self.0.eq(other)
    }
}

impl PartialOrd<u64> for VarInt {
    fn partial_cmp(&self, other: &u64) -> Option<Ordering> {
        self.0.partial_cmp(other)
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Error module for VarInt
pub mod err {
    use std::fmt::Debug;

    use thiserror::Error;

    /// Overflow error indicating that a value exceeds 2^62
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
    #[error("Value({0}) too large for varint encoding")]
    pub struct Overflow(pub(super) u128);
}

use bytes::BufMut;
use nom::{IResult, Parser, bits::streaming::take, combinator::flat_map, error::Error};

/// Parse a variable-length integer from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
///
/// ## Example
/// ```
/// use qbase::varint::be_varint;
///
/// let input = &[0b01000000, 0x01][..];
/// let result = be_varint(input);
/// assert_eq!(result, Ok((&[][..], 1u32.into())));
/// ```
pub fn be_varint(input: &[u8]) -> IResult<&[u8], VarInt> {
    flat_map(take(2usize), |prefix: u8| {
        take::<&[u8], u64, usize, Error<(&[u8], usize)>>((8 << prefix) - 2)
    })
    .parse((input, 0))
    .map_err(|err| match err {
        nom::Err::Incomplete(needed) => {
            nom::Err::Incomplete(needed.map(|n| n.get().div_ceil(8) - input.len()))
        }
        _ => unreachable!(),
    })
    .map(|((buf, _), value)| (buf, VarInt(value)))
}

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly to write VarInt.
pub trait WriteVarInt: BufMut {
    /// Write a variable-length integer.
    ///
    /// `put_varint` will write the smallest number of bytes needed to represent the value.
    /// `encode_varint` will write the specified number of bytes, and panic if the specified number of bytes
    /// is less than the smallest number of bytes needed to repressent the value.
    ///
    /// # Example
    /// ```rust
    /// use bytes::BufMut;
    /// use qbase::varint::{EncodeBytes, VarInt, WriteVarInt};
    ///
    /// let val = VarInt::from_u32(1);
    /// let mut encode_buf = [0u8; 8];
    ///
    /// let mut buf = &mut encode_buf[..];
    /// buf.put_varint(&val);
    /// assert_eq!(buf.len(), 7);
    /// assert_eq!(encode_buf[0..1], [0x01]);
    ///
    /// let mut buf = &mut encode_buf[..];
    /// buf.encode_varint(&val, EncodeBytes::Two);
    /// assert_eq!(buf.len(), 6);
    /// assert_eq!(encode_buf[0..2], [0x40, 0x01]);
    /// ```
    fn put_varint(&mut self, value: &VarInt);

    /// Write a variable-length integer with specified number of bytes.
    fn encode_varint(&mut self, value: &VarInt, nbytes: EncodeBytes);
}

// 所有的BufMut都可以调用put_varint来写入VarInt了
impl<T: BufMut> WriteVarInt for T {
    fn put_varint(&mut self, value: &VarInt) {
        let x = value.0;
        if x < 1u64 << 6 {
            self.put_u8(x as u8);
        } else if x < 1u64 << 14 {
            self.put_u16((0b01 << 14) | x as u16);
        } else if x < 1u64 << 30 {
            self.put_u32((0b10 << 30) | x as u32);
        } else if x < 1u64 << 62 {
            self.put_u64((0b11 << 62) | x);
        } else {
            unreachable!("malformed VarInt")
        }
    }

    fn encode_varint(&mut self, value: &VarInt, nbytes: EncodeBytes) {
        match nbytes {
            EncodeBytes::One => {
                assert!(value.0 < 1u64 << 6);
                self.put_u8(value.0 as u8);
            }
            EncodeBytes::Two => {
                assert!(value.0 < 1u64 << 14);
                self.put_u16((0b01 << 14) | value.0 as u16);
            }
            EncodeBytes::Four => {
                assert!(value.0 < 1u64 << 30);
                self.put_u32((0b10 << 30) | value.0 as u32);
            }
            EncodeBytes::Eight => {
                assert!(value.0 < 1u64 << 62);
                self.put_u64((0b11 << 62) | value.0);
            }
        }
    }
}
