use std::cmp::max;

use bytes::BufMut;
use thiserror::Error;

/// An encoded or undecoded packet number
///
/// The actual packet number is an integer in the range 0 to 2^62  - 1 and encoded in 1 to 4 bytes.
///
/// See [packet numbers](https://www.rfc-editor.org/rfc/rfc9000.html#name-packet-numbers) and
/// [packet number encoding and decoding](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.1)
/// of [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PacketNumber {
    U8(u8),
    U16(u16),
    U24(u32),
    U32(u32),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InvalidPacketNumber {
    #[error("Packet number too old")]
    TooOld,
    #[error("Packet number too large")]
    TooLarge,
    #[error("Packet with this number has been received")]
    Duplicate,
}

/// Implement this trait for buffer, which can be used to write the packet number into the buffer.
pub trait WritePacketNumber {
    /// Write the encoded packet number to the buffer.
    fn put_packet_number(&mut self, pn: PacketNumber);
}

impl<T: BufMut> WritePacketNumber for T {
    fn put_packet_number(&mut self, pn: PacketNumber) {
        use self::PacketNumber::*;
        match pn {
            U8(x) => self.put_u8(x),
            U16(x) => self.put_u16(x),
            U24(x) => {
                self.put_u8((x >> 16) as u8);
                self.put_u16(x as u16);
            }
            U32(x) => self.put_u32(x),
        }
    }
}

/// Parse the packet number from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
///
/// ## Example
///
/// ```
/// use qbase::packet::number::{PacketNumber, take_pn_len};
///
/// let buf = [0x01, 0x00];
/// assert_eq!(
///     (&[][..], PacketNumber::U16(1 << 8)),
///     take_pn_len(2)(&buf).unwrap()
/// );
/// ```
pub fn take_pn_len(pn_len: u8) -> impl FnMut(&[u8]) -> nom::IResult<&[u8], PacketNumber> {
    use nom::{
        Parser,
        combinator::map,
        number::complete::{be_u8, be_u16, be_u24, be_u32},
    };
    move |input: &[u8]| match pn_len {
        1 => map(be_u8, PacketNumber::U8).parse(input),
        2 => map(be_u16, PacketNumber::U16).parse(input),
        3 => map(be_u24, PacketNumber::U24).parse(input),
        4 => map(be_u32, PacketNumber::U32).parse(input),
        _ => unreachable!(),
    }
}

impl PacketNumber {
    /// Encode the packet number, based on the maximum confirmed packet number.
    ///
    /// The size of the packet number encoding is at least one bit more than the
    /// base-2 logarithm of the number of contiguous unacknowledged packet numbers
    ///
    /// See [Section 17.1-5](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.1-5) and
    /// [Appendix A.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-a.2)
    /// for more details.
    pub fn encode(pn: u64, largest_acked: u64) -> Self {
        // Minimum 16-bit PN encoding ensures delayed packets on slower paths remain decodable
        let range = max((pn - largest_acked) * 2, (1 << 16) - 1);
        if range < 1 << 8 {
            Self::U8(pn as u8)
        } else if range < 1 << 16 {
            Self::U16(pn as u16)
        } else if range < 1 << 24 {
            Self::U24(pn as u32)
        } else if range < 1 << 32 {
            Self::U32(pn as u32)
        } else {
            panic!("packet number too large to encode")
        }
    }

    /// Return the size of the packet number encoding.
    pub fn size(self) -> usize {
        use self::PacketNumber::*;
        match self {
            U8(_) => 1,
            U16(_) => 2,
            U24(_) => 3,
            U32(_) => 4,
        }
    }

    /// Decode the packet number after header protection has been removed.
    ///
    /// The packet number is decoded based on the largest received packet number.
    /// The next expected packet is the largest received packet number plus one.
    ///
    /// See [Section 17.1-7](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.1-7) and
    /// [Section A.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-a.3)
    /// for more details.
    pub fn decode(self, expected: u64) -> u64 {
        use self::PacketNumber::*;

        let (truncated, nbits) = match self {
            U8(x) => (u64::from(x), 8),
            U16(x) => (u64::from(x), 16),
            U24(x) => (u64::from(x), 24),
            U32(x) => (u64::from(x), 32),
        };
        let win = 1 << nbits;
        let hwin = win / 2;
        let mask = win - 1;
        // The incoming packet number should be greater than expected - hwin and less than or equal
        // to expected + hwin
        //
        // This means we can't just strip the trailing bits from expected and add the truncated
        // because that might yield a value outside the window.
        //
        // The following code calculates a candidate value and makes sure it's within the packet
        // number window.
        let candidate = (expected & !mask) | truncated;
        if expected.checked_sub(hwin).is_some_and(|x| candidate <= x) {
            candidate + win
        } else if candidate > expected + hwin && candidate > win {
            candidate - win
        } else {
            candidate
        }
    }
}
