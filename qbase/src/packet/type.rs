use derive_more::Deref;

use super::{KeyPhaseBit, PacketNumber, error::Error};

/// Definitions of packet types related to long headers
pub mod long;
/// Definitions of packet types related to short headers
pub mod short;

/// Header form bit
const HEADER_FORM_MASK: u8 = 0x80;
/// The next bit (0x40) of byte 0 is set to 1, unless the packet is a Version Negotiation packet.
const FIXED_BIT: u8 = 0x40;

/// Reserved bits mask for long headers, for the 5th and 6th bits of the first byte of the long header
pub const LONG_RESERVED_MASK: u8 = 0x0C;
/// Reserved bits mask for short headers, for the 4th and 5th bits of the first byte of the short header
pub const SHORT_RESERVED_MASK: u8 = 0x18;

/// The lower specific bits of the first byte of the long or short header.
/// 'R' represents the reserved bits.
///
/// - For long packet headers, it is the lower 4 bits of the first byte, and R is 0x0C.
/// - For the short packet header, it is the lower 5 bits of the first byte, and R is 0x18.
#[derive(Debug, Clone, Copy, Deref)]
pub struct SpecificBits<const R: u8>(pub(super) u8);

/// The lower 4 bits of the first byte of the long header.
///
/// Include 2 reserved bits that must be 0, and 2 bits for the packet number length.
/// All of them are protected.
pub type LongSpecificBits = SpecificBits<LONG_RESERVED_MASK>;
/// The lower 5 bits of the first byte of the short header, i.e., the last 5 bits.
///
/// Include 2 reserved bits that must be 0, 1 bit for the key phase,
/// and 2 bits for the packet number length.
/// All of them are protected.
pub type ShortSpecificBits = SpecificBits<SHORT_RESERVED_MASK>;

impl<const R: u8> SpecificBits<R> {
    /// Create a [`SpecificBits`] with the [`PacketNumber`].
    pub fn from_pn(pn: &PacketNumber) -> Self {
        Self(pn.size() as u8 - 1)
    }

    /// Create a [`SpecificBits`] with the packet number length.
    pub fn with_pn_len(pn_size: usize) -> Self {
        debug_assert!(pn_size <= 4 && pn_size > 0);
        Self(pn_size as u8 - 1)
    }
}

impl ShortSpecificBits {
    /// Set the Key Phase bit to the specific bits for 1rtt header.
    pub fn set_key_phase(&mut self, key_phase_bit: KeyPhaseBit) {
        key_phase_bit.imply(&mut self.0);
    }

    /// Get the Key Phase bit from the specific bits of 1rtt header.
    pub fn key_phase(&self) -> KeyPhaseBit {
        KeyPhaseBit::from(self.0)
    }
}

impl<const R: u8> From<u8> for SpecificBits<R> {
    fn from(byte: u8) -> Self {
        Self(byte)
    }
}

/// Get the packet number length from the protected first byte of the long or short header.
/// The reserved bits must be 0; otherwise, a connection error of type PROTOCOL_VIOLATION
/// is returned.
///
/// See [Section 17.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-8.2) and
/// [Section 17.3.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1-4.8) of QUIC.
pub trait GetPacketNumberLength {
    /// The last two bits of first byte contain the length of the Packet Number
    const PN_LEN_MASK: u8 = 0x03;

    /// Get the encoding length of the Packet Number
    fn pn_len(&self) -> Result<u8, Error>;
}

impl<const R: u8> GetPacketNumberLength for SpecificBits<R> {
    fn pn_len(&self) -> Result<u8, Error> {
        let reserved_bit = self.0 & R;
        if reserved_bit == 0 {
            Ok((self.0 & Self::PN_LEN_MASK) + 1)
        } else {
            Err(Error::InvalidReservedBits(reserved_bit, R))
        }
    }
}

/// The Type of the packet
///
/// The Type is only extracted from the first 3 or 4 bits of the first byte, these contents
/// are not protected.
/// For simplicity and future-oriented considerations, the Version of the long packet header
/// is also considered part of the Type, such as the Initial packet of V1 version,
/// That is, the Initial packet only makes sense under the V1 version, and it is uncertain
/// whether future versions of QUIC will still have Initial packets.
/// The SpinBit of the short packet header should be part of the short packet header, but for
/// simplicity, the SpinBit is also part of the 1RTT header type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Long(long::Type),
    Short(short::OneRtt),
}

impl Type {
    #[inline]
    pub fn encoding_size(&self) -> usize {
        match self {
            Type::Short(_) => 1,
            Type::Long(_) => 5,
        }
    }
}

/// The io module provides the functions to parse and write the packet type.
pub mod io {
    use bytes::BufMut;

    use super::{long::io::WriteLongType, short::WriteShortType, *};

    /// Parse the packet type from the input buffer,
    /// [nom](https://docs.rs/nom/latest/nom/) parser style.
    pub fn be_packet_type(input: &[u8]) -> nom::IResult<&[u8], Type, Error> {
        let (remain, ty) = nom::number::streaming::be_u8(input)?;
        if ty & HEADER_FORM_MASK == 0 {
            Ok((remain, Type::Short(short::OneRtt::from(ty))))
        } else {
            let (remain, ty) = long::io::parse_long_type(ty)(remain)?;
            Ok((remain, Type::Long(ty)))
        }
    }

    /// A [`bytes::BufMut`] extension trait, makes buffer more friendly to write packet type.
    pub trait WritePacketType: BufMut {
        /// Write the packet type to the buffer.
        fn put_packet_type(&mut self, ty: &Type);
    }

    impl<B: BufMut> WritePacketType for B {
        fn put_packet_type(&mut self, ty: &Type) {
            match ty {
                Type::Short(one_rtt) => self.put_short_type(one_rtt),
                Type::Long(long_type) => self.put_long_type(long_type),
            }
        }
    }
}
