use bytes::BufMut;
use nom::{
    Err,
    error::{Error, ErrorKind},
    number::streaming::{be_u8, be_u32},
};

use self::v0::WriteV0Type;

pub mod stun;
pub mod v0;

const HEADER_FORM_BIT: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
const FORWARD_BIT: u8 = 0x20;
const LONG_TYPE_MASK: u8 = 0x3f;

/// The outer type of a UDP datagram.
///
/// Raw datagrams have no dquic envelope and therefore consume no type bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Raw,
    V0(v0::Type),
}

/// Returns the datagram type represented by a value.
pub trait GetDatagramType {
    fn get_datagram_type(&self) -> Type;
}

/// Parses the dquic type prefix.
///
/// Ordinary QUIC packets are returned as [`Type::Raw`] without consuming any
/// input. Invalid fixed bits, conflicting extension bits, and unsupported
/// datagram versions are rejected.
pub fn be_datagram_type(input: &[u8]) -> nom::IResult<&[u8], Type> {
    let original = input;
    let (input, first) = be_u8(input)?;
    if first & FIXED_BIT == 0 {
        return Err(Err::Error(Error::new(original, ErrorKind::Verify)));
    }

    if first & HEADER_FORM_BIT == 0 {
        if first & FORWARD_BIT == 0 {
            return Ok((original, Type::Raw));
        }

        let (input, ty) = v0::be_forward_type(input, first)?;
        Ok((input, Type::V0(ty)))
    } else {
        let (input, quic_version) = be_u32(input)?;
        if quic_version != 0 || first & LONG_TYPE_MASK == 0 {
            return Ok((original, Type::Raw));
        }

        let (input, ty) = stun::be_stun_type(input, first)?;
        Ok((input, Type::V0(v0::Type::Stun(ty))))
    }
}

/// A [`BufMut`] extension for writing a datagram type.
///
/// Long STUN types include the four-byte QUIC version, two fixed zero bytes, and
/// the two-byte datagram version. A Forward type writes its two-byte type prefix.
pub trait WriteDatagramType: BufMut {
    fn put_datagram_type(&mut self, ty: &Type);
}

impl<T: BufMut> WriteDatagramType for T {
    fn put_datagram_type(&mut self, ty: &Type) {
        if let Type::V0(ty) = ty {
            self.put_v0_type(ty);
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::{stun, v0, *};
    use crate::net::{Family, addr::Kind};

    fn round_trip_long(ty: Type, expected: &[u8]) {
        let mut bytes = BytesMut::new();
        bytes.put_datagram_type(&ty);
        assert_eq!(bytes, expected);

        bytes.extend_from_slice(&[0xaa, 0xbb]);
        let (remain, decoded) = be_datagram_type(&bytes).unwrap();
        assert_eq!(decoded, ty);
        assert_eq!(remain, [0xaa, 0xbb]);
    }

    #[test]
    fn stun_uses_the_low_two_long_header_bits() {
        round_trip_long(
            Type::V0(v0::Type::Stun(stun::Type::BindingRequest)),
            &[0b1100_0010, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        round_trip_long(
            Type::V0(v0::Type::Stun(stun::Type::BindingResponse)),
            &[0b1100_0011, 0, 0, 0, 0, 0, 0, 0, 0],
        );
    }

    #[test]
    fn forward_uses_a_short_v0_type_byte() {
        let cases = [
            (Family::V4, Kind::Direct, Kind::Direct, 0b0000_1000),
            (Family::V6, Kind::Direct, Kind::Direct, 0b0000_1100),
            (Family::V4, Kind::Mediate, Kind::Direct, 0b0000_1010),
            (Family::V4, Kind::Direct, Kind::Mediate, 0b0000_1001),
        ];
        for (family, source, destination, byte) in cases {
            let ty = Type::V0(v0::Type::Forward(family, source, destination));
            let mut bytes = BytesMut::new();
            bytes.put_datagram_type(&ty);
            assert_eq!(bytes[0] & 0b1110_0000, 0b0110_0000);
            assert_eq!(bytes[1], byte);

            bytes.extend_from_slice(&[0xaa, 0xbb]);
            let (remain, decoded) = be_datagram_type(&bytes).unwrap();
            assert_eq!(decoded, ty);
            assert_eq!(remain, [0xaa, 0xbb]);
        }
    }

    #[test]
    fn non_v0_long_datagram_remains_raw() {
        let input = [0xe0, 0, 0, 0, 1, 0xaa, 0xbb];
        let (remain, ty) = be_datagram_type(&input).unwrap();
        assert_eq!(ty, Type::Raw);
        assert_eq!(remain, input);
    }

    #[test]
    fn version_negotiation_datagram_remains_raw() {
        let input = [0b1100_0000, 0, 0, 0, 0, 0xaa, 0xbb];
        let (remain, ty) = be_datagram_type(&input).unwrap();
        assert_eq!(ty, Type::Raw);
        assert_eq!(remain, input);
    }

    #[test]
    fn invalid_fixed_bit_is_rejected() {
        assert!(be_datagram_type(&[0b0010_0000, 0]).is_err());
        assert!(be_datagram_type(&[0b1010_0000, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn invalid_short_type_is_rejected() {
        assert!(be_datagram_type(&[0b0110_0000, 0b0001_1000]).is_err());
        assert!(be_datagram_type(&[0b0110_0000, 0b0000_0000]).is_err());
    }

    #[test]
    fn conflicting_long_type_bits_are_rejected() {
        for first in [0b1110_0000, 0b1110_0010, 0b1101_0000, 0b1100_0001] {
            let input = [first, 0, 0, 0, 0, 0, 0, 0, 0];
            assert!(be_datagram_type(&input).is_err());
        }
    }

    #[test]
    fn invalid_long_v0_suffix_is_rejected() {
        assert!(be_datagram_type(&[0xe0, 0, 0, 0, 0, 0, 1, 0, 0]).is_err());
        assert!(be_datagram_type(&[0xe0, 0, 0, 0, 0, 0, 0, 0, 1]).is_err());
    }

    #[test]
    fn truncated_type_is_incomplete() {
        assert!(matches!(
            be_datagram_type(&[0xe0, 0, 0, 0]),
            Err(nom::Err::Incomplete(_))
        ));
        assert!(matches!(
            be_datagram_type(&[0b0110_0000]),
            Err(nom::Err::Incomplete(_))
        ));
    }
}
