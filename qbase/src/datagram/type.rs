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
