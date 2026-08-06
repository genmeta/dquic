use bytes::BufMut;
use nom::{
    Err, IResult,
    error::{Error, ErrorKind},
    number::streaming::be_u16,
};

use super::{Type as OuterType, WriteDatagramType, v0};
use crate::datagram::Error as DatagramError;

/// STUN message types supported by datagram version 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    BindingRequest,
    BindingResponse,
}

impl From<Type> for u8 {
    fn from(value: Type) -> u8 {
        match value {
            Type::BindingRequest => 0,
            Type::BindingResponse => 1,
        }
    }
}

impl TryFrom<u8> for Type {
    type Error = DatagramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Type::BindingRequest),
            1 => Ok(Type::BindingResponse),
            _ => Err(DatagramError::InvalidStunType),
        }
    }
}

const STUN_HEADER_BITS: u8 = 0b1100_0010;
const STUN_HEADER_MASK: u8 = 0b1111_1110;

pub fn be_stun_type(input: &[u8], first: u8) -> IResult<&[u8], Type> {
    if first & STUN_HEADER_MASK != STUN_HEADER_BITS {
        return Err(Err::Error(Error::new(input, ErrorKind::Verify)));
    }
    let ty =
        Type::try_from(first & 1).map_err(|_| Err::Error(Error::new(input, ErrorKind::Verify)))?;
    let (input, reserved) = be_u16(input)?;
    let (input, datagram_version) = be_u16(input)?;
    if reserved != 0 || datagram_version != 0 {
        return Err(Err::Error(Error::new(input, ErrorKind::Verify)));
    }
    Ok((input, ty))
}

pub trait WriteStunType: BufMut {
    fn put_stun_type(&mut self, ty: &Type);
}

impl<T: BufMut> WriteStunType for T {
    fn put_stun_type(&mut self, ty: &Type) {
        self.put_datagram_type(&OuterType::V0(v0::Type::Stun(*ty)));
    }
}
