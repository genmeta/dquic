use bytes::BufMut;
use nom::{
    Err, IResult,
    error::{Error, ErrorKind},
    number::streaming::be_u8,
};
use rand::RngExt;

use super::stun;
use crate::net::{Family, addr::Kind};

const LONG_HEADER_BITS: u8 = 0b1100_0000;
const FORWARD_HEADER_BITS: u8 = 0b0110_0000;
const FORWARD_HEADER_MASK: u8 = 0b1110_0000;
const FORWARD_REMAIN_MASK: u8 = 0b0001_1111;

/// Datagram types defined by version 0.
///
/// The long STUN type byte uses its low six bits as follows. Forward, Family,
/// and endpoint kinds must all be zero.
///
/// ```text
/// +---------+--------+----------+----------+------+-----------+
/// |    0    |    0   |     0    |     0    |  1   | STUN Type |
/// +---------+--------+----------+----------+------+-----------+
/// ```
///
/// A Forward type uses a short-header marker byte followed by its version/type
/// byte:
///
/// ```text
/// +-----+-------+---------------------------------------+
/// | 011 | Random remain bits (5)                        |
/// +-----+-------+---------------------------------------+
/// | Version (4) | Forward | Family | Src Kind | Dst Kind |
/// +-------------+---------+--------+----------+----------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Stun(stun::Type),
    Forward(Family, Kind, Kind),
}

pub trait WriteV0Type: BufMut {
    fn put_v0_type(&mut self, ty: &Type);
}

impl<T: BufMut> WriteV0Type for T {
    fn put_v0_type(&mut self, ty: &Type) {
        match *ty {
            Type::Stun(ty) => {
                self.put_u8(LONG_HEADER_BITS | (1 << 1) | u8::from(ty));
                self.put_u32(0);
                self.put_u16(0);
                self.put_u16(0);
            }
            Type::Forward(family, src, dst) => {
                let mut random = [0];
                rand::rng().fill(&mut random);
                self.put_u8(FORWARD_HEADER_BITS | (random[0] & FORWARD_REMAIN_MASK));
                self.put_u8((1 << 3) | (family as u8) << 2 | (src as u8) << 1 | dst as u8);
            }
        }
    }
}

pub(super) fn be_forward_type(input: &[u8], first: u8) -> IResult<&[u8], Type> {
    if first & FORWARD_HEADER_MASK != FORWARD_HEADER_BITS {
        return Err(Err::Error(Error::new(input, ErrorKind::Verify)));
    }
    let (input, encoded) = be_u8(input)?;
    if encoded >> 4 != 0 || matches!(encoded & 0b0000_1000, 0) {
        return Err(Err::Error(Error::new(input, ErrorKind::Verify)));
    }
    Ok((
        input,
        Type::Forward(
            Family::from(encoded & 0b0100),
            Kind::from(encoded & 0b0010),
            Kind::from(encoded & 0b0001),
        ),
    ))
}
