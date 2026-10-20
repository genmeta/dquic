use derive_more::Deref;

/// Supports IQuic version 1, if other versions are supported in the future, add them here.
pub mod v1;

/// The long packet header contains version information, so the 32-bit
/// version number info is also one part of the versioned packet type.
///
/// `N`` represents an 32-bit version number, and
/// `Ty`` represents the specific type of the version.
#[derive(Debug, Clone, Copy, Deref, PartialEq, Eq)]
pub struct Version<const N: u32, Ty>(#[deref] pub(crate) Ty);

/// Long packet types all have a Version, so the version number can be obtained
/// from the long packet type.
pub trait GetVersion {
    /// Get the version number from long packet type.
    fn get_version(&self) -> u32;
}

impl<const N: u32, Ty> GetVersion for Version<N, Ty> {
    fn get_version(&self) -> u32 {
        N
    }
}

/// Mainly define the long packet types of the IQuic version 1.
impl Version<1, v1::Type> {
    /// Retry packet type of the IQuic version 1.
    pub const RETRY: Self = Self(v1::Type::Retry);
    /// Initial packet type of the IQuic version 1.
    pub const INITIAL: Self = Self(v1::Type::Initial);
    /// 0-RTT packet type of the IQuic version 1.
    pub const ZERO_RTT: Self = Self(v1::Type::ZeroRtt);
    /// Handshake packet type of the IQuic version 1.
    pub const HANDSHAKE: Self = Self(v1::Type::Handshake);
}

/// Represent the packet types in the IQuic version 1, including Retry/Initial/0-RTT/Handshake.
pub type Ver1 = Version<1, v1::Type>;

/// The sum types of the long packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    VersionNegotiation,
    V1(Version<1, v1::Type>),
    // in the future, add other versions here
    // V2(v2::HeaderType),
}

/// The io module provides the functions to parse and write the long packet type.
pub mod io {
    use bytes::BufMut;
    use nom::number::streaming::be_u32;

    use super::{super::FIXED_BIT, *};
    use crate::packet::error::Error;

    const LONG_HEADER_BIT: u8 = 0x80;

    /// Parse the long packet type from the input buffer,
    /// [nom](https://docs.rs/nom/latest/nom/) parser style.
    pub fn parse_long_type(ty: u8) -> impl FnMut(&[u8]) -> nom::IResult<&[u8], Type, Error> {
        move |input| {
            let (remain, version) = be_u32(input)?;
            match version {
                0 => Ok((remain, Type::VersionNegotiation)),
                1 => Ok((
                    remain,
                    Type::V1(Version::<1, v1::Type>(
                        ty.try_into().map_err(nom::Err::Error)?,
                    )),
                )),
                v => Err(nom::Err::Error(Error::UnsupportedVersion(v))),
            }
        }
    }

    /// A [`bytes::BufMut`] extension trait, makes buffer more friendly to write long packet type.
    pub trait WriteLongType: BufMut {
        /// Write the long packet type to the buffer.
        fn put_long_type(&mut self, value: &Type);
    }

    impl<B: BufMut> WriteLongType for B {
        fn put_long_type(&mut self, value: &Type) {
            match value {
                Type::VersionNegotiation => {
                    self.put_u8(LONG_HEADER_BIT);
                    self.put_u32(0);
                }
                Type::V1(Version::<1, _>(ty)) => {
                    let ty: u8 = (*ty).into();
                    self.put_u8(LONG_HEADER_BIT | FIXED_BIT | ty);
                    self.put_u32(1);
                }
            }
        }
    }
}
