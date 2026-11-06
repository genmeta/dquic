use std::io;

use crate::varint::VarInt;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NetFeature: u8 {
        const Blocked = 0x01;
        const Public = 0x02;
        const Restricted = 0x04;
        const PortRestricted = 0x08;
        const Symmetric = 0x10;
        const Dynamic = 0x20;
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum NatType {
    Blocked = 0x00,
    FullCone = 0x01,
    RestrictedCone = 0x02,
    RestrictedPort = 0x03,
    Symmetric = 0x04,
    Dynamic = 0x05,
}

impl From<NatType> for VarInt {
    fn from(nat_type: NatType) -> Self {
        VarInt::from(nat_type as u8)
    }
}

impl TryFrom<u8> for NatType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(NatType::Blocked),
            0x01 => Ok(NatType::FullCone),
            0x02 => Ok(NatType::RestrictedCone),
            0x03 => Ok(NatType::RestrictedPort),
            0x04 => Ok(NatType::Symmetric),
            0x05 => Ok(NatType::Dynamic),
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid value for NatType")),
        }
    }
}

impl TryFrom<VarInt> for NatType {
    type Error = io::Error;

    fn try_from(value: VarInt) -> Result<Self, Self::Error> {
        Self::try_from(value.into_u64() as u8)
    }
}

impl From<NetFeature> for NatType {
    fn from(value: NetFeature) -> Self {
        if value.contains(NetFeature::Blocked) {
            NatType::Blocked
        } else if value.contains(NetFeature::Symmetric) {
            NatType::Symmetric
        } else if value.contains(NetFeature::Dynamic) {
            NatType::Dynamic
        } else if value.contains(NetFeature::PortRestricted) {
            NatType::RestrictedPort
        } else if value.contains(NetFeature::Restricted) {
            NatType::RestrictedCone
        } else {
            NatType::FullCone
        }
    }
}
