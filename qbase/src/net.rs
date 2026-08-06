use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use bytes::BufMut;
use nom::{
    IResult, Parser,
    combinator::{flat_map, map},
    number::complete::{be_u16, be_u32, be_u128},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::frame::EncodeSize;

pub mod addr;
pub mod nat;
pub mod route;
pub mod tx;

pub use nat::{NatType, NetFeature};

/// IP protocol family
///
/// Represents IPv4 or IPv6 protocol family.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    /// IPv4 protocol family
    V4 = 0,
    /// IPv6 protocol family
    V6 = 1,
}

impl Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Family::V4 => write!(f, "v4"),
            Family::V6 => write!(f, "v6"),
        }
    }
}

impl From<u8> for Family {
    fn from(value: u8) -> Self {
        match value {
            0 => Family::V4,
            _ => Family::V6,
        }
    }
}

/// Invalid IP protocol family error
///
/// Returned when attempting to parse an unsupported IP protocol family string.
///
/// Supported values: `v4`, `V4`, `v6`, `V6`
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("Invalid address family")]
pub struct InvalidFamily;

impl FromStr for Family {
    type Err = InvalidFamily;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "v4" => Ok(Family::V4),
            "v6" => Ok(Family::V6),
            _ => Err(InvalidFamily),
        }
    }
}

pub trait AddrFamily {
    /// Get the IP protocol family
    ///
    /// Returns `IpFamily::V4` for IPv4 addresses and `IpFamily::V6` for IPv6 addresses.
    fn family(&self) -> Family;
}

impl AddrFamily for std::net::Ipv4Addr {
    fn family(&self) -> Family {
        Family::V4
    }
}

impl AddrFamily for std::net::Ipv6Addr {
    fn family(&self) -> Family {
        Family::V6
    }
}

impl AddrFamily for std::net::IpAddr {
    fn family(&self) -> Family {
        match self {
            std::net::IpAddr::V4(_) => Family::V4,
            std::net::IpAddr::V6(_) => Family::V6,
        }
    }
}

impl AddrFamily for std::net::SocketAddr {
    fn family(&self) -> Family {
        self.ip().family()
    }
}

pub trait WriteSocketAddr {
    fn put_socket_addr(&mut self, addr: &SocketAddr);
}

impl<T: BufMut> WriteSocketAddr for T {
    fn put_socket_addr(&mut self, addr: &SocketAddr) {
        self.put_u16(addr.port());
        match addr.ip() {
            IpAddr::V4(ipv4) => self.put_u32(ipv4.into()),
            IpAddr::V6(ipv6) => self.put_u128(ipv6.into()),
        }
    }
}

pub fn be_socket_addr(input: &[u8], family: Family) -> IResult<&[u8], SocketAddr> {
    flat_map(be_u16, |port| {
        map(be_ip_addr(family), move |ip| SocketAddr::new(ip, port))
    })
    .parse(input)
}

pub fn be_ip_addr(family: Family) -> impl Fn(&[u8]) -> IResult<&[u8], IpAddr> {
    move |input| match family {
        Family::V6 => map(be_u128, |ip| IpAddr::V6(Ipv6Addr::from(ip))).parse(input),
        Family::V4 => map(be_u32, |ip| IpAddr::V4(Ipv4Addr::from(ip))).parse(input),
    }
}

impl EncodeSize for SocketAddr {
    fn max_encoding_size(&self) -> usize {
        2 + 16 // IPv6 address
    }

    fn encoding_size(&self) -> usize {
        match self.ip() {
            IpAddr::V4(_) => 2 + 4,
            IpAddr::V6(_) => 2 + 16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_family_display_and_parse() {
        assert_eq!(Family::V4.to_string(), "v4");
        assert_eq!(Family::V6.to_string(), "v6");

        assert_eq!("v4".parse::<Family>().unwrap(), Family::V4);
        assert_eq!("V4".parse::<Family>().unwrap(), Family::V4);
        assert_eq!("v6".parse::<Family>().unwrap(), Family::V6);
        assert_eq!("V6".parse::<Family>().unwrap(), Family::V6);

        assert!(matches!("v7".parse::<Family>(), Err(InvalidFamily)));
    }
}
