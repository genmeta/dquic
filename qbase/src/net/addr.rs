use std::{
    fmt::Display,
    net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Deref,
    str::FromStr,
};

use bytes::BufMut;
use serde::{Deserialize, Serialize};

use crate::net::{Family, be_socket_addr};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Direct = 0,
    Mediate = 1,
}

impl From<u8> for Kind {
    fn from(value: u8) -> Self {
        match value {
            0 => Kind::Direct,
            _ => Kind::Mediate,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndpointAddr {
    Direct {
        addr: SocketAddr,
    },
    Mediate {
        agent: SocketAddr,
        outer: SocketAddr,
    },
}

fn is_publicly_reachable_ipv4(addr: Ipv4Addr) -> bool {
    let [first, second, third, fourth] = addr.octets();

    !(first == 0
        || addr.is_private()
        || first == 100 && (64..=127).contains(&second)
        || addr.is_loopback()
        || addr.is_link_local()
        || first == 192 && second == 0 && third == 0 && !matches!(fourth, 9 | 10)
        || addr.is_documentation()
        || first == 192 && second == 88 && third == 99
        || first == 198 && matches!(second, 18 | 19)
        || addr.is_multicast()
        || first >= 240)
}

fn is_publicly_reachable_ipv6(addr: Ipv6Addr) -> bool {
    let segments = addr.segments();

    if matches!(segments, [0x0064, 0xff9b, 0, 0, 0, 0, _, _]) {
        return true;
    }

    // IPv6 global unicast addresses are allocated from 2000::/3. Prefixes outside it are not
    // publicly reachable unless IANA explicitly designates them, as with 64:ff9b::/96 above.
    if segments[0] & 0xe000 != 0x2000 {
        return false;
    }

    match segments {
        [0x2001, second, third, fourth, fifth, sixth, seventh, eighth] if second < 0x0200 => {
            matches!(
                (second, third, fourth, fifth, sixth, seventh, eighth),
                (1, 0, 0, 0, 0, 0, 1..=3)
            ) || second == 3
                || second == 4 && third == 0x0112
                || (0x20..=0x3f).contains(&second)
        }
        [0x2001, 0x0db8, _, _, _, _, _, _] | [0x2002, _, _, _, _, _, _, _] => false,
        [0x3fff, second, _, _, _, _, _, _] if second & 0xf000 == 0 => false,
        _ => true,
    }
}

impl EndpointAddr {
    pub fn direct(addr: SocketAddr) -> Self {
        EndpointAddr::Direct { addr }
    }

    pub fn with_agent(agent: SocketAddr, outer: SocketAddr) -> Self {
        EndpointAddr::Mediate { agent, outer }
    }

    /// Returns the outer addr of this EndpointAddr
    ///
    /// Note: Before successful hole punching with this Endpoint, packets should be sent to the addr
    /// returned by deref() to establish communication. Once hole punching is successful or about to
    /// begin, use the addr returned by this function.
    pub fn addr(&self) -> SocketAddr {
        match self {
            EndpointAddr::Direct { addr } => *addr,
            EndpointAddr::Mediate { outer, .. } => *outer,
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            EndpointAddr::Direct { .. } => Kind::Direct,
            EndpointAddr::Mediate { .. } => Kind::Mediate,
        }
    }

    /// Returns whether this endpoint can be reached through public routing.
    ///
    /// A direct endpoint must contain a globally reachable unicast address. A mediated endpoint
    /// is considered publicly reachable through its validated agent.
    pub fn is_publicly_reachable(&self) -> bool {
        match self {
            EndpointAddr::Direct { addr } => match addr.ip() {
                IpAddr::V4(addr) => is_publicly_reachable_ipv4(addr),
                IpAddr::V6(addr) => is_publicly_reachable_ipv6(addr),
            },
            EndpointAddr::Mediate { .. } => true,
        }
    }

    pub fn encoding_size(&self) -> usize {
        match self {
            EndpointAddr::Direct {
                addr: SocketAddr::V4(_),
            } => 2 + 4,
            EndpointAddr::Direct {
                addr: SocketAddr::V6(_),
            } => 2 + 16,
            EndpointAddr::Mediate {
                agent: SocketAddr::V4(_),
                outer: SocketAddr::V4(_),
            } => 2 + 4 + 2 + 4,
            EndpointAddr::Mediate {
                agent: SocketAddr::V6(_),
                outer: SocketAddr::V6(_),
            } => 2 + 16 + 2 + 16,
            _ => unimplemented!("Unix socket addresses are not supported"),
        }
    }
}

pub trait WriteEndpointAddr {
    fn put_endpoint_addr(&mut self, endpoint: EndpointAddr);
}

impl<T: BufMut> WriteEndpointAddr for T {
    fn put_endpoint_addr(&mut self, endpoint: EndpointAddr) {
        use crate::net::WriteSocketAddr;
        match endpoint {
            EndpointAddr::Direct { addr } => self.put_socket_addr(&addr),
            EndpointAddr::Mediate {
                agent,
                outer: inner,
            } => {
                self.put_socket_addr(&agent);
                self.put_socket_addr(&inner);
            }
        }
    }
}

pub fn be_endpoint_addr(
    input: &[u8],
    family: Family,
    kind: Kind,
) -> nom::IResult<&[u8], EndpointAddr> {
    match kind {
        Kind::Direct => {
            let (remain, addr) = be_socket_addr(input, family)?;
            Ok((remain, EndpointAddr::direct(addr)))
        }
        Kind::Mediate => {
            let (remain, agent) = be_socket_addr(input, family)?;
            let (remain, outer) = be_socket_addr(remain, family)?;
            Ok((remain, EndpointAddr::with_agent(agent, outer)))
        }
    }
}

impl Display for EndpointAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndpointAddr::Direct { addr } => write!(f, "{addr}"),
            EndpointAddr::Mediate { agent, outer } => write!(f, "{agent}-{outer}"),
        }
    }
}

impl Deref for EndpointAddr {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        match self {
            EndpointAddr::Direct { addr } => addr,
            EndpointAddr::Mediate { agent, .. } => agent,
        }
    }
}

impl FromStr for EndpointAddr {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((first, second)) = s.split_once("-") {
            // Agent format: "inet:1.12.124.56:1234-inet:202.106.68.43:6080"
            let agent = first.trim().parse()?;
            let outer = second.trim().parse()?;
            Ok(EndpointAddr::with_agent(agent, outer))
        } else {
            // Direct format: "1.12.124.56:1234"
            let addr = s.trim().parse()?;
            Ok(EndpointAddr::direct(addr))
        }
    }
}

impl From<SocketAddr> for EndpointAddr {
    fn from(addr: SocketAddr) -> Self {
        EndpointAddr::direct(addr)
    }
}

impl From<(SocketAddr, SocketAddr)> for EndpointAddr {
    fn from((agent, outer): (SocketAddr, SocketAddr)) -> Self {
        EndpointAddr::with_agent(agent, outer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_public_reachability() {
        for addr in [
            "8.8.8.8:443",
            "192.0.0.9:443",
            "192.0.0.10:443",
            "192.31.196.1:443",
        ] {
            assert!(
                EndpointAddr::direct(addr.parse().unwrap()).is_publicly_reachable(),
                "{addr} should be publicly reachable"
            );
        }

        for addr in [
            "0.0.0.0:443",
            "10.0.0.1:443",
            "100.64.0.1:443",
            "127.0.0.1:443",
            "169.254.1.1:443",
            "172.16.0.1:443",
            "192.0.0.1:443",
            "192.0.2.1:443",
            "192.88.99.1:443",
            "192.168.1.1:443",
            "198.18.0.1:443",
            "198.51.100.1:443",
            "203.0.113.1:443",
            "224.0.0.1:443",
            "240.0.0.1:443",
            "255.255.255.255:443",
        ] {
            assert!(
                !EndpointAddr::direct(addr.parse().unwrap()).is_publicly_reachable(),
                "{addr} should not be publicly reachable"
            );
        }
    }

    #[test]
    fn ipv6_public_reachability() {
        for addr in [
            "[64:ff9b::1]:443",
            "[2001:1::1]:443",
            "[2001:1::2]:443",
            "[2001:1::3]:443",
            "[2001:3::1]:443",
            "[2001:4:112::1]:443",
            "[2001:20::1]:443",
            "[2001:30::1]:443",
            "[2001:4860:4860::8888]:443",
        ] {
            assert!(
                EndpointAddr::direct(addr.parse().unwrap()).is_publicly_reachable(),
                "{addr} should be publicly reachable"
            );
        }

        for addr in [
            "[::]:443",
            "[::1]:443",
            "[::2]:443",
            "[::ffff:c000:201]:443",
            "[64:ff9b:1::1]:443",
            "[100::1]:443",
            "[100:0:0:1::1]:443",
            "[2001::1]:443",
            "[2001:1::4]:443",
            "[2001:2::1]:443",
            "[2001:10::1]:443",
            "[2001:db8::1]:443",
            "[2002::1]:443",
            "[3fff::1]:443",
            "[4000::1]:443",
            "[5f00::1]:443",
            "[fd00::1]:443",
            "[fec0::1]:443",
            "[fe80::1]:443",
            "[ff02::1]:443",
        ] {
            assert!(
                !EndpointAddr::direct(addr.parse().unwrap()).is_publicly_reachable(),
                "{addr} should not be publicly reachable"
            );
        }
    }

    #[test]
    fn mediate_endpoint_is_publicly_reachable_through_its_agent() {
        assert!(
            EndpointAddr::with_agent(
                "8.8.8.8:3478".parse().unwrap(),
                "192.168.1.2:50000".parse().unwrap(),
            )
            .is_publicly_reachable()
        );
    }
}
