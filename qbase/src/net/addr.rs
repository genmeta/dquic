use std::{
    fmt::Display,
    net::{AddrParseError, SocketAddr},
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
    Agent {
        agent: SocketAddr,
        outer: SocketAddr,
    },
}

impl EndpointAddr {
    pub fn direct(addr: SocketAddr) -> Self {
        EndpointAddr::Direct { addr }
    }

    pub fn with_agent(agent: SocketAddr, outer: SocketAddr) -> Self {
        EndpointAddr::Agent { agent, outer }
    }

    /// Returns the outer addr of this EndpointAddr
    ///
    /// Note: Before successful hole punching with this Endpoint, packets should be sent to the addr
    /// returned by deref() to establish communication. Once hole punching is successful or about to
    /// begin, use the addr returned by this function.
    pub fn addr(&self) -> SocketAddr {
        match self {
            EndpointAddr::Direct { addr } => *addr,
            EndpointAddr::Agent { outer, .. } => *outer,
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            EndpointAddr::Direct { .. } => Kind::Direct,
            EndpointAddr::Agent { .. } => Kind::Mediate,
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
            EndpointAddr::Agent {
                agent: SocketAddr::V4(_),
                outer: SocketAddr::V4(_),
            } => 2 + 4 + 2 + 4,
            EndpointAddr::Agent {
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
            EndpointAddr::Agent {
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
            EndpointAddr::Agent { agent, outer } => write!(f, "{agent}-{outer}"),
        }
    }
}

impl Deref for EndpointAddr {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        match self {
            EndpointAddr::Direct { addr } => addr,
            EndpointAddr::Agent { agent, .. } => agent,
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
