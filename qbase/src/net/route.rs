use std::{fmt::Display, net::SocketAddr};

use bytes::BufMut;
use derive_more::{Deref, DerefMut};
use nom::number::streaming::be_u8;
use serde::{Deserialize, Serialize};

use crate::{
    frame::EncodeSize,
    net::{
        Family,
        addr::{EndpointAddr, Kind, WriteEndpointAddr, be_endpoint_addr},
        be_socket_addr,
    },
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pathway<E = EndpointAddr> {
    local: E,
    remote: E,
}

impl<E> Pathway<E> {
    #[inline]
    pub fn new(local: E, remote: E) -> Self {
        Self { local, remote }
    }

    #[inline]
    pub fn local(&self) -> E
    where
        E: Clone,
    {
        self.local.clone()
    }

    #[inline]
    pub fn remote(&self) -> E
    where
        E: Clone,
    {
        self.remote.clone()
    }

    #[inline]
    pub fn map<E1>(self, mut f: impl FnMut(E) -> E1) -> Pathway<E1> {
        Pathway {
            local: f(self.local),
            remote: f(self.remote),
        }
    }

    #[inline]
    pub fn flip(self) -> Self {
        Self {
            local: self.remote,
            remote: self.local,
        }
    }
}

pub fn be_pathway(
    input: &[u8],
    family: Family,
    local_kind: Kind,
    remote_kind: Kind,
) -> nom::IResult<&[u8], Pathway> {
    let (remain, local) = be_endpoint_addr(input, family, local_kind)?;
    let (remain, remote) = be_endpoint_addr(remain, family, remote_kind)?;
    Ok((remain, Pathway::new(local, remote)))
}

pub trait WritePathway<E> {
    fn put_pathway(&mut self, pathway: &Pathway<E>);
}

impl<T: BufMut> WritePathway<EndpointAddr> for T {
    fn put_pathway(&mut self, pathway: &Pathway<EndpointAddr>) {
        self.put_endpoint_addr(pathway.local.clone());
        self.put_endpoint_addr(pathway.remote.clone());
    }
}

impl<E: Display> Display for Pathway<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}---{}", self.local, self.remote)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Link {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl Display for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}<->{}", self.src, self.dst)
    }
}

pub fn be_link(input: &[u8]) -> nom::IResult<&[u8], Link> {
    let (remain, family) = be_u8(input)?;
    let family = match family {
        0 => Family::V4,
        1 => Family::V6,
        _ => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Alt,
            )));
        }
    };
    let (remain, src) = be_socket_addr(remain, family)?;
    let (remain, dst) = be_socket_addr(remain, family)?;
    Ok((remain, Link { src, dst }))
}

pub trait WriteLink {
    fn put_link(&mut self, link: &Link);
}

impl<T: BufMut> WriteLink for T {
    fn put_link(&mut self, link: &Link) {
        use crate::net::WriteSocketAddr;
        self.put_u8(link.src.is_ipv6() as u8);
        self.put_socket_addr(&link.src);
        self.put_socket_addr(&link.dst);
    }
}

impl EncodeSize for Link {
    fn max_encoding_size(&self) -> usize {
        1 + self.src.max_encoding_size() + self.dst.max_encoding_size()
    }

    fn encoding_size(&self) -> usize {
        1 + self.src.encoding_size() + self.dst.encoding_size()
    }
}

impl Link {
    #[inline]
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        Self { src, dst }
    }

    #[inline]
    pub fn flip(self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
        }
    }
}

impl<E: From<SocketAddr>> From<Link> for Pathway<E> {
    fn from(link: Link) -> Self {
        Pathway::new(E::from(link.src), E::from(link.dst))
    }
}

#[derive(Clone, Copy, Debug, Deref, DerefMut)]
pub struct Line {
    #[deref]
    #[deref_mut]
    pub link: Link,
    pub ttl: u8,
    // Explicit congestion notification (ECN)
    pub ecn: Option<u8>,
    // packet segment size
    pub seg_size: u16,
}

impl Line {
    pub const DEFAULT_TTL: u8 = 64;

    pub fn new(link: Link, ttl: u8, ecn: Option<u8>, seg_size: u16) -> Self {
        Self {
            link,
            ttl,
            ecn,
            seg_size,
        }
    }
}

impl Default for Line {
    fn default() -> Self {
        Self {
            link: Link::new(
                SocketAddr::from(([0, 0, 0, 0], 0)),
                SocketAddr::from(([0, 0, 0, 0], 0)),
            ),
            ttl: Self::DEFAULT_TTL,
            ecn: None,
            seg_size: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Deref, DerefMut)]
pub struct Route {
    pub pathway: Pathway,
    #[deref]
    #[deref_mut]
    pub line: Line,
}

impl Route {
    pub fn new(pathway: Pathway, line: Line) -> Self {
        Self { pathway, line }
    }

    /// Create a new empty packet header for receive packets.
    pub fn empty() -> Self {
        let src = SocketAddr::from(([0, 0, 0, 0], 0));
        let dst = SocketAddr::from(([0, 0, 0, 0], 0));
        let link = Link::new(SocketAddr::from(src), SocketAddr::from(dst));
        Self::new(link.into(), Line::default())
    }

    pub fn pathway(&self) -> Pathway {
        self.pathway
    }

    pub fn link(&self) -> Link {
        self.line.link
    }

    pub fn ttl(&self) -> u8 {
        self.line.ttl
    }

    pub fn ecn(&self) -> Option<u8> {
        self.line.ecn
    }

    pub fn seg_size(&self) -> u16 {
        self.line.seg_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_addr_from_str() {
        // Test direct format
        let addr = "127.0.0.1:8080".parse::<EndpointAddr>().unwrap();
        assert!(matches!(addr, EndpointAddr::Direct { .. }));

        // Test agent format
        let addr = "127.0.0.1:8080-192.168.1.1:9000"
            .parse::<EndpointAddr>()
            .unwrap();
        assert!(matches!(addr, EndpointAddr::Mediate { .. }));

        // Test with whitespace
        let addr = "  127.0.0.1:8080  -  192.168.1.1:9000  "
            .parse::<EndpointAddr>()
            .unwrap();
        assert!(matches!(addr, EndpointAddr::Mediate { .. }));

        // Test invalid format
        assert!("invalid".parse::<EndpointAddr>().is_err());
    }
}
