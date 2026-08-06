use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::{BufMut, BytesMut};
use dashmap::DashMap;
use qbase::net::{
    Family,
    addr::{EndpointAddr, WriteEndpointAddr, be_endpoint_addr},
    route::{Line, Link, Pathway},
};
use thiserror::Error;

use crate::{UdpSocket, quic::QuicProtocol};

const HEADER_MASK: u8 = 0b1110_0000;
const HEADER_BITS: u8 = 0b0110_0000;
const FORWARD_BIT: u8 = 0b0000_1000;
const FAMILY_BIT: u8 = 0b0000_0100;
const SOURCE_AGENT_BIT: u8 = 0b0000_0010;
const DESTINATION_AGENT_BIT: u8 = 0b0000_0001;

#[derive(Debug, Error)]
pub enum ForwardHeaderError {
    #[error("a Forward packet requires a non-empty QUIC payload")]
    EmptyPayload,
    #[error("Forward header version must fit in four bits")]
    InvalidVersion,
    #[error("Forward Pathway endpoints must use one address family")]
    AddressFamilyMismatch,
    #[error("invalid Forward header")]
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardHeader {
    quic_bits: u8,
    version: u8,
    pathway: Pathway,
}

impl ForwardHeader {
    pub fn new(version: u8, pathway: Pathway, payload: &[u8]) -> Result<Self, ForwardHeaderError> {
        let Some(first) = payload.first() else {
            return Err(ForwardHeaderError::EmptyPayload);
        };
        if version > 0x0f {
            return Err(ForwardHeaderError::InvalidVersion);
        }
        if endpoint_is_ipv6(pathway.local())? != endpoint_is_ipv6(pathway.remote())? {
            return Err(ForwardHeaderError::AddressFamilyMismatch);
        }
        Ok(Self {
            quic_bits: first & 0b0001_1111,
            version,
            pathway,
        })
    }

    pub fn pathway(&self) -> Pathway {
        self.pathway
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn encoded_len(&self) -> usize {
        Self::encoding_size(self.pathway)
    }

    pub fn encoding_size(pathway: Pathway) -> usize {
        let both_direct = matches!(pathway.local(), EndpointAddr::Direct { .. })
            && matches!(pathway.remote(), EndpointAddr::Direct { .. });
        if both_direct {
            0
        } else {
            2 + pathway.local().encoding_size() + pathway.remote().encoding_size()
        }
    }
}

fn endpoint_is_ipv6(endpoint: EndpointAddr) -> Result<bool, ForwardHeaderError> {
    match endpoint {
        EndpointAddr::Direct { addr } => Ok(addr.is_ipv6()),
        EndpointAddr::Agent { agent, outer } if agent.is_ipv6() == outer.is_ipv6() => {
            Ok(agent.is_ipv6())
        }
        EndpointAddr::Agent { .. } => Err(ForwardHeaderError::AddressFamilyMismatch),
    }
}

pub trait WriteForwardHeader {
    fn put_forward_header(&mut self, header: &ForwardHeader);
}

impl<T: BufMut> WriteForwardHeader for T {
    fn put_forward_header(&mut self, header: &ForwardHeader) {
        self.put_u8(HEADER_BITS | header.quic_bits);
        let mut flags = (header.version << 4) | FORWARD_BIT;
        if header.pathway.local().ip().is_ipv6() {
            flags |= FAMILY_BIT;
        }
        if matches!(header.pathway.local(), EndpointAddr::Agent { .. }) {
            flags |= SOURCE_AGENT_BIT;
        }
        if matches!(header.pathway.remote(), EndpointAddr::Agent { .. }) {
            flags |= DESTINATION_AGENT_BIT;
        }
        self.put_u8(flags);
        self.put_endpoint_addr(header.pathway.local());
        self.put_endpoint_addr(header.pathway.remote());
    }
}

pub fn looks_like_forward(input: &[u8]) -> bool {
    input
        .first()
        .is_some_and(|first| first & HEADER_MASK == HEADER_BITS)
}

pub fn decode_forward(input: &[u8]) -> Result<(ForwardHeader, usize), ForwardHeaderError> {
    if input.len() < 2 || !looks_like_forward(input) {
        return Err(ForwardHeaderError::Invalid);
    }

    let first = input[0];
    let flags = input[1];
    if flags & FORWARD_BIT == 0 {
        return Err(ForwardHeaderError::Invalid);
    }
    let family = if flags & FAMILY_BIT == 0 {
        Family::V4
    } else {
        Family::V6
    };
    let source_type = flags & SOURCE_AGENT_BIT;
    let destination_type = flags & DESTINATION_AGENT_BIT;
    let body = &input[2..];
    let (body, source) =
        be_endpoint_addr(body, source_type, family).map_err(|_| ForwardHeaderError::Invalid)?;
    let (remain, destination) = be_endpoint_addr(body, destination_type, family)
        .map_err(|_| ForwardHeaderError::Invalid)?;
    let consumed = input.len() - remain.len();

    Ok((
        ForwardHeader {
            quic_bits: first & 0b0001_1111,
            version: flags >> 4,
            pathway: Pathway::new(source, destination),
        },
        consumed,
    ))
}

pub struct ForwardProtocol {
    enabled: Arc<AtomicBool>,
    agents: DashMap<SocketAddr, Weak<UdpSocket>>,
    quic: Arc<QuicProtocol>,
}

impl ForwardProtocol {
    pub fn new(quic: Arc<QuicProtocol>) -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(false)),
            agents: DashMap::new(),
            quic,
        }
    }

    pub fn enable(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn serve(&self, agent: SocketAddr, socket: &Arc<UdpSocket>) {
        self.agents.insert(agent, Arc::downgrade(socket));
    }

    pub fn stop_serving(&self, agent: SocketAddr) {
        self.agents.remove(&agent);
    }

    pub async fn on_packet(
        &self,
        socket: &Arc<UdpSocket>,
        mut packet: BytesMut,
        link: Link,
        header: ForwardHeader,
        header_len: usize,
    ) -> io::Result<()> {
        let sent_pathway = header.pathway();
        let destination = sent_pathway.remote();

        if self.quic.socket(destination).is_some() {
            let payload = packet.split_off(header_len);
            self.quic.on_packet(payload, sent_pathway.flip(), link);
            return Ok(());
        }

        let EndpointAddr::Agent { agent, outer } = destination else {
            return Ok(());
        };
        if !self.enabled() || !self.serves(agent, socket) {
            return Ok(());
        }

        let line = Line::new(
            Link::new(link.src, outer),
            Line::DEFAULT_TTL,
            None,
            packet.len().min(u16::MAX as usize) as u16,
        );
        let slices = [IoSlice::new(&packet)];
        let sent = socket.send(&slices, line).await?;
        if sent == 1 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "forwarding socket sent zero datagrams",
            ))
        }
    }

    fn serves(&self, agent: SocketAddr, socket: &Arc<UdpSocket>) -> bool {
        let Some(registered) = self.agents.get(&agent) else {
            return false;
        };
        Weak::ptr_eq(&registered, &Arc::downgrade(socket))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_header_round_trips_mixed_pathway() {
        let pathway = Pathway::new(
            EndpointAddr::with_agent(
                "198.51.100.1:3478".parse().unwrap(),
                "192.0.2.1:50000".parse().unwrap(),
            ),
            EndpointAddr::direct("203.0.113.1:4433".parse().unwrap()),
        );
        let payload = [0x41, 1, 2, 3];
        let header = ForwardHeader::new(0, pathway, &payload).unwrap();
        let mut packet = BytesMut::new();
        packet.put_forward_header(&header);
        packet.extend_from_slice(&payload);

        let (decoded, consumed) = decode_forward(&packet).unwrap();
        assert_eq!(decoded.pathway(), pathway);
        assert_eq!(&packet[consumed..], payload);
    }
}
