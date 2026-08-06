use std::{
    io::{self, IoSlice},
    sync::{Arc, RwLock, Weak},
};

use bytes::BytesMut;
use dashmap::DashMap;
use qbase::net::{
    addr::EndpointAddr,
    route::{Line, Link, Pathway},
};
use thiserror::Error;

use crate::{
    UdpSocket,
    forward::{ForwardHeader, WriteForwardHeader},
};

type DatagramHandler = dyn Fn(BytesMut, Arc<QuicSocket>, Pathway, Link) + Send + Sync + 'static;

#[derive(Debug, Error)]
#[error("a live QuicSocket is already bound to {0}")]
pub struct EndpointInUse(pub EndpointAddr);

pub struct QuicSocket {
    udp: Arc<UdpSocket>,
    endpoint: EndpointAddr,
}

impl QuicSocket {
    pub fn new(udp: Arc<UdpSocket>, endpoint: EndpointAddr) -> Self {
        Self { udp, endpoint }
    }

    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.endpoint
    }

    pub fn udp_socket(&self) -> &Arc<UdpSocket> {
        &self.udp
    }

    pub async fn send(
        &self,
        packets: &[IoSlice<'_>],
        remote: EndpointAddr,
        link: Link,
    ) -> io::Result<()> {
        if packets.is_empty() {
            return Ok(());
        }

        let pathway = Pathway::new(self.endpoint, remote);
        let both_direct = matches!(self.endpoint, EndpointAddr::Direct { .. })
            && matches!(remote, EndpointAddr::Direct { .. });

        if both_direct {
            return send_all(&self.udp, packets, line(link, packets[0].len())).await;
        }

        let mut datagrams = Vec::with_capacity(packets.len());
        for packet in packets {
            let header = ForwardHeader::new(0, pathway, packet)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            let mut datagram = BytesMut::with_capacity(header.encoded_len() + packet.len());
            datagram.put_forward_header(&header);
            datagram.extend_from_slice(packet);
            datagrams.push(datagram);
        }
        let slices = datagrams
            .iter()
            .map(|datagram| IoSlice::new(datagram))
            .collect::<Vec<_>>();
        send_all(&self.udp, &slices, line(link, slices[0].len())).await
    }
}

pub struct QuicProtocol {
    sockets: DashMap<EndpointAddr, Weak<QuicSocket>>,
    handler: RwLock<Arc<DatagramHandler>>,
}

impl Default for QuicProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicProtocol {
    pub fn new() -> Self {
        Self {
            sockets: DashMap::new(),
            handler: RwLock::new(Arc::new(|_, _, _, _| {})),
        }
    }

    pub fn set_handler(
        &self,
        handler: impl Fn(BytesMut, Arc<QuicSocket>, Pathway, Link) + Send + Sync + 'static,
    ) {
        *self.handler.write().unwrap() = Arc::new(handler);
    }

    pub fn register(&self, socket: &Arc<QuicSocket>) -> Result<(), EndpointInUse> {
        let endpoint = socket.endpoint_addr();
        match self.sockets.entry(endpoint) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                if entry.get().upgrade().is_some() {
                    return Err(EndpointInUse(endpoint));
                }
                entry.insert(Arc::downgrade(socket));
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(Arc::downgrade(socket));
            }
        }
        Ok(())
    }

    pub fn unregister(&self, socket: &Arc<QuicSocket>) {
        let endpoint = socket.endpoint_addr();
        let weak = Arc::downgrade(socket);
        self.sockets
            .remove_if(&endpoint, |_, registered| Weak::ptr_eq(registered, &weak));
    }

    pub fn socket(&self, endpoint: EndpointAddr) -> Option<Arc<QuicSocket>> {
        let socket = self.sockets.get(&endpoint)?.upgrade();
        if socket.is_none() {
            self.sockets.remove(&endpoint);
        }
        socket
    }

    pub fn on_packet(&self, datagram: BytesMut, pathway: Pathway, link: Link) -> bool {
        let Some(socket) = self.socket(pathway.local()) else {
            return false;
        };
        let handler = self.handler.read().unwrap().clone();
        handler(datagram, socket, pathway, link);
        true
    }
}

fn line(link: Link, segment_size: usize) -> Line {
    Line::new(
        link,
        Line::DEFAULT_TTL,
        None,
        segment_size.min(u16::MAX as usize) as u16,
    )
}

async fn send_all(socket: &UdpSocket, packets: &[IoSlice<'_>], line: Line) -> io::Result<()> {
    let mut sent = 0;
    while sent < packets.len() {
        let count = socket.send(&packets[sent..], line).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "UDP socket sent zero datagrams",
            ));
        }
        sent += count;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test]
    async fn register_and_deliver_by_endpoint() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let endpoint = EndpointAddr::direct(raw.local_addr().unwrap());
        let socket = Arc::new(QuicSocket::new(raw, endpoint));
        let protocol = QuicProtocol::new();
        let delivered = Arc::new(AtomicUsize::new(0));
        protocol.set_handler({
            let delivered = delivered.clone();
            move |_, _, _, _| {
                delivered.fetch_add(1, Ordering::Relaxed);
            }
        });

        protocol.register(&socket).unwrap();
        assert!(protocol.register(&socket).is_err());
        let link = Link::new(endpoint.addr(), "127.0.0.1:4433".parse().unwrap());
        assert!(protocol.on_packet(BytesMut::from(&b"quic"[..]), link.into(), link));
        assert_eq!(delivered.load(Ordering::Relaxed), 1);

        protocol.unregister(&socket);
        assert!(protocol.socket(endpoint).is_none());
    }

    #[test]
    fn mixed_endpoint_paths_require_forward_header() {
        let direct = EndpointAddr::direct("203.0.113.1:4433".parse().unwrap());
        let agent = EndpointAddr::with_agent(
            "198.51.100.1:3478".parse().unwrap(),
            "192.0.2.1:50000".parse().unwrap(),
        );
        let payload = [0x40, 1, 2, 3];

        assert_eq!(
            ForwardHeader::encoding_size(Pathway::new(direct, direct)),
            0
        );
        assert!(ForwardHeader::encoding_size(Pathway::new(direct, agent)) > 0);
        assert!(ForwardHeader::encoding_size(Pathway::new(agent, direct)) > 0);
        assert!(ForwardHeader::encoding_size(Pathway::new(agent, agent)) > 0);
        assert!(ForwardHeader::new(0, Pathway::new(agent, direct), &payload).is_ok());
    }
}
