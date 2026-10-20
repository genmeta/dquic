use std::{
    future::poll_fn,
    io::{self, IoSlice},
    net::SocketAddr,
    sync::{Arc, RwLock, Weak},
    task::{Context, Poll},
};

use bytes::BytesMut;
use dashmap::DashMap;
use qbase::{
    datagram::forward::Payload as ForwardPayload,
    net::{
        addr::EndpointAddr,
        route::{Line, Link, Pathway},
    },
};
use thiserror::Error;

use crate::socket::UdpSocket;

type Receiver = dyn Fn(BytesMut, Pathway, Link) + Send + Sync + 'static;

#[derive(Debug, Error)]
#[error("a live UDP socket is already registered for {0}")]
pub struct EndpointInUse(pub EndpointAddr);

pub struct QuicProtocol {
    sockets: DashMap<EndpointAddr, Weak<UdpSocket>>,
    receiver: RwLock<Arc<Receiver>>,
}

impl Default for QuicProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicProtocol {
    pub fn global() -> &'static Arc<Self> {
        crate::Dock::global().topology().quic()
    }

    pub fn new() -> Self {
        Self {
            sockets: DashMap::new(),
            receiver: RwLock::new(Arc::new(|_, _, _| {})),
        }
    }

    pub fn register(
        &self,
        endpoint: EndpointAddr,
        socket: &Arc<UdpSocket>,
    ) -> Result<(), EndpointInUse> {
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

    /// Revoke every endpoint for a local binding and discard expired registrations.
    pub fn unregister(&self, bound: SocketAddr) {
        self.sockets.retain(|_, registered| {
            registered.upgrade().is_some_and(|socket| {
                socket
                    .local_addr()
                    .is_ok_and(|registered| registered != bound)
            })
        });
    }

    pub fn find_socket(&self, endpoint_addr: EndpointAddr) -> Option<Arc<UdpSocket>> {
        let registered = self.sockets.get(&endpoint_addr)?.clone();
        let socket = registered.upgrade();
        if socket.is_none() {
            self.sockets.remove_if(&endpoint_addr, |_, socket| {
                Weak::ptr_eq(socket, &registered)
            });
        }
        socket
    }

    pub fn on_receive(&self, receiver: impl Fn(BytesMut, Pathway, Link) + Send + Sync + 'static) {
        *self.receiver.write().unwrap() = Arc::new(receiver);
    }

    /// Maximum number of UDP datagrams in one submission.
    pub const MAX_DATAGRAMS: usize = qudp::BATCH_SIZE;

    /// Submit one batch, returning the number of datagrams in the accepted prefix.
    pub async fn send(&self, pathway: Pathway, packets: &[IoSlice<'_>]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send(cx, pathway, packets)).await
    }

    /// Pending submits nothing. A partial success is returned immediately for accounting.
    pub fn poll_send(
        &self,
        cx: &mut Context<'_>,
        pathway: Pathway,
        packets: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if packets.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let packets = &packets[..packets.len().min(Self::MAX_DATAGRAMS)];
        let overhead = Self::packet_overhead(pathway);
        if overhead == 0 {
            return self.poll_send_datagrams(cx, pathway, packets);
        }
        let mut payloads = Vec::with_capacity(packets.len());
        for packet in packets {
            let mut bytes = BytesMut::zeroed(overhead + packet.len());
            bytes[overhead..].copy_from_slice(packet);
            payloads.push(
                ForwardPayload::from_raw(&pathway, bytes, overhead)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
            );
        }
        let packets = payloads
            .iter()
            .map(|packet| IoSlice::new(packet.as_ref()))
            .collect::<Vec<_>>();
        self.poll_send_datagrams(cx, pathway, &packets)
    }

    /// Submit complete datagrams, including the Forward header for a mediated Pathway.
    pub fn poll_send_datagrams(
        &self,
        cx: &mut Context<'_>,
        pathway: Pathway,
        packets: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if packets.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let packets = &packets[..packets.len().min(Self::MAX_DATAGRAMS)];
        let socket = self.find_socket(pathway.local()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "local endpoint unavailable")
        })?;
        let destination = match pathway.remote() {
            EndpointAddr::Direct { addr } => addr,
            EndpointAddr::Mediate { agent, .. } => agent,
        };
        let link = Link::new(socket.local_addr()?, destination);
        let segment_size = packets.iter().map(|packet| packet.len()).max().unwrap();
        socket.poll_send(cx, packets, &line(link, segment_size))
    }

    /// Bytes added by qprotocol outside the QUIC packet.
    pub fn packet_overhead(pathway: Pathway) -> usize {
        if matches!(pathway.local(), EndpointAddr::Direct { .. })
            && matches!(pathway.remote(), EndpointAddr::Direct { .. })
        {
            0
        } else {
            2 + pathway.local().encoding_size() + pathway.remote().encoding_size()
        }
    }

    pub fn on_packet(&self, datagram: BytesMut, pathway: Pathway, link: Link) -> bool {
        if self.find_socket(pathway.local()).is_none() {
            return false;
        }
        let handler = self.receiver.read().unwrap().clone();
        handler(datagram, pathway, link);
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
