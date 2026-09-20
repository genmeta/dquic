use std::{
    io::{self, IoSlice},
    sync::{Arc, RwLock, Weak},
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

    pub fn unregister(&self, ep_addr: EndpointAddr, socket: &Arc<UdpSocket>) {
        let weak = Arc::downgrade(socket);
        self.sockets
            .remove_if(&ep_addr, |_, registered| Weak::ptr_eq(registered, &weak));
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
        std::future::poll_fn(|cx| self.poll_send(cx, pathway, packets)).await
    }

    /// Pending submits nothing. A partial success is returned immediately for accounting.
    pub fn poll_send(
        &self,
        cx: &mut std::task::Context<'_>,
        pathway: Pathway,
        packets: &[IoSlice<'_>],
    ) -> std::task::Poll<io::Result<usize>> {
        use std::task::Poll;
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
        let overhead = Self::packet_overhead(pathway);
        // Every IoSlice is a complete UDP datagram; GSO must never split a larger
        // later datagram using the size of the first one.
        let segment_size = packets.iter().map(|packet| packet.len()).max().unwrap() + overhead;
        if overhead == 0 {
            return socket.poll_send(cx, packets, &line(link, segment_size));
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
        socket.poll_send(cx, &packets, &line(link, segment_size))
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

#[cfg(test)]
mod tests {
    use std::{
        net::UdpSocket as StdUdpSocket,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use qbase::datagram::{Datagram, be_datagram};

    use super::*;

    fn receiver() -> StdUdpSocket {
        let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        socket
    }

    #[tokio::test]
    async fn register_and_deliver_by_endpoint() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let endpoint = EndpointAddr::direct(raw.local_addr().unwrap());
        let protocol = QuicProtocol::new();
        let delivered = Arc::new(AtomicUsize::new(0));
        protocol.on_receive({
            let delivered = delivered.clone();
            move |_, _, _| {
                delivered.fetch_add(1, Ordering::Relaxed);
            }
        });

        protocol.register(endpoint, &raw).unwrap();
        assert!(protocol.register(endpoint, &raw).is_err());
        let link = Link::new(endpoint.addr(), "127.0.0.1:4433".parse().unwrap());
        assert!(protocol.on_packet(BytesMut::from(&b"quic"[..]), link.into(), link));
        assert_eq!(delivered.load(Ordering::Relaxed), 1);

        protocol.unregister(endpoint, &raw);
        assert!(protocol.find_socket(endpoint).is_none());
    }

    #[tokio::test]
    async fn direct_pathway_sends_a_batch_without_splitting_datagrams() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let receiver = receiver();
        let local = EndpointAddr::direct(raw.local_addr().unwrap());
        let remote = EndpointAddr::direct(receiver.local_addr().unwrap());
        let protocol = QuicProtocol::new();
        protocol.register(local, &raw).unwrap();

        let packets = [vec![0x40; 4], vec![0x41; 1200], vec![0x42; 73]];
        let slices = packets.each_ref().map(|packet| IoSlice::new(packet));
        let mut sent = 0;
        while sent < packets.len() {
            let count = protocol
                .send(Pathway::new(local, remote), &slices[sent..])
                .await
                .unwrap();
            assert!(count > 0);
            sent += count;
        }
        let mut received = [0; 1500];
        for packet in packets {
            let (len, source) = receiver.recv_from(&mut received).unwrap();
            assert_eq!(&received[..len], packet);
            assert_eq!(source, raw.local_addr().unwrap());
        }
    }

    #[tokio::test]
    async fn mediated_pathway_sends_a_batch_of_forward_datagrams_to_agent() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let receiver = receiver();
        let local = EndpointAddr::direct(raw.local_addr().unwrap());
        let remote = EndpointAddr::mediate(
            receiver.local_addr().unwrap(),
            "127.0.0.1:4433".parse().unwrap(),
        );
        let pathway = Pathway::new(local, remote);
        let protocol = QuicProtocol::new();
        protocol.register(local, &raw).unwrap();

        let packets = [vec![0x40; 4], vec![0x41; 1200], vec![0x42; 73]];
        let slices = packets.each_ref().map(|packet| IoSlice::new(packet));
        let mut sent = 0;
        while sent < packets.len() {
            let count = protocol.send(pathway, &slices[sent..]).await.unwrap();
            assert!(count > 0);
            sent += count;
        }
        let mut received = [0; 1500];
        for packet in packets {
            let (len, source) = receiver.recv_from(&mut received).unwrap();
            let Datagram::Forward(decoded_pathway, payload) =
                be_datagram(BytesMut::from(&received[..len])).unwrap()
            else {
                panic!("expected Forward datagram");
            };
            assert_eq!(decoded_pathway, pathway);
            assert_eq!(payload.into_raw().as_ref(), packet);
            assert_eq!(source, raw.local_addr().unwrap());
        }
    }

    #[tokio::test]
    async fn unavailable_local_endpoint_fails_to_send() {
        let local = EndpointAddr::direct("127.0.0.1:4433".parse().unwrap());
        let remote = EndpointAddr::direct("127.0.0.1:4434".parse().unwrap());
        let protocol = QuicProtocol::new();

        let error = protocol
            .send(Pathway::new(local, remote), &[IoSlice::new(&[0x40])])
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    }

    #[tokio::test]
    async fn reclaimed_udp_socket_fails_to_send_and_clears_registration() {
        let protocol = QuicProtocol::new();
        let local = {
            let raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
            let local = EndpointAddr::direct(raw.local_addr().unwrap());
            protocol.register(local, &raw).unwrap();
            local
        };
        let remote = EndpointAddr::direct("127.0.0.1:4434".parse().unwrap());

        let error = protocol
            .send(Pathway::new(local, remote), &[IoSlice::new(&[0x40])])
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert!(!protocol.sockets.contains_key(&local));
    }
}
