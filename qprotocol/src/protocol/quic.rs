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

    pub async fn send(&self, pathway: Pathway, packets: &[IoSlice<'_>]) -> io::Result<()> {
        if packets.is_empty() {
            return Ok(());
        }

        let ep_addr = pathway.local();
        let socket = self.find_socket(ep_addr).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                format!("local endpoint {ep_addr} is unavailable"),
            )
        })?;
        let destination = match pathway.remote() {
            EndpointAddr::Direct { addr } => addr,
            EndpointAddr::Mediate { agent, .. } => agent,
        };
        let link = Link::new(socket.local_addr()?, destination);

        let both_direct = matches!(pathway.local(), EndpointAddr::Direct { .. })
            && matches!(pathway.remote(), EndpointAddr::Direct { .. });
        if both_direct {
            return send_all(&socket, packets, line(link, packets[0].len())).await;
        }

        let mut payloads = Vec::with_capacity(packets.len());
        for packet in packets {
            let raw_offset = 2 + pathway.local().encoding_size() + pathway.remote().encoding_size();
            let mut bytes = BytesMut::zeroed(raw_offset + packet.len());
            bytes[raw_offset..].copy_from_slice(packet);
            let payload = ForwardPayload::from_raw(&pathway, bytes, raw_offset)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            payloads.push(payload);
        }
        let packets = payloads
            .iter()
            .map(|payload| IoSlice::new(payload.as_ref()))
            .collect::<Vec<_>>();
        send_all(&socket, &packets, line(link, packets[0].len())).await
    }

    /// Bytes added by qprotocol outside the QUIC packet.
    pub fn packet_overhead(pathway: Pathway) -> usize {
        if matches!(pathway.local(), EndpointAddr::Direct { .. })
            && matches!(pathway.remote(), EndpointAddr::Direct { .. }) { 0 }
        else { 2 + pathway.local().encoding_size() + pathway.remote().encoding_size() }
    }

    /// Submit exactly one UDP datagram without awaiting while holding the caller's
    /// submission boundary. Pending means no datagram was submitted. Ready(Ok(n))
    /// reports the complete UDP payload size, including forwarding overhead.
    pub fn poll_send_packet(&self, cx: &mut std::task::Context<'_>, pathway: Pathway, packet: &[u8])
        -> std::task::Poll<io::Result<usize>>
    {
        use std::task::{Poll, ready};
        let socket = self.find_socket(pathway.local()).ok_or_else(||
            io::Error::new(io::ErrorKind::NotConnected, "local endpoint unavailable"))?;
        let destination = match pathway.remote() {
            EndpointAddr::Direct { addr } => addr,
            EndpointAddr::Mediate { agent, .. } => agent,
        };
        let link = Link::new(socket.local_addr()?, destination);
        let overhead = Self::packet_overhead(pathway);
        let payload;
        let wire = if overhead == 0 { packet } else {
            let mut bytes = BytesMut::zeroed(overhead + packet.len());
            bytes[overhead..].copy_from_slice(packet);
            payload = ForwardPayload::from_raw(&pathway, bytes, overhead)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            payload.as_ref()
        };
        let count = ready!(socket.poll_send(cx, &[IoSlice::new(wire)], &line(link, wire.len())))?;
        if count != 1 { return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "UDP did not submit the packet"))); }
        Poll::Ready(Ok(wire.len()))
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
    async fn direct_pathway_sends_raw_quic() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let receiver = receiver();
        let local = EndpointAddr::direct(raw.local_addr().unwrap());
        let remote = EndpointAddr::direct(receiver.local_addr().unwrap());
        let protocol = QuicProtocol::new();
        protocol.register(local, &raw).unwrap();

        let packet = [0x40, 1, 2, 3];
        protocol
            .send(Pathway::new(local, remote), &[IoSlice::new(&packet)])
            .await
            .unwrap();

        let mut received = [0; 16];
        let (len, source) = receiver.recv_from(&mut received).unwrap();
        assert_eq!(&received[..len], &packet);
        assert_eq!(source, raw.local_addr().unwrap());
    }

    #[tokio::test]
    async fn mediated_pathway_sends_forward_datagram_to_agent() {
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

        let packet = [0x40, 1, 2, 3];
        protocol
            .send(pathway, &[IoSlice::new(&packet)])
            .await
            .unwrap();

        let mut received = [0; 128];
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
