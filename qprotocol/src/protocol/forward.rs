use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::{Arc, Weak},
};

use dashmap::DashMap;
pub use qbase::datagram::forward::Payload as ForwardPayload;
use qbase::net::{
    addr::EndpointAddr,
    route::{Line, Link, Pathway},
};

use crate::socket::UdpSocket;

#[derive(Default)]
pub struct ForwardProtocol {
    agents: DashMap<SocketAddr, Weak<UdpSocket>>,
}

impl ForwardProtocol {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn serve(&self, agent: SocketAddr, socket: &Arc<UdpSocket>) {
        self.agents.insert(agent, Arc::downgrade(socket));
    }

    pub fn stop_serving(&self, agent: SocketAddr) {
        self.agents.remove(&agent);
    }

    pub async fn on_datagram(
        &self,
        pathway: Pathway,
        payload: ForwardPayload,
        link: Link,
    ) -> io::Result<usize> {
        let Some(socket) = self.agent_socket(link.src) else {
            return Ok(0);
        };
        let destination = match pathway.remote() {
            EndpointAddr::Direct { addr } => addr,
            EndpointAddr::Mediate { agent, outer } => match self.agent_socket(agent) {
                None => agent,
                Some(agent_socket) => {
                    debug_assert_or_warn!(
                        Arc::ptr_eq(&socket, &agent_socket),
                        "destination agent {agent} and receiving address {} map to different sockets",
                        link.src
                    );
                    outer
                }
            },
        };

        let encoded = payload.as_ref();
        let line = Line::new(
            Link::new(link.src, destination),
            Line::DEFAULT_TTL,
            None,
            encoded.len().min(u16::MAX as usize) as u16,
        );
        let slices = [IoSlice::new(encoded)];
        socket.send(&slices, line).await
    }

    pub(crate) fn agent_socket(&self, agent: SocketAddr) -> Option<Arc<UdpSocket>> {
        let socket = self.agents.get(&agent)?.upgrade();
        if socket.is_none() {
            self.agents.remove(&agent);
        }
        socket
    }
}

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket as StdUdpSocket, time::Duration};

    use bytes::{BufMut, BytesMut};
    use qbase::datagram::{Datagram, be_datagram};

    use super::*;

    const RAW_DATAGRAM: &[u8] = &[0x40, 1, 2, 3];

    fn forward_payload(pathway: Pathway) -> ForwardPayload {
        let raw_offset = 2 + pathway.local().encoding_size() + pathway.remote().encoding_size();
        let mut bytes = BytesMut::zeroed(raw_offset + RAW_DATAGRAM.len());
        bytes[raw_offset..].copy_from_slice(RAW_DATAGRAM);
        ForwardPayload::from_raw(&pathway, bytes, raw_offset).unwrap()
    }

    fn receiver() -> StdUdpSocket {
        let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        socket
    }

    fn receive(socket: &StdUdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut bytes = vec![0; 1_500];
        let (len, source) = socket.recv_from(&mut bytes).unwrap();
        bytes.truncate(len);
        (bytes, source)
    }

    #[test]
    fn forward_datagram_round_trips_mixed_pathway() {
        let pathway = Pathway::new(
            EndpointAddr::mediate(
                "198.51.100.1:3478".parse().unwrap(),
                "192.0.2.1:50000".parse().unwrap(),
            ),
            EndpointAddr::direct("203.0.113.1:4433".parse().unwrap()),
        );
        let payload = BytesMut::from(&[0xc1, 1, 2, 3][..]);
        let raw_offset = 2 + pathway.local().encoding_size() + pathway.remote().encoding_size();
        let mut bytes = BytesMut::zeroed(raw_offset + payload.len());
        bytes[raw_offset..].copy_from_slice(&payload);
        let forward = ForwardPayload::from_raw(&pathway, bytes, raw_offset).unwrap();
        let mut packet = BytesMut::new();
        packet.put_slice(forward.as_ref());

        let Datagram::Forward(decoded_pathway, decoded) = be_datagram(packet).unwrap() else {
            panic!("expected Forward datagram");
        };
        assert_eq!(decoded_pathway, pathway);
        assert_eq!(decoded.into_raw(), payload);
    }

    #[tokio::test]
    async fn unknown_receiving_address_is_dropped() {
        let agent = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let outer = receiver();
        let pathway = Pathway::new(
            EndpointAddr::direct("127.0.0.1:4433".parse().unwrap()),
            EndpointAddr::mediate(agent.local_addr().unwrap(), outer.local_addr().unwrap()),
        );
        let payload = forward_payload(pathway);
        let protocol = ForwardProtocol::new();
        protocol.serve(agent.local_addr().unwrap(), &agent);

        let unknown = Link::new(
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        );
        assert_eq!(
            protocol
                .on_datagram(pathway, payload, unknown)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn destination_agent_forwards_to_outer() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let outer = receiver();
        let inner = socket.local_addr().unwrap();
        let agent = "127.0.0.1:4434".parse().unwrap();
        let pathway = Pathway::new(
            EndpointAddr::direct("127.0.0.1:4433".parse().unwrap()),
            EndpointAddr::mediate(agent, outer.local_addr().unwrap()),
        );
        let payload = forward_payload(pathway);
        let encoded = payload.as_ref().to_vec();
        let protocol = ForwardProtocol::new();
        protocol.serve(inner, &socket);
        protocol.serve(agent, &socket);

        let link = Link::new(inner, "127.0.0.1:4433".parse().unwrap());
        assert_eq!(
            protocol.on_datagram(pathway, payload, link).await.unwrap(),
            1
        );

        let (received, source) = receive(&outer);
        assert_eq!(received, encoded);
        assert_eq!(source, inner);
    }

    #[tokio::test]
    async fn intermediate_forwards_to_destination_agent() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let agent = receiver();
        let local = socket.local_addr().unwrap();
        let pathway = Pathway::new(
            EndpointAddr::direct("127.0.0.1:4433".parse().unwrap()),
            EndpointAddr::mediate(
                agent.local_addr().unwrap(),
                "127.0.0.1:4435".parse().unwrap(),
            ),
        );
        let payload = forward_payload(pathway);
        let encoded = payload.as_ref().to_vec();
        let protocol = ForwardProtocol::new();
        protocol.serve(local, &socket);

        let link = Link::new(local, "127.0.0.1:4433".parse().unwrap());
        assert_eq!(
            protocol.on_datagram(pathway, payload, link).await.unwrap(),
            1
        );

        let (received, source) = receive(&agent);
        assert_eq!(received, encoded);
        assert_eq!(source, local);
    }

    #[tokio::test]
    async fn intermediate_forwards_to_direct_destination() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let direct = receiver();
        let local = socket.local_addr().unwrap();
        let pathway = Pathway::new(
            EndpointAddr::direct("127.0.0.1:4433".parse().unwrap()),
            EndpointAddr::direct(direct.local_addr().unwrap()),
        );
        let payload = forward_payload(pathway);
        let encoded = payload.as_ref().to_vec();
        let protocol = ForwardProtocol::new();
        protocol.serve(local, &socket);

        let link = Link::new(local, "127.0.0.1:4433".parse().unwrap());
        assert_eq!(
            protocol.on_datagram(pathway, payload, link).await.unwrap(),
            1
        );

        let (received, source) = receive(&direct);
        assert_eq!(received, encoded);
        assert_eq!(source, local);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    #[should_panic(expected = "and receiving address")]
    async fn inconsistent_destination_agent_panics() {
        let receiving = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let agent = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let local = receiving.local_addr().unwrap();
        let pathway = Pathway::new(
            EndpointAddr::direct("127.0.0.1:4433".parse().unwrap()),
            EndpointAddr::mediate(
                agent.local_addr().unwrap(),
                "127.0.0.1:4435".parse().unwrap(),
            ),
        );
        let payload = forward_payload(pathway);
        let protocol = ForwardProtocol::new();
        protocol.serve(local, &receiving);
        protocol.serve(agent.local_addr().unwrap(), &agent);

        let link = Link::new(local, "127.0.0.1:4433".parse().unwrap());
        let _ = protocol.on_datagram(pathway, payload, link).await;
    }
}
