use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

use dashmap::DashMap;
pub use qbase::datagram::forward::Payload as ForwardPayload;
use qbase::net::{
    addr::EndpointAddr,
    route::{Line, Link, Pathway},
};

use crate::{UdpSocket, quic::QuicProtocol};

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

    pub async fn on_datagram(
        &self,
        socket: &Arc<UdpSocket>,
        sent_pathway: Pathway,
        payload: ForwardPayload,
        link: Link,
    ) -> io::Result<()> {
        let destination = sent_pathway.remote();

        if self.quic.socket(destination).is_some() {
            let raw = payload.into_raw();
            self.quic.on_packet(raw, sent_pathway.flip(), link);
            return Ok(());
        }

        let EndpointAddr::Agent { agent, outer } = destination else {
            return Ok(());
        };
        if !self.enabled() || !self.serves(agent, socket) {
            return Ok(());
        }

        let encoded = payload.as_ref();
        let line = Line::new(
            Link::new(link.src, outer),
            Line::DEFAULT_TTL,
            None,
            encoded.len().min(u16::MAX as usize) as u16,
        );
        let slices = [IoSlice::new(encoded)];
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
    use bytes::{BufMut, BytesMut};
    use qbase::datagram::{Datagram, be_datagram};

    use super::*;

    #[test]
    fn forward_datagram_round_trips_mixed_pathway() {
        let pathway = Pathway::new(
            EndpointAddr::with_agent(
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
}
