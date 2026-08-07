use std::{
    io::{self, IoSlice},
    sync::Arc,
};

use bytes::BytesMut;
use qbase::{
    datagram::forward::Payload as ForwardPayload,
    net::{
        addr::EndpointAddr,
        route::{Line, Link, Pathway},
    },
};

use super::UdpSocket;

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

        let mut payloads = Vec::with_capacity(packets.len());
        for packet in packets {
            let raw_offset = 2 + pathway.local().encoding_size() + pathway.remote().encoding_size();
            let mut bytes = BytesMut::zeroed(raw_offset + packet.len());
            bytes[raw_offset..].copy_from_slice(packet);
            let payload = ForwardPayload::from_raw(&pathway, bytes, raw_offset)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            payloads.push(payload);
        }
        let slices = payloads
            .iter()
            .map(|payload| IoSlice::new(payload.as_ref()))
            .collect::<Vec<_>>();
        send_all(&self.udp, &slices, line(link, slices[0].len())).await
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
    use qbase::datagram::{Datagram, WriteDatagram};

    use super::*;

    #[test]
    fn mixed_endpoint_paths_can_be_encoded() {
        let direct = EndpointAddr::direct("203.0.113.1:4433".parse().unwrap());
        let agent = EndpointAddr::mediate(
            "198.51.100.1:3478".parse().unwrap(),
            "192.0.2.1:50000".parse().unwrap(),
        );
        let payload = [0x40, 1, 2, 3];

        for pathway in [
            Pathway::new(direct, agent),
            Pathway::new(agent, direct),
            Pathway::new(agent, agent),
        ] {
            let raw_offset = 2 + pathway.local().encoding_size() + pathway.remote().encoding_size();
            let mut bytes = BytesMut::zeroed(raw_offset + payload.len());
            bytes[raw_offset..].copy_from_slice(&payload);
            let forward = ForwardPayload::from_raw(&pathway, bytes, raw_offset).unwrap();
            let datagram = Datagram::Forward(pathway, forward);
            let mut encoded = BytesMut::new();
            encoded.put_datagram(&datagram).unwrap();
            assert!(!encoded.is_empty());
        }
    }
}
