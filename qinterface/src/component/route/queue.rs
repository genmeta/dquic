use qbase::{
    packet::{
        DataHeader, Packet,
        header::{long, short},
    },
    util::BoundQueue,
};

use crate::component::route::{CipherPacket, ReceivedPacket, Way};

type PacketQueue<P> = BoundQueue<(ReceivedPacket<CipherPacket<P>>, Way)>;

// 需要一个四元组，pathway + src + dst
#[derive(Debug)]
pub struct RcvdPacketQueue {
    initial: PacketQueue<long::InitialHeader>,
    handshake: PacketQueue<long::HandshakeHeader>,
    zero_rtt: PacketQueue<long::ZeroRttHeader>,
    one_rtt: PacketQueue<short::OneRttHeader>,
    // pub retry:
}

impl Default for RcvdPacketQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl RcvdPacketQueue {
    pub fn new() -> Self {
        Self {
            initial: BoundQueue::new(8),
            handshake: BoundQueue::new(8),
            zero_rtt: BoundQueue::new(8),
            one_rtt: BoundQueue::new(128),
        }
    }

    pub fn initial(&self) -> &PacketQueue<long::InitialHeader> {
        &self.initial
    }

    pub fn handshake(&self) -> &PacketQueue<long::HandshakeHeader> {
        &self.handshake
    }

    pub fn zero_rtt(&self) -> &PacketQueue<long::ZeroRttHeader> {
        &self.zero_rtt
    }

    pub fn one_rtt(&self) -> &PacketQueue<short::OneRttHeader> {
        &self.one_rtt
    }

    pub fn close_all(&self) {
        self.initial.close();
        self.handshake.close();
        self.zero_rtt.close();
        self.one_rtt.close();
    }

    /// A per-connection queue must never backpressure the shared UDP receive loop.
    pub async fn deliver(&self, (packet, datagram_size): ReceivedPacket, way: Way) {
        match packet {
            Packet::Data(packet) => match packet.header {
                DataHeader::Long(long::DataHeader::Initial(header)) => {
                    let packet = CipherPacket::new(header, packet.bytes, packet.offset);
                    _ = self.initial.try_send(((packet, datagram_size), way));
                }
                DataHeader::Long(long::DataHeader::Handshake(header)) => {
                    let packet = CipherPacket::new(header, packet.bytes, packet.offset);
                    _ = self.handshake.try_send(((packet, datagram_size), way));
                }
                DataHeader::Long(long::DataHeader::ZeroRtt(header)) => {
                    let packet = CipherPacket::new(header, packet.bytes, packet.offset);
                    _ = self.zero_rtt.try_send(((packet, datagram_size), way));
                }
                DataHeader::Short(header) => {
                    let packet = CipherPacket::new(header, packet.bytes, packet.offset);
                    _ = self.one_rtt.try_send(((packet, datagram_size), way));
                }
            },
            Packet::VN(_vn) => {}
            Packet::Retry(_retry) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use bytes::BytesMut;
    use qbase::{
        cid::ConnectionId,
        net::route::{Link, Pathway},
        packet::{DataPacket, LongHeaderBuilder},
    };

    use super::*;
    use crate::bind_uri::BindUri;

    fn initial_packet() -> Packet {
        let header = LongHeaderBuilder::with_cid(
            ConnectionId::from_slice(b"destination"),
            ConnectionId::from_slice(b"source"),
        )
        .initial(Vec::new());
        Packet::Data(DataPacket {
            header: DataHeader::Long(long::DataHeader::Initial(header)),
            bytes: BytesMut::new(),
            offset: 0,
        })
    }

    fn way() -> Way {
        let local = SocketAddr::from(([127, 0, 0, 1], 4433));
        let remote = SocketAddr::from(([192, 0, 2, 1], 50000));
        let link = Link::new(local, remote);
        (BindUri::from(local), Pathway::from(link), link)
    }

    #[tokio::test]
    async fn deliver_enqueues_when_capacity_is_available() {
        let queue = RcvdPacketQueue::new();

        queue.deliver((initial_packet(), Some(1200)), way()).await;

        let ((_packet, datagram_size), _) = queue.initial().recv().await.unwrap();
        assert_eq!(datagram_size, Some(1200));
    }

    #[tokio::test]
    async fn deliver_does_not_wait_for_a_full_connection_queue() {
        let queue = RcvdPacketQueue::new();
        loop {
            let Packet::Data(packet) = initial_packet() else {
                unreachable!()
            };
            let DataHeader::Long(long::DataHeader::Initial(header)) = packet.header else {
                unreachable!()
            };
            let packet = CipherPacket::new(header, packet.bytes, packet.offset);
            match queue.initial.try_send(((packet, Some(1200)), way())) {
                Ok(()) => {}
                Err(error) if error.is_full() => break,
                Err(error) => panic!("queue closed while filling it: {error}"),
            }
        }

        tokio::time::timeout(
            Duration::from_millis(25),
            queue.deliver((initial_packet(), Some(1200)), way()),
        )
        .await
        .expect("routing must not wait for one connection's full queue");
    }
}
