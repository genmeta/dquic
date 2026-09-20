use qbase::{
    net::route::{Link, Pathway},
    packet::{
        DataHeader, Packet,
        header::{long, short},
    },
};
use tokio::sync::mpsc;

use crate::packet::CipherPacket;

pub type PacketSender<H> = mpsc::Sender<(CipherPacket<H>, Pathway, Link)>;
pub type PacketReceiver<H> = mpsc::Receiver<(CipherPacket<H>, Pathway, Link)>;

#[derive(Debug, Clone)]
pub struct Inbox {
    initial: PacketSender<long::InitialHeader>,
    handshake: PacketSender<long::HandshakeHeader>,
    zero_rtt: PacketSender<long::ZeroRttHeader>,
    one_rtt: PacketSender<short::OneRttHeader>,
}

#[derive(Debug)]
pub struct RcvdPacket {
    pub initial: PacketReceiver<long::InitialHeader>,
    pub handshake: PacketReceiver<long::HandshakeHeader>,
    pub zero_rtt: PacketReceiver<long::ZeroRttHeader>,
    pub one_rtt: PacketReceiver<short::OneRttHeader>,
}

pub fn new() -> (Inbox, RcvdPacket) {
    let (initial_tx, initial_rx) = mpsc::channel(8);
    let (handshake_tx, handshake_rx) = mpsc::channel(8);
    let (zero_rtt_tx, zero_rtt_rx) = mpsc::channel(8);
    let (one_rtt_tx, one_rtt_rx) = mpsc::channel(128);
    (
        Inbox {
            initial: initial_tx,
            handshake: handshake_tx,
            zero_rtt: zero_rtt_tx,
            one_rtt: one_rtt_tx,
        },
        RcvdPacket {
            initial: initial_rx,
            handshake: handshake_rx,
            zero_rtt: zero_rtt_rx,
            one_rtt: one_rtt_rx,
        },
    )
}

impl Inbox {
    pub fn try_send_initial(
        &self,
        packet: CipherPacket<long::InitialHeader>,
        pathway: Pathway,
        link: Link,
    ) -> bool {
        self.initial.try_send((packet, pathway, link)).is_ok()
    }

    pub(crate) fn same_channel(&self, other: &Self) -> bool {
        self.initial.same_channel(&other.initial)
    }

    /// A connection must never backpressure the shared UDP receive loop.
    pub(crate) fn try_send(&self, packet: Packet, pathway: Pathway, link: Link) -> bool {
        match packet {
            Packet::Data(packet) => match packet.header {
                DataHeader::Long(long::DataHeader::Initial(header)) => self
                    .initial
                    .try_send((
                        CipherPacket::new(header, packet.bytes, packet.offset),
                        pathway,
                        link,
                    ))
                    .is_ok(),
                DataHeader::Long(long::DataHeader::Handshake(header)) => self
                    .handshake
                    .try_send((
                        CipherPacket::new(header, packet.bytes, packet.offset),
                        pathway,
                        link,
                    ))
                    .is_ok(),
                DataHeader::Long(long::DataHeader::ZeroRtt(header)) => self
                    .zero_rtt
                    .try_send((
                        CipherPacket::new(header, packet.bytes, packet.offset),
                        pathway,
                        link,
                    ))
                    .is_ok(),
                DataHeader::Short(header) => self
                    .one_rtt
                    .try_send((
                        CipherPacket::new(header, packet.bytes, packet.offset),
                        pathway,
                        link,
                    ))
                    .is_ok(),
            },
            Packet::VN(_) | Packet::Retry(_) => false,
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

    fn way() -> (Pathway, Link) {
        let local = SocketAddr::from(([127, 0, 0, 1], 4433));
        let remote = SocketAddr::from(([192, 0, 2, 1], 50000));
        let link = Link::new(local, remote);
        (Pathway::from(link), link)
    }

    #[tokio::test]
    async fn routes_each_level_to_its_typed_receiver() {
        let (inbox, mut rcvd_pkt) = new();
        let (pathway, link) = way();
        assert!(inbox.try_send(initial_packet(), pathway, link));
        assert_eq!(rcvd_pkt.initial.recv().await.unwrap().0.payload_len(), 0);
    }

    #[tokio::test]
    async fn full_receiver_does_not_block_routing() {
        let (inbox, _rcvd_pkt) = new();
        let (pathway, link) = way();
        while inbox.try_send(initial_packet(), pathway, link) {}

        tokio::time::timeout(Duration::from_millis(25), async {
            assert!(!inbox.try_send(initial_packet(), pathway, link));
        })
        .await
        .expect("routing must not wait for one connection's full receiver");
    }
}
