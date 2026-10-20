use std::{net::SocketAddr, time::Duration};

use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    net::route::{Link, Pathway},
    packet::{DataHeader, DataPacket, LongHeaderBuilder, Packet, header::long},
};
use qtransport::packet::channel::new;

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
