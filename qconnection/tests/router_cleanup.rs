use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    net::route::Link,
    packet::{DataHeader, DataPacket, LongHeaderBuilder, Packet, long},
};
use qconnection::ServerRegistry;
use qtransport::router::QuicRouter;

#[tokio::test]
async fn initial_without_a_listening_server_leaves_no_odcid_route() {
    // A separate test process keeps the global server registry empty.
    ServerRegistry::global();
    let router = QuicRouter::global();
    let odcid = ConnectionId::from_slice(b"original");
    let scid = ConnectionId::from_slice(b"client00");
    let packet = || {
        Packet::Data(DataPacket {
            header: DataHeader::Long(long::DataHeader::Initial(
                LongHeaderBuilder::with_cid(odcid, scid).initial(vec![]),
            )),
            bytes: BytesMut::new(),
            offset: 0,
        })
    };
    let link = Link::new(
        "127.0.0.1:4433".parse().unwrap(),
        "127.0.0.1:9000".parse().unwrap(),
    );

    router.deliver(packet(), link.into(), link);
    assert!(router.find_entry(&packet(), &link).is_none());
}
