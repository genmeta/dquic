use std::sync::{Arc, Mutex};

use qbase::packet::{DataHeader, DataPacket, LongHeaderBuilder, long};

use super::*;
use crate::packet::channel;

fn router() -> Arc<QuicRouter> {
    Arc::new(QuicRouter::new())
}

fn packet(cid: ConnectionId) -> Packet {
    Packet::Data(DataPacket {
        header: DataHeader::Long(long::DataHeader::Initial(
            LongHeaderBuilder::with_cid(cid, cid).initial(vec![]),
        )),
        bytes: BytesMut::new(),
        offset: 0,
    })
}

fn way() -> (Pathway, Link) {
    let link = Link::new(
        "127.0.0.1:4433".parse().unwrap(),
        "127.0.0.1:9000".parse().unwrap(),
    );
    (link.into(), link)
}

fn is_routed(router: &QuicRouter, packet: &Packet) -> bool {
    router.find_entry(packet, &way().1).is_some()
}

#[tokio::test]
async fn empty_cid_routes_by_peer_address() {
    let router = router();
    let (inbox, mut rcvd_pkt) = channel::new();
    let route = router.insert(way().1.dst.into(), inbox);
    let (pathway, link) = way();
    router.deliver(packet(ConnectionId::default()), pathway, link);
    assert!(rcvd_pkt.initial.recv().await.is_some());
    drop(route);
    assert!(!is_routed(&router, &packet(ConnectionId::default())));
}

#[tokio::test]
async fn old_entry_cannot_remove_a_replacement() {
    let router = router();
    let cid = ConnectionId::from_slice(b"replaced");
    let (old_inbox, _) = channel::new();
    let old = router.insert(cid.into(), old_inbox);
    let (replacement, mut rcvd_pkt) = channel::new();
    let current = router.insert(cid.into(), replacement);
    drop(old);
    let (pathway, link) = way();
    router.deliver(packet(cid), pathway, link);
    assert!(rcvd_pkt.initial.recv().await.is_some());
    drop(current);
    assert!(!is_routed(&router, &packet(cid)));
}

#[tokio::test]
async fn incoming_initial_uses_the_router_callback() {
    let router = router();
    let incoming = Arc::new(Mutex::new(None));
    let delivered = incoming.clone();
    router.on_incoming(move |packet, pathway, link| {
        *delivered.lock().unwrap() = Some((packet, pathway, link));
    });
    let cid = ConnectionId::from_slice(b"unrouted");
    let mut handshake = match packet(cid) {
        Packet::Data(packet) => packet,
        _ => unreachable!(),
    };
    handshake.header = DataHeader::Long(long::DataHeader::Handshake(
        LongHeaderBuilder::with_cid(cid, cid).handshake(),
    ));
    let (pathway, link) = way();
    router.deliver(Packet::Data(handshake), pathway, link);
    assert!(incoming.lock().unwrap().is_none());

    let (pathway, link) = way();
    router.deliver(packet(cid), pathway, link);
    let (received, pathway, link) = incoming.lock().unwrap().take().unwrap();
    assert_eq!(*received.dcid(), cid);
    assert_eq!((pathway, link), way());
}

#[derive(Clone, Default)]
struct IssuedFrames(Arc<Mutex<Vec<NewConnectionIdFrame>>>);

impl SendFrame<NewConnectionIdFrame> for IssuedFrames {
    fn send_frame<I: IntoIterator<Item = NewConnectionIdFrame>>(&self, frames: I) {
        self.0.lock().unwrap().extend(frames);
    }
}

#[tokio::test]
async fn registry_routes_issued_cids_and_forwards_frames() {
    let router = router();
    let (inbox, mut rcvd_pkt) = channel::new();
    let frames = IssuedFrames::default();
    let registry = router.registry_on_issuing_scid(inbox, frames.clone());
    let first = registry.gen_unique_cid();
    let second = registry.gen_unique_cid();
    assert_ne!(first, second);
    let frame = NewConnectionIdFrame::new(first, 1u32.into(), 0u32.into());
    registry.send_frame([frame]);
    assert_eq!(*frames.0.lock().unwrap(), vec![frame]);
    let (pathway, link) = way();
    router.deliver(packet(first), pathway, link);
    assert!(rcvd_pkt.initial.recv().await.is_some());
    registry.retire_cid(first);
    assert!(!is_routed(&router, &packet(first)));
    assert!(is_routed(&router, &packet(second)));
    registry.retire_cid(second);
}
