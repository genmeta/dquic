use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use qbase::{
    cid::{ArcLocalCids, ConnectionId, GenUniqueCid, RetireCid},
    frame::{NewConnectionIdFrame, io::SendFrame},
    net::route::{Link, Pathway},
    packet::{DataHeader, DataPacket, GetDcid, LongHeaderBuilder, long},
    role::Role,
};
use qtransport::{
    packet::channel,
    router::{Packet, QuicRouter},
};

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
    router.insert(way().1.dst.into(), inbox, ());
    let (pathway, link) = way();
    router.deliver(packet(ConnectionId::default()), pathway, link);
    assert!(rcvd_pkt.initial.recv().await.is_some());
    router.remove(&way().1.dst.into());
    assert!(!is_routed(&router, &packet(ConnectionId::default())));
}

#[tokio::test]
async fn old_registry_cannot_retire_a_replacement() {
    let router = router();
    let cid = ConnectionId::from_slice(b"replaced");
    let (old_inbox, _) = channel::new();
    let old = router.insert(cid.into(), old_inbox, ());
    let (replacement, mut rcvd_pkt) = channel::new();
    let current = router.insert(cid.into(), replacement, ());
    old.retire_cid(cid);
    let (pathway, link) = way();
    router.deliver(packet(cid), pathway, link);
    assert!(rcvd_pkt.initial.recv().await.is_some());
    current.retire_cid(cid);
    assert!(!is_routed(&router, &packet(cid)));
}

#[tokio::test]
async fn retained_route_drops_late_initials_after_the_receiver_closes() {
    let router = router();
    let incoming = Arc::new(Mutex::new(0));
    let observed = incoming.clone();
    router.on_incoming(move |_, _, _| *observed.lock().unwrap() += 1);
    let cid = ConnectionId::from_slice(b"original");
    let (inbox, received) = channel::new();
    let registry = router.insert(cid.into(), inbox, ());
    drop(received);

    let (pathway, link) = way();
    router.deliver(packet(cid), pathway, link);
    assert_eq!(*incoming.lock().unwrap(), 0);

    registry.retire_cid(cid);
    router.deliver(packet(cid), pathway, link);
    assert_eq!(*incoming.lock().unwrap(), 1);
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

#[test]
fn server_local_cids_clear_the_original_route() {
    let router = router();
    let odcid = ConnectionId::from_slice(b"original");
    let (inbox, received) = channel::new();
    let frames = IssuedFrames::default();
    let registry = router.insert(odcid.into(), inbox, frames.clone());
    let scid = registry.gen_unique_cid();
    let local = ArcLocalCids::new(Role::Server, odcid, scid, registry);
    let issued = *frames.0.lock().unwrap()[0].connection_id();
    drop(received);
    assert!(is_routed(&router, &packet(odcid)));

    local.clear();
    for cid in [odcid, scid, issued] {
        assert!(!is_routed(&router, &packet(cid)));
    }

    let (replacement, _) = channel::new();
    router.insert(odcid.into(), replacement, ());
    local.clear();
    drop(local);
    assert!(is_routed(&router, &packet(odcid)));
}

#[test]
fn local_cids_drop_retires_odcid_only_for_servers() {
    for role in [Role::Client, Role::Server] {
        let router = router();
        let odcid = ConnectionId::from_slice(b"original");
        let (inbox, _) = channel::new();
        let frames = IssuedFrames::default();
        let registry = router.insert(odcid.into(), inbox, frames.clone());
        let scid = registry.gen_unique_cid();
        let local = ArcLocalCids::new(role, odcid, scid, registry);
        let issued = *frames.0.lock().unwrap()[0].connection_id();
        let clone = local.clone();
        drop(local);
        for cid in [odcid, scid, issued] {
            assert!(is_routed(&router, &packet(cid)));
        }

        drop(clone);
        assert!(!is_routed(&router, &packet(scid)));
        assert!(!is_routed(&router, &packet(issued)));
        assert_eq!(is_routed(&router, &packet(odcid)), role == Role::Client);
    }
}
