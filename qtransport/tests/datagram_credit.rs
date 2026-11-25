mod common;

use std::sync::Arc;

use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    frame::PingFrame,
    net::{
        addr::EndpointAddr,
        route::{Link, Pathway},
    },
    packet::LongHeaderBuilder,
    role::Role,
};
use qrecovery::journal::ArcSentJournal;
use qtransport::{packet::channel, recv::recv_ih_pkt_and_deliver_frames, router::QuicRouter};

async fn receive_coalesced_initials(corrupt_packets: usize, known_path: bool, copies: usize) -> Option<usize> {
    let scid = ConnectionId::from_slice(b"localcid");
    let paths = common::initial_paths(Role::Server, scid, ConnectionId::from_slice(b"original"), common::initial_keys(true));
    let local = "127.0.0.1:30001".parse().unwrap();
    let remote = "127.0.0.1:30002".parse().unwrap();
    let pathway = Pathway::new(EndpointAddr::direct(local), EndpointAddr::direct(remote));
    if known_path {
        paths.add_path(pathway);
    }
    let router = Arc::new(QuicRouter::new());
    let (inbox, received) = channel::new();
    router.insert(scid.into(), inbox, ());

    let keys = common::initial_keys(false);
    let journal = ArcSentJournal::default();
    let mut datagram = BytesMut::new();
    for index in 0..2 {
        let header = LongHeaderBuilder::with_cid(scid, ConnectionId::from_slice(b"peercid0")).initial(vec![]);
        let mut packet = common::seal(header, &keys.sealing, &journal, [&mut PingFrame]).unwrap();
        if index < corrupt_packets {
            let last = packet.len() - 1;
            packet[last] ^= 1;
        }
        datagram.extend_from_slice(&packet);
    }
    // Neither packet includes these bytes; they still belong to the datagram.
    datagram.resize(2500, 0);
    for _ in 0..copies {
        router.receive(datagram.clone(), pathway, Link::new(local, remote), 8);
    }
    drop(router);
    recv_ih_pkt_and_deliver_frames((received.initial, None), common::initial_space(&paths.spaces), paths.clone()).await;

    let path = paths.entries.lock().unwrap().get(&pathway).cloned();
    let credit = path.and_then(|path| common::path_credit(&path));
    paths.terminator.terminate();
    paths.clean();
    credit
}

#[tokio::test]
async fn coalesced_packets_credit_the_entire_datagram_once() {
    assert_eq!(receive_coalesced_initials(0, true, 1).await, Some(3 * 2500));
}

#[tokio::test]
async fn authentication_failure_does_not_lose_datagram_credit() {
    assert_eq!(receive_coalesced_initials(1, true, 1).await, Some(3 * 2500));
}

#[tokio::test]
async fn discarded_packets_still_credit_the_attributable_datagram() {
    assert_eq!(receive_coalesced_initials(2, true, 1).await, Some(3 * 2500));
}

#[tokio::test]
async fn duplicate_packets_still_credit_each_received_datagram() {
    assert_eq!(receive_coalesced_initials(0, true, 2).await, Some(3 * 2500 * 2));
}

#[tokio::test]
async fn invalid_unknown_path_does_not_create_a_path_or_save_credit() {
    assert_eq!(receive_coalesced_initials(2, false, 1).await, None);
    assert_eq!(receive_coalesced_initials(1, false, 1).await, Some(0));
}

#[tokio::test]
async fn first_valid_packet_on_an_unknown_path_credits_its_datagram() {
    assert_eq!(receive_coalesced_initials(0, false, 1).await, Some(3 * 2500));
}
