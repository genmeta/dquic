use std::{
    io::{self, IoSlice},
    net::UdpSocket as StdUdpSocket,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    datagram::{Datagram, be_datagram},
    net::{
        addr::EndpointAddr,
        route::{Link, Pathway},
    },
};
use qprotocol::{QuicProtocol, UdpSocket};

fn receiver() -> StdUdpSocket {
    let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    socket
}

#[tokio::test]
async fn register_and_deliver_by_endpoint() {
    let raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let endpoint = EndpointAddr::direct(raw.local_addr().unwrap());
    let protocol = QuicProtocol::new();
    let delivered = Arc::new(AtomicUsize::new(0));
    protocol.on_receive({
        let delivered = delivered.clone();
        move |_, _, _| {
            delivered.fetch_add(1, Ordering::Relaxed);
        }
    });

    protocol.register(endpoint, &raw).unwrap();
    assert!(protocol.register(endpoint, &raw).is_err());
    let link = Link::new(endpoint.addr(), "127.0.0.1:4433".parse().unwrap());
    assert!(protocol.on_packet(BytesMut::from(&b"quic"[..]), link.into(), link));
    assert_eq!(delivered.load(Ordering::Relaxed), 1);

    protocol.unregister(raw.local_addr().unwrap());
    assert!(protocol.find_socket(endpoint).is_none());
}

#[tokio::test]
async fn direct_pathway_sends_a_batch_without_splitting_datagrams() {
    let raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let receiver = receiver();
    let local = EndpointAddr::direct(raw.local_addr().unwrap());
    let remote = EndpointAddr::direct(receiver.local_addr().unwrap());
    let protocol = QuicProtocol::new();
    protocol.register(local, &raw).unwrap();

    let packets = [vec![0x40; 4], vec![0x41; 1200], vec![0x42; 73]];
    let slices = packets.each_ref().map(|packet| IoSlice::new(packet));
    let mut sent = 0;
    while sent < packets.len() {
        let count = protocol
            .send(Pathway::new(local, remote), &slices[sent..])
            .await
            .unwrap();
        assert!(count > 0);
        sent += count;
    }
    let mut received = [0; 1500];
    for packet in packets {
        let (len, source) = receiver.recv_from(&mut received).unwrap();
        assert_eq!(&received[..len], packet);
        assert_eq!(source, raw.local_addr().unwrap());
    }
}

#[tokio::test]
async fn mediated_pathway_sends_a_batch_of_forward_datagrams_to_agent() {
    let raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let receiver = receiver();
    let local = EndpointAddr::direct(raw.local_addr().unwrap());
    let remote = EndpointAddr::mediate(
        receiver.local_addr().unwrap(),
        "127.0.0.1:4433".parse().unwrap(),
    );
    let pathway = Pathway::new(local, remote);
    let protocol = QuicProtocol::new();
    protocol.register(local, &raw).unwrap();

    let packets = [vec![0x40; 4], vec![0x41; 1200], vec![0x42; 73]];
    let slices = packets.each_ref().map(|packet| IoSlice::new(packet));
    let mut sent = 0;
    while sent < packets.len() {
        let count = protocol.send(pathway, &slices[sent..]).await.unwrap();
        assert!(count > 0);
        sent += count;
    }
    let mut received = [0; 1500];
    for packet in packets {
        let (len, source) = receiver.recv_from(&mut received).unwrap();
        let Datagram::Forward(decoded_pathway, payload) =
            be_datagram(BytesMut::from(&received[..len])).unwrap()
        else {
            panic!("expected Forward datagram");
        };
        assert_eq!(decoded_pathway, pathway);
        assert_eq!(payload.into_raw().as_ref(), packet);
        assert_eq!(source, raw.local_addr().unwrap());
    }
}

#[tokio::test]
async fn unavailable_local_endpoint_fails_to_send() {
    let local = EndpointAddr::direct("127.0.0.1:4433".parse().unwrap());
    let remote = EndpointAddr::direct("127.0.0.1:4434".parse().unwrap());
    let protocol = QuicProtocol::new();

    let error = protocol
        .send(Pathway::new(local, remote), &[IoSlice::new(&[0x40])])
        .await
        .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::NotConnected);
}

#[tokio::test]
async fn reclaimed_udp_socket_fails_to_send_and_clears_registration() {
    let protocol = QuicProtocol::new();
    let local = {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let local = EndpointAddr::direct(raw.local_addr().unwrap());
        protocol.register(local, &raw).unwrap();
        local
    };
    let remote = EndpointAddr::direct("127.0.0.1:4434".parse().unwrap());

    let error = protocol
        .send(Pathway::new(local, remote), &[IoSlice::new(&[0x40])])
        .await
        .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    assert!(protocol.find_socket(local).is_none());
}

#[tokio::test]
async fn unregister_bound_clears_all_its_endpoints_and_preserves_other_bindings() {
    let protocol = QuicProtocol::new();
    let first = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let second = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let bound = first.local_addr().unwrap();
    let direct = EndpointAddr::direct(bound);
    let outer = EndpointAddr::direct("8.8.8.8:4567".parse().unwrap());
    let mediated = EndpointAddr::mediate("127.0.0.1:3478".parse().unwrap(), outer.addr());
    let other = EndpointAddr::direct(second.local_addr().unwrap());
    protocol.register(direct, &first).unwrap();
    protocol.register(outer, &first).unwrap();
    protocol.register(mediated, &first).unwrap();
    protocol.register(other, &second).unwrap();
    protocol.unregister(bound);
    assert!(protocol.find_socket(direct).is_none());
    assert!(protocol.find_socket(outer).is_none());
    assert!(protocol.find_socket(mediated).is_none());
    assert!(Arc::ptr_eq(&protocol.find_socket(other).unwrap(), &second));
}
