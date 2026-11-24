use std::{
    io::{self, IoSlice},
    sync::Arc,
    time::Duration,
};

use qbase::net::{addr::EndpointAddr, route::Link};
use qprotocol::{
    Dock, UdpSocket,
    protocol::{ForwardProtocol, QuicProtocol, StunProtocol, stun::StunError},
    topology::Topology,
};
use tokio::time::timeout;

fn isolated_dock() -> Arc<Dock> {
    Dock::new(Arc::new(Topology::new(Arc::new(StunProtocol::new()), Arc::new(ForwardProtocol::new()), Arc::new(QuicProtocol::new()))))
}

#[tokio::test]
async fn bind_sends_on_the_selected_interface_and_drop_unregisters() {
    for ifindex in [0, crate::common::loopback_ifindex()] {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let dock = isolated_dock();
            dock.with_socket_factory(Arc::new(move |addr| UdpSocket::bind(addr, ifindex)));
            let socket = dock.ephemeral_socket(bind.parse().unwrap()).unwrap();
            let raw = socket.socket().clone();
            let bound = raw.local_addr().unwrap();
            assert_eq!(raw.ifindex(), ifindex);
            let peer = tokio::net::UdpSocket::bind(bind).await.unwrap();
            let link = Link::new(bound, peer.local_addr().unwrap());
            assert_eq!(socket.send(&[IoSlice::new(b"probe")], link).await.unwrap(), 1);
            let mut bytes = [0; 16];
            let (size, source) = timeout(Duration::from_secs(1), peer.recv_from(&mut bytes)).await.unwrap().unwrap();
            assert_eq!(&bytes[..size], b"probe");
            assert_eq!(source, bound);

            drop(socket);
            while dock.find_socket(bound).is_some() {
                tokio::task::yield_now().await;
            }
            assert!(dock.topology().quic().find_socket(EndpointAddr::direct(bound)).is_none());
        }
    }
}

#[tokio::test]
async fn bind_receives_quic_and_drop_unregisters_even_with_a_live_udp_handle() {
    let dock = isolated_dock();
    let stun = dock.topology().stun();
    let quic = dock.topology().quic();
    let (sent, mut received) = tokio::sync::mpsc::unbounded_channel();
    quic.on_receive(move |packet, pathway, _| {
        let _ = sent.send((packet, pathway));
    });
    let socket = dock.ephemeral_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let raw = socket.socket().clone();
    let bound = raw.local_addr().unwrap();
    let endpoint = EndpointAddr::direct(bound);
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = [0x40, 1, 2, 3];
    peer.send_to(&packet, bound).await.unwrap();
    let (received_packet, pathway) = timeout(Duration::from_secs(1), received.recv()).await.unwrap().unwrap();
    assert_eq!(received_packet.as_ref(), packet);
    assert_eq!(pathway.local(), endpoint);

    drop(socket);
    while dock.find_socket(bound).is_some() {
        tokio::task::yield_now().await;
    }
    assert!(dock.find_socket(bound).is_none());
    assert!(quic.find_socket(endpoint).is_none());
    assert_eq!(raw.local_addr().unwrap(), bound);
    let error = stun.detect_outer(bound, peer.local_addr().unwrap()).await.unwrap_err();
    assert!(matches!(error, StunError::Io(error) if error.kind() == io::ErrorKind::NotFound));
}

#[tokio::test]
async fn failed_quic_registration_rolls_back_dock_and_preserves_the_existing_alias() {
    let dock = isolated_dock();
    let stun = dock.topology().stun();
    let quic = dock.topology().quic();
    let existing = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap(), crate::common::loopback_ifindex()).unwrap());
    let reservation = UdpSocket::bind("127.0.0.1:0".parse().unwrap(), crate::common::loopback_ifindex()).unwrap();
    let bound = reservation.local_addr().unwrap();
    let endpoint = EndpointAddr::direct(bound);
    quic.register(endpoint, &existing).unwrap();
    drop(reservation);

    let result = dock.ephemeral_socket(bound);
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::AddrInUse));
    assert!(dock.find_socket(bound).is_none());
    assert!(Arc::ptr_eq(&quic.find_socket(endpoint).unwrap(), &existing));
    let error = stun.detect_outer(bound, existing.local_addr().unwrap()).await.unwrap_err();
    assert!(matches!(error, StunError::Io(error) if error.kind() == io::ErrorKind::NotFound));
    quic.unregister(endpoint, &existing);
}

#[tokio::test]
async fn cancelling_the_owner_releases_the_receive_task_and_port() {
    let dock = isolated_dock();
    let quic = dock.topology().quic();
    let socket = dock.ephemeral_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = socket.socket().local_addr().unwrap();
    let weak = Arc::downgrade(socket.socket());
    let task = tokio::spawn(async move {
        let _socket = socket;
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    while dock.find_socket(bound).is_some() {
        tokio::task::yield_now().await;
    }
    assert!(dock.find_socket(bound).is_none());
    assert!(quic.find_socket(EndpointAddr::direct(bound)).is_none());
    timeout(Duration::from_secs(1), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let rebound = UdpSocket::bind(bound, crate::common::loopback_ifindex()).unwrap();
    assert_eq!(rebound.local_addr().unwrap(), bound);
}
