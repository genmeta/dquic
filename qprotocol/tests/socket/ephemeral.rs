use std::{io, sync::Arc, time::Duration};

use qbase::net::addr::EndpointAddr;
use qprotocol::{Dock, EphemeralSocket, UdpSocket, protocol::stun::StunError};
use tokio::time::timeout;

#[tokio::test]
async fn bind_receives_quic_and_drop_unregisters_even_with_a_live_udp_handle() {
    let dock = Dock::global();
    let stun = dock.topology().stun();
    let quic = dock.topology().quic();
    let (sent, mut received) = tokio::sync::mpsc::unbounded_channel();
    quic.on_receive(move |packet, pathway, _| {
        let _ = sent.send((packet, pathway));
    });
    let socket = EphemeralSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let raw = socket.udp_socket().clone();
    let bound = raw.local_addr().unwrap();
    let endpoint = EndpointAddr::direct(bound);
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = [0x40, 1, 2, 3];
    peer.send_to(&packet, bound).await.unwrap();
    let (received_packet, pathway) = timeout(Duration::from_secs(1), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received_packet.as_ref(), packet);
    assert_eq!(pathway.local(), endpoint);

    drop(socket);
    assert!(dock.find_socket(bound).is_none());
    assert!(quic.find_socket(endpoint).is_none());
    assert_eq!(raw.local_addr().unwrap(), bound);
    let error = stun
        .detect_outer(bound, peer.local_addr().unwrap())
        .await
        .unwrap_err();
    assert!(matches!(error, StunError::Io(error) if error.kind() == io::ErrorKind::NotFound));
}

#[tokio::test]
async fn failed_quic_registration_rolls_back_dock_and_preserves_the_existing_alias() {
    let dock = Dock::global();
    let stun = dock.topology().stun();
    let quic = dock.topology().quic();
    let existing = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let reservation = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = reservation.local_addr().unwrap();
    let endpoint = EndpointAddr::direct(bound);
    quic.register(endpoint, &existing).unwrap();
    drop(reservation);

    let result = EphemeralSocket::bind(bound);
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::AddrInUse));
    assert!(dock.find_socket(bound).is_none());
    assert!(Arc::ptr_eq(&quic.find_socket(endpoint).unwrap(), &existing));
    let error = stun
        .detect_outer(bound, existing.local_addr().unwrap())
        .await
        .unwrap_err();
    assert!(matches!(error, StunError::Io(error) if error.kind() == io::ErrorKind::NotFound));
    quic.unregister(existing.local_addr().unwrap());
}

#[tokio::test]
async fn old_owner_does_not_remove_replacement_registrations() {
    let dock = Dock::global();
    let quic = dock.topology().quic();
    let socket = EphemeralSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let raw = socket.udp_socket().clone();
    let bound = raw.local_addr().unwrap();
    let endpoint = EndpointAddr::direct(bound);
    assert!(dock.remove(&raw));
    assert!(dock.add(raw.clone()).unwrap().is_some());

    drop(socket);
    assert!(Arc::ptr_eq(&dock.find_socket(bound).unwrap(), &raw));
    assert!(Arc::ptr_eq(&quic.find_socket(endpoint).unwrap(), &raw));
    assert!(dock.remove(&raw));
}

#[tokio::test]
async fn cancelling_the_owner_releases_the_receive_task_and_port() {
    let dock = Dock::global();
    let quic = dock.topology().quic();
    let socket = EphemeralSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = socket.udp_socket().local_addr().unwrap();
    let weak = Arc::downgrade(socket.udp_socket());
    let task = tokio::spawn(async move {
        let _socket = socket;
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(dock.find_socket(bound).is_none());
    assert!(quic.find_socket(EndpointAddr::direct(bound)).is_none());
    timeout(Duration::from_secs(1), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let rebound = UdpSocket::bind(bound).unwrap();
    assert_eq!(rebound.local_addr().unwrap(), bound);
}
