use std::{io, net::SocketAddr, sync::Arc};

use qbase::net::addr::EndpointAddr;
use qprotocol::{
    AddressBook, Dock, UdpSocket,
    protocol::{forward::ForwardProtocol, quic::QuicProtocol, stun::StunProtocol},
    topology::Topology,
};

#[tokio::test]
async fn one_socket_starts_one_task() {
    let quic = Arc::new(QuicProtocol::new());
    let topology = Arc::new(Topology::new(
        Arc::new(StunProtocol::new()),
        Arc::new(ForwardProtocol::new()),
        quic,
    ));
    let dock = Dock::new(topology);
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());

    assert!(dock.add(socket.clone()).unwrap().is_some());
    assert!(dock.add(socket.clone()).unwrap().is_none());
    assert_eq!(dock.len(), 1);
    assert!(dock.remove(&socket));
    assert!(dock.is_empty());
}

#[tokio::test]
async fn concurrent_adds_register_one_receiver() {
    let dock = isolated_dock();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let barrier = std::sync::Barrier::new(2);
    let runtime = tokio::runtime::Handle::current();
    let results = std::thread::scope(|scope| {
        let workers = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    let _runtime = runtime.enter();
                    barrier.wait();
                    dock.add(socket.clone()).unwrap()
                })
            })
            .collect::<Vec<_>>();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results.into_iter().filter(|added| added.is_some()).count(),
        1
    );
    assert_eq!(dock.len(), 1);
    assert!(dock.remove(&socket));
}

#[tokio::test]
async fn old_receiver_cleanup_preserves_a_new_registration_of_the_same_socket() {
    let dock = Dock::global();
    let stun = dock.topology().stun();
    let old = qprotocol::EphemeralSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let socket = old.udp_socket().clone();
    let bound = socket.local_addr().unwrap();
    assert!(dock.remove(&socket));
    let current = dock.add(socket.clone()).unwrap().unwrap();

    // Dropping the old owner invokes cleanup with its original registration ID.
    drop(old);
    assert!(Arc::ptr_eq(&dock.find_socket(bound).unwrap(), &socket));
    assert!(!current.is_finished());
    stun.set_change_server(
        bound,
        qprotocol::protocol::stun::ChangeServer {
            outer_address: bound,
            change_port: bound.port() ^ 1,
            change_address: SocketAddr::from(([127, 0, 0, 2], bound.port() ^ 1)),
        },
    )
    .unwrap();
    assert!(dock.remove(&socket));
    assert!(dock.find_socket(bound).is_none());
}

fn isolated_dock() -> Arc<Dock> {
    Dock::new(Arc::new(Topology::new(
        Arc::new(StunProtocol::new()),
        Arc::new(ForwardProtocol::new()),
        Arc::new(QuicProtocol::new()),
    )))
}

#[tokio::test]
async fn socket_registration_and_removal_leave_publication_to_the_address_book() {
    let dock = isolated_dock();
    let addresses = AddressBook::global();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let bound = socket.local_addr().unwrap();
    let direct = EndpointAddr::direct(bound);
    let outer = EndpointAddr::direct("8.8.8.8:4567".parse().unwrap());
    let relay = EndpointAddr::mediate("8.8.4.4:3478".parse().unwrap(), outer.addr());
    let mut events = addresses.subscribe_punch(qbase::net::route::Scopes::ALL);
    dock.add(socket.clone()).unwrap().unwrap();
    assert!(addresses.mdns_endpoints(bound).is_empty());
    addresses.insert_inner(&socket, direct).unwrap();
    assert_eq!(addresses.mdns_endpoints(bound).as_ref(), &[direct]);
    assert!(
        matches!(events.try_recv().unwrap(), qprotocol::AddressEvent::Added { endpoint, .. } if endpoint == direct)
    );
    dock.topology().quic().register(outer, &socket).unwrap();
    dock.topology().quic().register(relay, &socket).unwrap();
    addresses.insert_outer(&socket, outer).unwrap();
    addresses.set_nat(bound, qbase::net::NatType::RestrictedCone);

    let other = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    dock.add(other.clone()).unwrap().unwrap();
    assert!(dock.remove_bound(bound));
    for alias in [direct, outer, relay] {
        assert!(dock.topology().quic().find_socket(alias).is_none());
    }
    assert_eq!(addresses.mdns_endpoints(bound).as_ref(), &[direct]);
    assert!(addresses.ddns_endpoints().contains(&outer));
    assert_eq!(
        addresses.nat(bound),
        Some(qbase::net::NatType::RestrictedCone)
    );
    assert!(Arc::ptr_eq(
        &dock.find_socket(other.local_addr().unwrap()).unwrap(),
        &other
    ));
    let error = dock
        .topology()
        .stun()
        .detect_outer(bound, other.local_addr().unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(error, qprotocol::protocol::stun::StunError::Io(error) if error.kind() == io::ErrorKind::NotFound)
    );
    addresses.remove_bound(bound);
    assert!(addresses.mdns_endpoints(bound).is_empty());
    assert!(!addresses.ddns_endpoints().contains(&outer));
    assert_eq!(addresses.nat(bound), None);
    let mut removed = false;
    while let Ok(event) = events.try_recv() {
        removed |= matches!(event, qprotocol::AddressEvent::BoundRemoved { bound: candidate } if candidate == bound);
    }
    assert!(
        removed,
        "punch subscriptions must learn that the binding was removed"
    );
}

#[tokio::test]
async fn failed_quic_registration_rolls_back_stun_and_preserves_the_existing_alias() {
    let dock = isolated_dock();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let bound = socket.local_addr().unwrap();
    let direct = EndpointAddr::direct(bound);
    let existing = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    dock.topology().quic().register(direct, &existing).unwrap();
    assert!(dock.add(socket.clone()).is_err());
    assert!(dock.is_empty());
    assert!(Arc::ptr_eq(
        &dock.topology().quic().find_socket(direct).unwrap(),
        &existing
    ));
    let error = dock
        .topology()
        .stun()
        .detect_outer(bound, "127.0.0.1:9".parse().unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(error, qprotocol::protocol::stun::StunError::Io(error) if error.kind() == io::ErrorKind::NotFound)
    );
    dock.topology()
        .quic()
        .unregister(existing.local_addr().unwrap());
    assert!(dock.add(socket).unwrap().is_some());
}

#[tokio::test]
async fn shutdown_and_drop_revoke_aliases_with_live_socket_handles() {
    for shutdown in [true, false] {
        let dock = isolated_dock();
        let topology = dock.topology().clone();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let bound = socket.local_addr().unwrap();
        let direct = EndpointAddr::direct(bound);
        let handle = dock.add(socket.clone()).unwrap().unwrap();
        if shutdown {
            dock.shutdown();
        }
        drop(dock);
        assert!(topology.quic().find_socket(direct).is_none());
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !handle.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn receive_task_exit_removes_the_registration_and_protocol_aliases() {
    use qbase::{datagram::forward::Payload, net::route::Pathway};
    let dock = isolated_dock();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let bound = socket.local_addr().unwrap();
    let direct = EndpointAddr::direct(bound);
    dock.add(socket.clone()).unwrap().unwrap();
    dock.topology().forward().serve(bound, &socket);
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Forwarding to an IPv6 destination from an IPv4 socket fails in the receive loop.
    let pathway: Pathway = Pathway::new(
        "[::1]:12345".parse::<SocketAddr>().unwrap().into(),
        "[::1]:9".parse::<SocketAddr>().unwrap().into(),
    );
    let offset = 2 + pathway.local().encoding_size() + pathway.remote().encoding_size();
    let mut bytes = bytes::BytesMut::zeroed(offset + 1);
    bytes[offset] = 0x40;
    let packet = Payload::from_raw(&pathway, bytes, offset).unwrap();
    peer.send_to(packet.as_ref(), bound).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !dock.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(dock.topology().quic().find_socket(direct).is_none());
    assert_eq!(socket.local_addr().unwrap(), bound);
}
