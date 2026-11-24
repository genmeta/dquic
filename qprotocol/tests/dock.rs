#[path = "../../qudp/tests/common/mod.rs"]
mod common;

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use qbase::net::addr::EndpointAddr;
use qprotocol::{Dock, EphemeralSocket, ForwardProtocol, QuicProtocol, StunProtocol, UdpSocket, topology::Topology};
use tokio::time::timeout;

fn isolated_dock() -> Arc<Dock> {
    Dock::new(Arc::new(Topology::new(Arc::new(StunProtocol::new()), Arc::new(ForwardProtocol::new()), Arc::new(QuicProtocol::new()))))
}

async fn wait_until(mut ready: impl FnMut() -> bool) {
    timeout(Duration::from_secs(1), async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn fail_reception(dock: &Dock, socket: &Arc<UdpSocket>) {
    use qbase::{datagram::forward::Payload, net::route::Pathway};

    let bound = socket.local_addr().unwrap();
    dock.topology().forward().serve(bound, socket);
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // An IPv6 destination cannot be reached through this IPv4 forwarding socket.
    let pathway: Pathway =
        Pathway::new("[::1]:12345".parse::<SocketAddr>().unwrap().into(), "[::1]:9".parse::<SocketAddr>().unwrap().into());
    let offset = 2 + pathway.local().encoding_size() + pathway.remote().encoding_size();
    let mut bytes = bytes::BytesMut::zeroed(offset + 1);
    bytes[offset] = 0x40;
    let packet = Payload::from_raw(&pathway, bytes, offset).unwrap();
    peer.send_to(packet.as_ref(), bound).await.unwrap();
}

async fn heartbeat_request(server: &tokio::net::UdpSocket, bound: SocketAddr) -> qprotocol::protocol::stun::TransactionId {
    use qbase::datagram::{Datagram, be_datagram};
    use qprotocol::protocol::stun::Message;

    // Yield without advancing Tokio's paused clock while waiting for real UDP I/O.
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    let mut bytes = [0; 512];
    loop {
        match server.try_recv_from(&mut bytes) {
            Ok((len, source)) => {
                assert_eq!(source, bound);
                let Datagram::Stun(id, Message::Request(request)) = be_datagram(bytes::BytesMut::from(&bytes[..len])).unwrap() else {
                    panic!("expected heartbeat binding request");
                };
                assert_eq!(request.change_request().unwrap_or(0), 0);
                return id;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(std::time::Instant::now() < deadline, "heartbeat binding request did not arrive");
                tokio::task::yield_now().await;
            }
            Err(error) => panic!("heartbeat receive failed: {error}"),
        }
    }
}

async fn heartbeat_response(
    dock: &Dock,
    socket: &Arc<UdpSocket>,
    node: SocketAddr,
    id: qprotocol::protocol::stun::TransactionId,
    outer: SocketAddr,
) {
    use qbase::net::route::Link;
    use qprotocol::protocol::stun::{Attr, Message, Response};

    dock.topology()
        .stun()
        .on_datagram(
            socket,
            id,
            Message::Response(Response::with(vec![Attr::MappedAddress(outer)])),
            Link::new(socket.local_addr().unwrap(), node),
        )
        .await
        .unwrap();
    tokio::task::yield_now().await;
}

async fn tick_heartbeat(next: &mut tokio::time::Instant) {
    *next += Duration::from_secs(20);
    tokio::time::advance(*next - tokio::time::Instant::now()).await;
}

#[tokio::test]
async fn default_factory_binds_with_zero_index_and_starts_reception() -> io::Result<()> {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let dock = isolated_dock();
        let (sent, mut received) = tokio::sync::mpsc::unbounded_channel();
        dock.topology().quic().on_receive(move |packet, pathway, _| {
            sent.send((packet, pathway)).unwrap();
        });
        let socket = dock.use_socket(bind.parse().unwrap())?;
        let bound = socket.local_addr()?;
        assert_eq!(socket.ifindex(), 0);
        assert_ne!(bound.port(), 0);
        assert!(Arc::ptr_eq(&dock.find_socket(bound).unwrap(), &socket));
        let peer = tokio::net::UdpSocket::bind(bind).await?;
        let packet = [0x40, 1, 2, 3];
        peer.send_to(&packet, bound).await?;
        let (received_packet, pathway) = timeout(Duration::from_secs(1), received.recv()).await?.unwrap();
        assert_eq!(received_packet.as_ref(), packet);
        assert_eq!(pathway.local(), EndpointAddr::direct(bound));
    }
    Ok(())
}

#[tokio::test]
async fn external_factory_selects_the_interface_for_both_socket_types() {
    let dock = isolated_dock();
    let ifindex = common::loopback_ifindex();
    let (sent, mut created) = tokio::sync::mpsc::unbounded_channel();
    dock.with_socket_factory(Arc::new(move |addr| {
        sent.send(addr).unwrap();
        UdpSocket::bind(addr, ifindex)
    }));
    let addr = "127.0.0.1:0".parse().unwrap();
    let (sent, mut closed) = tokio::sync::mpsc::unbounded_channel();
    dock.on_socket_closed(Arc::new(move |bound| sent.send(bound).unwrap()));
    let socket = dock.use_socket(addr).unwrap();
    let ephemeral: EphemeralSocket = dock.ephemeral_socket(addr).unwrap();
    let bound = ephemeral.socket().local_addr().unwrap();
    assert_eq!(created.try_recv().unwrap(), addr);
    assert_eq!(created.try_recv().unwrap(), addr);
    assert!(created.try_recv().is_err());
    assert_eq!(socket.ifindex(), ifindex);
    assert_eq!(ephemeral.socket().ifindex(), ifindex);
    assert_eq!(dock.len(), 2);
    drop(ephemeral);
    wait_until(|| dock.find_socket(bound).is_none()).await;
    assert_eq!(dock.len(), 1);
    assert!(closed.try_recv().is_err());
}

#[tokio::test]
async fn factory_can_replace_itself_without_holding_a_configuration_lock() {
    let dock = isolated_dock();
    let weak = Arc::downgrade(&dock);
    dock.with_socket_factory(Arc::new(move |addr| {
        weak.upgrade().unwrap().with_socket_factory(Arc::new(|_| Err(io::ErrorKind::PermissionDenied.into())));
        UdpSocket::bind(addr, 0)
    }));
    let addr = "127.0.0.1:0".parse().unwrap();
    let _socket = dock.use_socket(addr).unwrap();
    assert_eq!(dock.use_socket(addr).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn factory_failure_leaves_no_registration_or_close_notification() {
    let dock = isolated_dock();
    let (sent, mut closed) = tokio::sync::mpsc::unbounded_channel();
    dock.on_socket_closed(Arc::new(move |bound| sent.send(bound).unwrap()));
    dock.with_socket_factory(Arc::new(|_| Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "factory failed"))));
    let addr = "127.0.0.1:0".parse().unwrap();
    assert_eq!(dock.use_socket(addr).unwrap_err().kind(), io::ErrorKind::AddrNotAvailable);
    assert!(matches!(dock.ephemeral_socket(addr), Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable));
    assert!(dock.is_empty());
    assert!(closed.try_recv().is_err());
}

#[tokio::test]
async fn failed_registration_rolls_back_stun_and_preserves_the_existing_alias() {
    let dock = isolated_dock();
    let reservation = UdpSocket::bind("127.0.0.1:0".parse().unwrap(), 0).unwrap();
    let bound = reservation.local_addr().unwrap();
    let existing = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap(), 0).unwrap());
    let endpoint = EndpointAddr::direct(bound);
    dock.topology().quic().register(endpoint, &existing).unwrap();
    let (sent, mut closed) = tokio::sync::mpsc::unbounded_channel();
    dock.on_socket_closed(Arc::new(move |bound| sent.send(bound).unwrap()));
    drop(reservation);
    assert_eq!(dock.use_socket(bound).unwrap_err().kind(), io::ErrorKind::AddrInUse);
    assert!(matches!(dock.ephemeral_socket(bound), Err(error) if error.kind() == io::ErrorKind::AddrInUse));
    assert!(dock.is_empty());
    assert!(closed.try_recv().is_err());
    assert!(Arc::ptr_eq(&dock.topology().quic().find_socket(endpoint).unwrap(), &existing));
    let error = dock.topology().stun().detect_outer(bound, existing.local_addr().unwrap()).await.unwrap_err();
    assert!(matches!(error, qprotocol::protocol::stun::StunError::Io(error) if error.kind() == io::ErrorKind::NotFound));
}

#[tokio::test]
async fn concurrent_creations_only_start_one_receiver_for_a_bound_address() {
    let dock = isolated_dock();
    let reservation = UdpSocket::bind("127.0.0.1:0".parse().unwrap(), 0).unwrap();
    let bound = reservation.local_addr().unwrap();
    drop(reservation);
    let (sent, mut closed) = tokio::sync::mpsc::unbounded_channel();
    dock.on_socket_closed(Arc::new(move |bound| sent.send(bound).unwrap()));
    let barrier = std::sync::Barrier::new(2);
    let runtime = tokio::runtime::Handle::current();
    let results = std::thread::scope(|scope| {
        let workers = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    let _runtime = runtime.enter();
                    barrier.wait();
                    dock.ephemeral_socket(bound)
                })
            })
            .collect::<Vec<_>>();
        workers.into_iter().map(|worker| worker.join().unwrap()).collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| matches!(result, Err(error) if error.kind() == io::ErrorKind::AddrInUse)).count(), 1);
    assert_eq!(dock.len(), 1);
    drop(results);
    wait_until(|| dock.is_empty()).await;
    assert!(dock.is_empty());
    assert!(closed.try_recv().is_err());
}

#[tokio::test]
async fn dropping_a_regular_socket_handle_does_not_stop_its_receiver() {
    let dock = isolated_dock();
    let (sent, mut closed) = tokio::sync::mpsc::unbounded_channel();
    dock.on_socket_closed(Arc::new(move |bound| sent.send(bound).unwrap()));
    let socket = dock.use_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = socket.local_addr().unwrap();
    drop(socket);
    tokio::task::yield_now().await;
    assert!(dock.find_socket(bound).is_some());
    assert!(closed.try_recv().is_err());
}

#[tokio::test]
async fn ephemeral_drop_stops_reception_even_before_the_first_poll() {
    for started in [false, true] {
        let dock = isolated_dock();
        let (sent, mut closed) = tokio::sync::mpsc::unbounded_channel();
        dock.on_socket_closed(Arc::new(move |bound| sent.send(bound).unwrap()));
        let socket = dock.ephemeral_socket("127.0.0.1:0".parse().unwrap()).unwrap();
        let bound = socket.socket().local_addr().unwrap();
        let weak = Arc::downgrade(socket.socket());
        if started {
            tokio::task::yield_now().await;
        }
        drop(socket);
        wait_until(|| weak.upgrade().is_none()).await;
        assert!(dock.is_empty());
        assert!(dock.topology().quic().find_socket(EndpointAddr::direct(bound)).is_none());
        assert!(closed.try_recv().is_err());
        let rebound = dock.ephemeral_socket(bound).unwrap();
        drop(rebound);
        wait_until(|| dock.is_empty()).await;
        assert!(closed.try_recv().is_err());
    }
}

#[tokio::test]
async fn receive_error_cleans_up_and_notifies_the_bound_address() {
    let dock = isolated_dock();
    let (sent, mut closed) = tokio::sync::mpsc::unbounded_channel();
    let weak = Arc::downgrade(&dock);
    dock.on_socket_closed(Arc::new(move |bound| {
        let dock = weak.upgrade().unwrap();
        assert!(dock.find_socket(bound).is_none());
        assert!(dock.topology().quic().find_socket(EndpointAddr::direct(bound)).is_none());
        dock.on_socket_closed(Arc::new(|_| {}));
        sent.send(bound).unwrap();
    }));
    let socket = dock.use_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = socket.local_addr().unwrap();
    fail_reception(&dock, &socket).await;
    assert_eq!(timeout(Duration::from_secs(1), closed.recv()).await.unwrap().unwrap(), bound);
    assert!(dock.is_empty());
    assert!(dock.topology().quic().find_socket(EndpointAddr::direct(bound)).is_none());
    drop(socket);
    tokio::task::yield_now().await;
    assert!(closed.try_recv().is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn fatal_stun_send_error_cleans_up_and_notifies_the_bound_address() {
    use qbase::net::route::Link;

    let dock = isolated_dock();
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    dock.bootstrap([server.local_addr().unwrap()]);
    // Binding succeeds; sending with a nonexistent interface fails at the socket.
    dock.with_socket_factory(Arc::new(|addr| UdpSocket::bind(addr, u32::MAX)));
    let (sent, mut closed) = tokio::sync::mpsc::unbounded_channel();
    dock.on_socket_closed(Arc::new(move |bound| sent.send(bound).unwrap()));
    let socket = dock.use_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = socket.local_addr().unwrap();
    assert_eq!(timeout(Duration::from_secs(1), closed.recv()).await.unwrap().unwrap(), bound);
    assert!(dock.is_empty());
    assert!(dock.topology().quic().find_socket(EndpointAddr::direct(bound)).is_none());
    assert_eq!(qprotocol::ArcAddrBook::global().try_get_nat_type(Link::new(bound, bound)), None);
    assert!(closed.try_recv().is_err());
}

#[tokio::test]
async fn ephemeral_receive_error_cleans_up_without_a_close_callback() {
    let dock = isolated_dock();
    let (sent, mut closed) = tokio::sync::mpsc::unbounded_channel();
    dock.on_socket_closed(Arc::new(move |bound| sent.send(bound).unwrap()));
    let socket = dock.ephemeral_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = socket.socket().local_addr().unwrap();
    let weak = Arc::downgrade(socket.socket());
    fail_reception(&dock, socket.socket()).await;
    wait_until(|| dock.is_empty()).await;
    assert!(dock.topology().quic().find_socket(EndpointAddr::direct(bound)).is_none());
    assert!(closed.try_recv().is_err());
    drop(socket);
    wait_until(|| weak.upgrade().is_none()).await;
    assert!(closed.try_recv().is_err());
}

#[tokio::test]
async fn ephemeral_owner_closes_after_dock_drop_and_releases_its_endpoint() {
    let dock = isolated_dock();
    let topology = dock.topology().clone();
    let (sent, mut closed) = tokio::sync::mpsc::unbounded_channel();
    dock.on_socket_closed(Arc::new(move |bound| sent.send(bound).unwrap()));
    let ephemeral = dock.ephemeral_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = ephemeral.socket().local_addr().unwrap();
    let weak = Arc::downgrade(ephemeral.socket());
    let raw = ephemeral.socket().clone();
    drop(dock);
    assert!(topology.quic().find_socket(EndpointAddr::direct(bound)).is_some());
    drop(ephemeral);
    wait_until(|| topology.quic().find_socket(EndpointAddr::direct(bound)).is_none()).await;
    assert!(topology.quic().find_socket(EndpointAddr::direct(bound)).is_none());
    drop(raw);
    wait_until(|| weak.upgrade().is_none()).await;
    assert!(closed.try_recv().is_err());
}

#[tokio::test]
async fn ephemeral_drop_releases_the_port_without_a_close_callback() {
    let dock = isolated_dock();
    let (sent, mut closed) = tokio::sync::mpsc::unbounded_channel();
    dock.on_socket_closed(Arc::new(move |bound| sent.send(bound).unwrap()));
    let socket = dock.ephemeral_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = socket.socket().local_addr().unwrap();
    let weak = Arc::downgrade(socket.socket());
    drop(socket);
    timeout(Duration::from_secs(1), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(dock.is_empty());
    assert!(dock.topology().quic().find_socket(EndpointAddr::direct(bound)).is_none());
    assert!(closed.try_recv().is_err());
    let rebound = UdpSocket::bind(bound, 0).unwrap();
    assert_eq!(rebound.local_addr().unwrap(), bound);
}

#[tokio::test]
async fn regular_socket_publishes_its_local_endpoint_and_candidate_and_withdraws_on_error() {
    use qbase::net::{NatType, route::Link};

    let dock = isolated_dock();
    let socket = dock.use_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = socket.local_addr().unwrap();
    let endpoint = EndpointAddr::direct(bound);
    let book = qprotocol::ArcAddrBook::global();
    let peer = EndpointAddr::direct(SocketAddr::new(bound.ip(), 9));
    assert!(book.matches(peer).contains(&endpoint));
    assert_eq!(book.try_get_nat_type(Link::new(bound, bound)), Some(NatType::FullCone));
    fail_reception(&dock, &socket).await;
    wait_until(|| dock.is_empty()).await;
    assert!(!book.matches(peer).contains(&endpoint));
    assert_eq!(book.try_get_nat_type(Link::new(bound, bound)), None);
}

#[tokio::test]
async fn bootstrap_drives_mapping_publication_and_nat_candidate_discovery() {
    use qbase::{
        datagram::{
            Datagram, be_datagram,
            stun::{CHANGE_IP, CHANGE_PORT},
        },
        net::{NatType, route::Link},
    };
    use qprotocol::protocol::stun::{Attr, Message, Response};

    let dock = isolated_dock();
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let node = server.local_addr().unwrap();
    let unused = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let v6 = "[::1]:3478".parse().unwrap();
    dock.bootstrap([v6, node, node, unused.local_addr().unwrap()]);
    assert_eq!(&*dock.topology().stun().stun_servers(), &[v6, node, unused.local_addr().unwrap()]);
    let (closed, mut closures) = tokio::sync::mpsc::unbounded_channel();
    dock.on_socket_closed(Arc::new(move |bound| closed.send(bound).unwrap()));
    let socket = dock.use_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = socket.local_addr().unwrap();
    let outer = SocketAddr::new("198.51.100.1".parse().unwrap(), bound.port());
    let changed = SocketAddr::new("127.0.0.2".parse().unwrap(), node.port() ^ 1);
    let book = qprotocol::ArcAddrBook::global();
    for step in 0..4 {
        let mut bytes = [0; 512];
        let (len, source) = timeout(Duration::from_secs(1), server.recv_from(&mut bytes)).await.unwrap().unwrap();
        assert_eq!(source, bound);
        let Datagram::Stun(id, Message::Request(request)) = be_datagram(bytes::BytesMut::from(&bytes[..len])).unwrap() else {
            panic!("expected binding request");
        };
        assert_eq!(request.change_request().unwrap_or(0), [0, 0, CHANGE_IP | CHANGE_PORT, CHANGE_PORT][step]);
        let reply_source = match step {
            2 => changed,
            3 => SocketAddr::new(node.ip(), changed.port()),
            _ => node,
        };
        // Classification uses its own mapping probe, independently of outer discovery.
        let mapped = if step == 0 { outer } else { bound };
        let response = Response::with(vec![Attr::MappedAddress(mapped), Attr::ChangedAddress(changed), Attr::SourceAddress(reply_source)]);
        dock.topology().stun().on_datagram(&socket, id, Message::Response(response), Link::new(bound, reply_source)).await.unwrap();
        if step == 1 {
            let peer = EndpointAddr::mediate(node, "8.8.8.8:443".parse().unwrap());
            assert!(book.matches(peer).contains(&EndpointAddr::mediate(node, outer)));
            assert!(dock.topology().quic().find_socket(EndpointAddr::direct(outer)).is_none());
            assert_eq!(book.try_get_nat_type(Link::new(bound, outer)), None);
        }
    }
    wait_until(|| book.try_get_nat_type(Link::new(bound, outer)) == Some(NatType::FullCone)).await;
    for endpoint in [EndpointAddr::direct(bound), EndpointAddr::mediate(node, outer)] {
        assert!(Arc::ptr_eq(&dock.topology().quic().find_socket(endpoint).unwrap(), &socket));
    }

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(19)).await;
    let mut bytes = [0; 512];
    assert!(matches!(server.try_recv_from(&mut bytes), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    assert!(matches!(unused.try_recv_from(&mut bytes), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    // Tokio rounds timer deadlines up to its millisecond resolution.
    tokio::time::advance(Duration::from_millis(1001)).await;
    let id = heartbeat_request(&server, bound).await;
    let mut next_heartbeat = tokio::time::Instant::now();
    let changed_outer = SocketAddr::new("198.51.100.2".parse().unwrap(), bound.port());
    let (sent, mut candidates) = tokio::sync::mpsc::unbounded_channel();
    book.attach_puncher(sent);
    while candidates.try_recv().is_ok() {}
    heartbeat_response(&dock, &socket, node, id, changed_outer).await;
    assert_eq!(book.try_get_nat_type(Link::new(bound, outer)), None);
    assert_eq!(book.try_get_nat_type(Link::new(bound, changed_outer)), Some(NatType::FullCone));
    for (mapped, present) in [(outer, false), (changed_outer, true)] {
        let endpoint = EndpointAddr::mediate(node, mapped);
        let peer = EndpointAddr::mediate(node, "8.8.8.8:443".parse().unwrap());
        assert_eq!(dock.topology().quic().find_socket(endpoint).is_some(), present);
        assert_eq!(book.matches(peer).contains(&endpoint), present);
        assert!(dock.topology().quic().find_socket(EndpointAddr::direct(mapped)).is_none());
    }
    let mut changes = Vec::new();
    while let Ok(candidate) = candidates.try_recv() {
        let link = match candidate {
            qprotocol::addr_book::Candidate::New { link, .. } | qprotocol::addr_book::Candidate::Invalid { link } => link,
        };
        if link.src == bound {
            changes.push(candidate);
        }
    }
    assert_eq!(
        changes,
        [
            qprotocol::addr_book::Candidate::Invalid { link: Link::new(bound, outer) },
            qprotocol::addr_book::Candidate::New { link: Link::new(bound, changed_outer), nat: NatType::FullCone },
        ]
    );

    // A successful response resets the consecutive failure counter.
    for (failed, present) in [(true, true), (true, true), (false, true), (true, true), (true, true), (true, false)] {
        tick_heartbeat(&mut next_heartbeat).await;
        let id = heartbeat_request(&server, bound).await;
        if failed {
            tokio::time::advance(Duration::from_millis(3001)).await;
            tokio::task::yield_now().await;
        } else {
            heartbeat_response(&dock, &socket, node, id, changed_outer).await;
        }
        assert!(dock.find_socket(bound).is_some());
        assert!(closures.try_recv().is_err());
        assert_eq!(book.try_get_nat_type(Link::new(bound, changed_outer)), present.then_some(NatType::FullCone));
    }
    assert_eq!(book.try_get_nat_type(Link::new(bound, changed_outer)), None);
    for endpoint in [EndpointAddr::direct(changed_outer), EndpointAddr::mediate(node, changed_outer)] {
        let peer = match endpoint {
            EndpointAddr::Direct { .. } => EndpointAddr::direct("8.8.8.8:443".parse().unwrap()),
            EndpointAddr::Mediate { .. } => EndpointAddr::mediate(node, "8.8.8.8:443".parse().unwrap()),
        };
        assert!(!book.matches(peer).contains(&endpoint));
        assert!(dock.topology().quic().find_socket(endpoint).is_none());
    }
    assert!(dock.topology().quic().find_socket(EndpointAddr::direct(bound)).is_some());
    assert_eq!(book.try_get_nat_type(Link::new(bound, bound)), Some(NatType::FullCone));

    // Heartbeats continue after withdrawal and restore a responding mapping.
    tick_heartbeat(&mut next_heartbeat).await;
    let id = heartbeat_request(&server, bound).await;
    heartbeat_response(&dock, &socket, node, id, changed_outer).await;
    assert_eq!(book.try_get_nat_type(Link::new(bound, changed_outer)), Some(NatType::FullCone));
    assert!(dock.topology().quic().find_socket(EndpointAddr::mediate(node, changed_outer)).is_some());

    // Direct and Mediate remain distinct endpoints even when their addresses are identical.
    tick_heartbeat(&mut next_heartbeat).await;
    let id = heartbeat_request(&server, bound).await;
    heartbeat_response(&dock, &socket, node, id, bound).await;
    assert!(Arc::ptr_eq(&dock.topology().quic().find_socket(EndpointAddr::direct(bound)).unwrap(), &socket));
    assert!(dock.topology().quic().find_socket(EndpointAddr::mediate(node, bound)).is_some());
    for _ in 0..3 {
        tick_heartbeat(&mut next_heartbeat).await;
        heartbeat_request(&server, bound).await;
        tokio::time::advance(Duration::from_millis(3001)).await;
        tokio::task::yield_now().await;
    }
    assert!(dock.topology().quic().find_socket(EndpointAddr::direct(bound)).is_some());
    assert!(dock.topology().quic().find_socket(EndpointAddr::mediate(node, bound)).is_none());
    assert_eq!(book.try_get_nat_type(Link::new(bound, bound)), Some(NatType::FullCone));
    tick_heartbeat(&mut next_heartbeat).await;
    let id = heartbeat_request(&server, bound).await;
    heartbeat_response(&dock, &socket, node, id, changed_outer).await;

    // A reception error cancels an in-flight heartbeat before withdrawing everything.
    tick_heartbeat(&mut next_heartbeat).await;
    let id = heartbeat_request(&server, bound).await;
    fail_reception(&dock, &socket).await;
    wait_until(|| dock.is_empty()).await;
    assert_eq!(closures.try_recv().unwrap(), bound);
    heartbeat_response(&dock, &socket, node, id, changed_outer).await;
    tokio::time::advance(Duration::from_secs(40)).await;
    assert_eq!(book.try_get_nat_type(Link::new(bound, changed_outer)), None);
    assert!(dock.topology().quic().find_socket(EndpointAddr::mediate(node, changed_outer)).is_none());
    assert!(
        !book.matches(EndpointAddr::mediate(node, "8.8.8.8:443".parse().unwrap())).contains(&EndpointAddr::mediate(node, changed_outer))
    );
    assert!(dock.topology().quic().find_socket(EndpointAddr::direct(bound)).is_none());
    assert_eq!(book.try_get_nat_type(Link::new(bound, bound)), None);
    assert!(matches!(server.try_recv_from(&mut bytes), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    assert!(closures.try_recv().is_err());
}

#[tokio::test]
async fn reception_error_cancels_pending_discovery_before_withdrawal() {
    use qbase::datagram::{Datagram, WriteDatagram, be_datagram};
    use qprotocol::protocol::stun::{Attr, Message, Response};

    let dock = isolated_dock();
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let node = server.local_addr().unwrap();
    dock.bootstrap([node]);
    let socket = dock.use_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = socket.local_addr().unwrap();
    let mut bytes = [0; 512];
    let (len, _) = timeout(Duration::from_secs(1), server.recv_from(&mut bytes)).await.unwrap().unwrap();
    let Datagram::Stun(id, _) = be_datagram(bytes::BytesMut::from(&bytes[..len])).unwrap() else {
        panic!("expected STUN");
    };
    fail_reception(&dock, &socket).await;
    wait_until(|| dock.is_empty()).await;
    let outer = SocketAddr::new("198.51.100.2".parse().unwrap(), bound.port());
    let mut reply = bytes::BytesMut::new();
    reply.put_datagram(&Datagram::Stun(id, Message::Response(Response::with(vec![Attr::MappedAddress(outer)])))).unwrap();
    server.send_to(&reply, bound).await.unwrap();
    tokio::task::yield_now().await;
    assert!(dock.topology().quic().find_socket(EndpointAddr::mediate(node, outer)).is_none());
    assert!(
        !qprotocol::ArcAddrBook::global()
            .matches(EndpointAddr::mediate(node, "8.8.8.8:443".parse().unwrap()))
            .contains(&EndpointAddr::mediate(node, outer))
    );
}

#[tokio::test]
async fn temporary_sockets_do_not_start_discovery_or_publish_local_candidates() {
    use qbase::net::route::Link;

    let dock = isolated_dock();
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    dock.bootstrap([server.local_addr().unwrap()]);
    let socket = dock.ephemeral_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = socket.socket().local_addr().unwrap();
    let mut bytes = [0; 512];
    assert!(timeout(Duration::from_millis(20), server.recv_from(&mut bytes)).await.is_err());
    assert_eq!(qprotocol::ArcAddrBook::global().try_get_nat_type(Link::new(bound, bound)), None);
    drop(socket);
    wait_until(|| dock.is_empty()).await;
}

#[tokio::test]
async fn global_returns_the_same_dock_and_topology() {
    assert!(Arc::ptr_eq(Dock::global(), Dock::global()));
    assert!(Arc::ptr_eq(Dock::global().topology(), Dock::global().topology()));
}
