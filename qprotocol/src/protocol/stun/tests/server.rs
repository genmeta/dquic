use super::*;

fn socket() -> Arc<UdpSocket> {
    Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap())
}

fn config(bound: SocketAddr) -> ChangeServer {
    ChangeServer {
        change_port: bound.port() ^ 1,
        change_address: SocketAddr::from(([198, 51, 100, 2], bound.port() ^ 1)),
        outer_address: SocketAddr::from(([198, 51, 100, 1], bound.port())),
    }
}

#[tokio::test]
async fn configuration_follows_registration_even_after_the_socket_expires() {
    let protocol = StunProtocol::new();
    let server = socket();
    let bound = server.local_addr().unwrap();
    let valid = config(bound);
    protocol.register_socket(bound, &server);
    protocol.set_change_server(bound, valid).unwrap();
    let registered = Arc::downgrade(&server);
    drop(server);
    assert!(registered.upgrade().is_none());
    // Configuration depends on registration, not on the weak socket's liveness.
    protocol.set_change_server(bound, valid).unwrap();
    protocol.unregister_socket(bound, &registered);
    assert!(!protocol.change_servers.contains_key(&bound));
    assert_eq!(
        protocol.set_change_server(bound, valid).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[tokio::test]
async fn configurations_follow_registration_identity() {
    let protocol = StunProtocol::new();
    let original = socket();
    let replacement = socket();
    let bound = original.local_addr().unwrap();
    protocol.register_socket(bound, &original);
    protocol.set_change_server(bound, config(bound)).unwrap();
    protocol.register_socket(bound, &original);
    assert!(protocol.change_servers.contains_key(&bound));
    protocol.unregister_socket(bound, &Arc::downgrade(&replacement));
    assert!(protocol.change_servers.contains_key(&bound));
    // Simulate a replacement under the same registry key without an OS rebind.
    protocol.register_socket(bound, &replacement);
    assert!(!protocol.change_servers.contains_key(&bound));
    protocol.set_change_server(bound, config(bound)).unwrap();
    protocol.unregister_socket(bound, &Arc::downgrade(&original));
    assert!(protocol.change_servers.contains_key(&bound));
    protocol.unregister_socket(bound, &Arc::downgrade(&replacement));
    assert!(!protocol.change_servers.contains_key(&bound));
}
