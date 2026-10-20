use qbase::datagram::{
    be_datagram,
    stun::{AttributeType, CHANGE_IP, CHANGE_PORT},
};

use super::*;

async fn send(socket: &UdpSocket, id: TransactionId, message: Message, link: Link) {
    let mut bytes = BytesMut::new();
    bytes.put_datagram(&Datagram::Stun(id, message)).unwrap();
    assert_eq!(
        socket
            .send(
                &[IoSlice::new(&bytes)],
                Line::new(link, Line::DEFAULT_TTL, None, bytes.len() as u16)
            )
            .await
            .unwrap(),
        1
    );
}

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

fn change_request(flags: u8) -> Request {
    let encoded = [u8::from(AttributeType::ChangeRequest(flags))];
    let (_, Message::Request(request)) = be_stun_message(Type::BindingRequest, &encoded).unwrap()
    else {
        panic!("expected binding request");
    };
    request
}

async fn receive(socket: &UdpSocket) -> (TransactionId, Message, Link) {
    let mut buffers = [BytesMut::zeroed(512)];
    let mut lines = [Line::default()];
    assert_eq!(
        timeout(
            Duration::from_secs(1),
            socket.receive(&mut buffers, &mut lines)
        )
        .await
        .unwrap()
        .unwrap(),
        1,
    );
    let packet = buffers[0].split_to(lines[0].seg_size as usize);
    let Datagram::Stun(id, message) = be_datagram(packet).unwrap() else {
        panic!("expected STUN datagram");
    };
    (id, message, lines[0].link)
}

async fn no_response(socket: &UdpSocket) {
    let mut buffers = [BytesMut::zeroed(512)];
    let mut lines = [Line::default()];
    assert!(
        timeout(
            Duration::from_millis(20),
            socket.receive(&mut buffers, &mut lines)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn service_is_enabled_by_default_and_replies_without_configuration() {
    let protocol = StunProtocol::new();
    let server = socket();
    let client = socket();
    let link = Link::new(server.local_addr().unwrap(), client.local_addr().unwrap());
    for request in [Request::default(), change_request(0)] {
        let id = TransactionId::random();
        protocol
            .on_datagram(&server, id, Message::Request(request), link)
            .await
            .unwrap();
        let (received_id, Message::Response(response), received_link) = receive(&client).await
        else {
            panic!("expected binding response");
        };
        assert_eq!(received_id, id);
        assert_eq!(received_link, link);
        assert_eq!(response.map_addr().unwrap(), link.dst);
        assert_eq!(response.source_addr().unwrap(), link.src);
        assert!(response.changed_addr().is_err());
    }
}

#[tokio::test]
async fn disabled_server_and_unconfigured_change_requests_are_silent() {
    let protocol = StunProtocol::new();
    protocol.disable_service();
    let server = socket();
    let client = socket();
    let link = Link::new(server.local_addr().unwrap(), client.local_addr().unwrap());
    protocol
        .on_datagram(
            &server,
            TransactionId::random(),
            Message::Request(Request::default()),
            link,
        )
        .await
        .unwrap();
    no_response(&client).await;

    protocol.enable_service();
    for flags in [CHANGE_PORT, CHANGE_IP, CHANGE_IP | CHANGE_PORT] {
        protocol
            .on_datagram(
                &server,
                TransactionId::random(),
                Message::Request(change_request(flags)),
                link,
            )
            .await
            .unwrap();
        no_response(&client).await;
    }
}

#[tokio::test]
async fn response_address_uses_the_original_client_and_receiving_socket_configuration() {
    let protocol = Arc::new(StunProtocol::new());
    let dock = isolated_dock(&protocol);
    let intermediary = socket();
    let client = socket();
    protocol.enable_service();

    for _ in 0..2 {
        let server = socket();
        let bound = server.local_addr().unwrap();
        let config = config(bound);
        // Register through Dock, then read forwarded packets explicitly below.
        dock.add(server.clone()).unwrap().unwrap().abort();
        protocol.set_change_server(bound, config).unwrap();
        let id = TransactionId::random();
        protocol
            .on_datagram(
                &server,
                id,
                Message::Request(Request::with_response_addr(client.local_addr().unwrap())),
                Link::new(bound, intermediary.local_addr().unwrap()),
            )
            .await
            .unwrap();
        let (received_id, Message::Response(response), link) = receive(&client).await else {
            panic!("expected binding response");
        };
        assert_eq!(received_id, id);
        assert_eq!(link.src, bound);
        assert_eq!(response.map_addr().unwrap(), client.local_addr().unwrap());
        assert_eq!(response.source_addr().unwrap(), config.outer_address);
        assert_eq!(response.changed_addr().unwrap(), config.change_address);
    }
    no_response(&intermediary).await;
}

#[tokio::test]
async fn change_requests_forward_only_response_address_with_the_original_id() {
    let protocol = Arc::new(StunProtocol::new());
    let dock = isolated_dock(&protocol);
    let server = socket();
    let alternate = socket();
    let client = socket();
    let bound = server.local_addr().unwrap();
    // Simulate a public mapping while keeping all actual traffic on loopback.
    let config = ChangeServer {
        change_port: alternate.local_addr().unwrap().port(),
        change_address: alternate.local_addr().unwrap(),
        ..config(bound)
    };
    // Register through Dock, then read forwarded packets explicitly below.
    dock.add(server.clone()).unwrap().unwrap().abort();
    protocol.set_change_server(bound, config).unwrap();
    protocol.enable_service();

    for flags in [CHANGE_PORT, CHANGE_IP, CHANGE_IP | CHANGE_PORT] {
        let mut request = change_request(flags);
        request.add_response_address("203.0.113.1:45000".parse().unwrap());
        let id = TransactionId::random();
        protocol
            .on_datagram(
                &server,
                id,
                Message::Request(request),
                Link::new(bound, client.local_addr().unwrap()),
            )
            .await
            .unwrap();
        let target = if flags == CHANGE_IP {
            &server
        } else {
            &alternate
        };
        let (received_id, Message::Request(request), link) = receive(target).await else {
            panic!("expected forwarded binding request");
        };
        assert_eq!(received_id, id);
        assert_eq!(link, Link::new(bound, target.local_addr().unwrap()));
        assert_eq!(
            request,
            Request::with_response_addr(client.local_addr().unwrap())
        );
    }
    no_response(&client).await;
}

#[tokio::test]
async fn change_port_replies_from_the_alternate_socket_through_dock() {
    let protocol = Arc::new(StunProtocol::new());
    let topology = Arc::new(Topology::new(
        protocol.clone(),
        Arc::new(ForwardProtocol::new()),
        Arc::new(QuicProtocol::new()),
    ));
    let dock = Dock::new(topology);
    let server = socket();
    let alternate = socket();
    let client = socket();
    for socket in [&server, &alternate, &client] {
        dock.add(socket.clone()).unwrap();
    }
    for (socket, other) in [(&server, &alternate), (&alternate, &server)] {
        let bound = socket.local_addr().unwrap();
        protocol
            .set_change_server(
                bound,
                ChangeServer {
                    change_port: other.local_addr().unwrap().port(),
                    outer_address: bound,
                    ..config(bound)
                },
            )
            .unwrap();
    }
    protocol.enable_service();
    let mut transaction = protocol.new_transaction();
    let (link, response) = timeout(
        Duration::from_secs(1),
        transaction.request(
            Link::new(client.local_addr().unwrap(), server.local_addr().unwrap()),
            Request::change_port(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(link.dst, alternate.local_addr().unwrap());
    assert_eq!(response.map_addr().unwrap(), client.local_addr().unwrap());
    assert_eq!(
        response.source_addr().unwrap(),
        alternate.local_addr().unwrap()
    );
    assert_eq!(
        response.changed_addr().unwrap(),
        config(alternate.local_addr().unwrap()).change_address
    );
    drop(transaction);
    assert!(dock.remove(&alternate));
    dock.add(alternate.clone()).unwrap();
    let mut transaction = protocol.new_transaction();
    let (_, response) = timeout(
        Duration::from_secs(1),
        transaction.request(
            Link::new(
                client.local_addr().unwrap(),
                alternate.local_addr().unwrap(),
            ),
            Request::default(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        response.source_addr().unwrap(),
        alternate.local_addr().unwrap()
    );
    assert!(response.changed_addr().is_err());
}

#[tokio::test]
async fn send_error_does_not_stop_the_dock_receive_loop() {
    let protocol = Arc::new(StunProtocol::new());
    let topology = Arc::new(Topology::new(
        protocol.clone(),
        Arc::new(ForwardProtocol::new()),
        Arc::new(QuicProtocol::new()),
    ));
    let dock = Dock::new(topology);
    let server = socket();
    let client = socket();
    dock.add(server.clone()).unwrap();
    protocol.enable_service();
    let request = Request::with_response_addr("[::1]:10000".parse().unwrap());
    let link = Link::new(client.local_addr().unwrap(), server.local_addr().unwrap());
    send(
        &client,
        TransactionId::random(),
        Message::Request(request),
        link,
    )
    .await;
    let id = TransactionId::random();
    send(&client, id, Message::Request(Request::default()), link).await;
    let (received_id, message, _) = receive(&client).await;
    assert_eq!(received_id, id);
    assert!(matches!(message, Message::Response(_)));
}

#[tokio::test]
async fn configuration_rejects_invalid_addresses_and_requires_registration() {
    let protocol = Arc::new(StunProtocol::new());
    let dock = isolated_dock(&protocol);
    let server = socket();
    let bound = server.local_addr().unwrap();
    let valid = config(bound);
    assert_eq!(
        protocol.set_change_server(bound, valid).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    dock.add(server.clone()).unwrap();
    protocol.set_change_server(bound, valid).unwrap();
    for config in [
        ChangeServer {
            change_port: 0,
            ..valid
        },
        ChangeServer {
            change_port: bound.port(),
            ..valid
        },
        ChangeServer {
            outer_address: SocketAddr::new(valid.outer_address.ip(), bound.port() ^ 1),
            ..valid
        },
        ChangeServer {
            outer_address: "0.0.0.0:20002".parse().unwrap(),
            ..valid
        },
        ChangeServer {
            change_address: "[::1]:20003".parse().unwrap(),
            ..valid
        },
        ChangeServer {
            change_address: SocketAddr::new(valid.outer_address.ip(), valid.change_port),
            ..valid
        },
        ChangeServer {
            change_address: SocketAddr::new(valid.change_address.ip(), bound.port()),
            ..valid
        },
        ChangeServer {
            change_address: SocketAddr::new(valid.change_address.ip(), 0),
            ..valid
        },
    ] {
        assert_eq!(
            protocol
                .set_change_server(bound, config)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    let client = socket();
    protocol
        .on_datagram(
            &server,
            TransactionId::random(),
            Message::Request(Request::default()),
            Link::new(bound, client.local_addr().unwrap()),
        )
        .await
        .unwrap();
    let (_, Message::Response(response), _) = receive(&client).await else {
        panic!("expected binding response");
    };
    assert_eq!(response.changed_addr().unwrap(), valid.change_address);
    assert!(dock.remove(&server));
    assert_eq!(
        protocol.set_change_server(bound, valid).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}
