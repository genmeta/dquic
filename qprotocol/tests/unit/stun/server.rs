use super::*;

fn socket() -> Arc<UdpSocket> {
    Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap(), crate::common::loopback_ifindex()).unwrap())
}

fn config(bound: SocketAddr) -> ChangeServer {
    ChangeServer {
        change_port: bound.port() ^ 1,
        change_address: SocketAddr::from(([198, 51, 100, 2], bound.port() ^ 1)),
        outer_address: SocketAddr::from(([198, 51, 100, 1], bound.port())),
    }
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

use qbase::datagram::{
    be_datagram,
    stun::{AttributeType, CHANGE_IP, CHANGE_PORT},
};
fn change_request(flags: u8) -> Request {
    let encoded = [u8::from(AttributeType::ChangeRequest(flags))];
    let (_, Message::Request(request)) = be_stun_message(Type::BindingRequest, &encoded).unwrap() else {
        panic!("expected binding request");
    };
    request
}

async fn receive(socket: &UdpSocket) -> (TransactionId, Message, Link) {
    let mut buffers = [BytesMut::zeroed(512)];
    let mut lines = [Line::default()];
    assert_eq!(timeout(Duration::from_secs(1), socket.receive(&mut buffers, &mut lines)).await.unwrap().unwrap(), 1,);
    let packet = buffers[0].split_to(lines[0].seg_size as usize);
    let Datagram::Stun(id, message) = be_datagram(packet).unwrap() else {
        panic!("expected STUN datagram");
    };
    (id, message, lines[0].link)
}

async fn no_response(socket: &UdpSocket) {
    let mut buffers = [BytesMut::zeroed(512)];
    let mut lines = [Line::default()];
    assert!(timeout(Duration::from_millis(20), socket.receive(&mut buffers, &mut lines)).await.is_err());
}

#[tokio::test]
async fn response_address_uses_the_original_client_and_receiving_socket_configuration() {
    let protocol = Arc::new(StunProtocol::new());
    let intermediary = socket();
    let client = socket();
    protocol.enable_service();

    for _ in 0..2 {
        let server = socket();
        let bound = server.local_addr().unwrap();
        let config = config(bound);
        // Register directly because this protocol test reads forwarded packets itself.
        protocol.register_socket(bound, &server);
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
    // Register directly because this protocol test reads forwarded packets itself.
    protocol.register_socket(bound, &server);
    protocol.set_change_server(bound, config).unwrap();
    protocol.enable_service();

    for flags in [CHANGE_PORT, CHANGE_IP, CHANGE_IP | CHANGE_PORT] {
        let mut request = change_request(flags);
        request.add_response_address("203.0.113.1:45000".parse().unwrap());
        let id = TransactionId::random();
        protocol.on_datagram(&server, id, Message::Request(request), Link::new(bound, client.local_addr().unwrap())).await.unwrap();
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
        assert_eq!(request, Request::with_response_addr(client.local_addr().unwrap()));
    }
    no_response(&client).await;
}
