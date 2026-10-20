mod client;
mod server;

use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    datagram::{Datagram, WriteDatagram},
    net::{
        NatType,
        route::{Line, Link},
    },
};
use qprotocol::{
    Dock, ForwardProtocol, QuicProtocol, UdpSocket, protocol::stun::*, topology::Topology,
};
use tokio::time::timeout;

fn isolated_dock(protocol: &Arc<StunProtocol>) -> Arc<Dock> {
    Dock::new(Arc::new(Topology::new(
        protocol.clone(),
        Arc::new(ForwardProtocol::new()),
        Arc::new(QuicProtocol::new()),
    )))
}

#[test]
fn binding_request_encodes() {
    let txid = TransactionId::random();
    let message = Message::Request(Request::default());
    let mut bytes = BytesMut::new();
    bytes.put_datagram(&Datagram::Stun(txid, message)).unwrap();
    assert!(!bytes.is_empty());
}

#[tokio::test]
async fn new_transactions_do_not_overwrite_each_other() {
    let protocol = Arc::new(StunProtocol::new());
    let dock = isolated_dock(&protocol);
    let client = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let server = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    dock.add(client.clone()).unwrap();
    let link = Link::new(client.local_addr().unwrap(), server.local_addr().unwrap());
    let mut first = protocol.new_transaction();
    let mut second = protocol.new_transaction();
    assert_ne!(first.id(), second.id());

    let first_mapping = "203.0.113.1:40000".parse().unwrap();
    let second_mapping = "203.0.113.1:40001".parse().unwrap();
    for (id, mapped) in [(second.id(), second_mapping), (first.id(), first_mapping)] {
        protocol
            .on_datagram(
                &client,
                id,
                Message::Response(Response::with(vec![Attr::MappedAddress(mapped)])),
                link,
            )
            .await
            .unwrap();
    }
    for (transaction, mapped) in [(&mut first, first_mapping), (&mut second, second_mapping)] {
        let (received_link, response) = timeout(
            Duration::from_secs(1),
            transaction.request(link, Request::default()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received_link, link);
        assert_eq!(response.map_addr().unwrap(), mapped);
    }
}

#[tokio::test]
async fn transaction_retries_with_the_same_id_after_timeout() {
    let protocol = Arc::new(StunProtocol::new());
    protocol.disable_service();
    let topology = Arc::new(Topology::new(
        protocol.clone(),
        Arc::new(ForwardProtocol::new()),
        Arc::new(QuicProtocol::new()),
    ));
    let dock = Dock::new(topology);
    let client = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let agent = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let client_addr = client.local_addr().unwrap();
    let link = Link::new(client_addr, agent.local_addr().unwrap());
    dock.add(client).unwrap();
    dock.add(agent).unwrap();

    let mut transaction = protocol.new_transaction();
    let transaction_id = transaction.id();
    assert!(
        timeout(
            Duration::from_millis(20),
            transaction.request(link, Request::default()),
        )
        .await
        .is_err()
    );
    assert_eq!(transaction.id(), transaction_id);

    protocol.enable_service();
    let (response_link, response) = timeout(
        Duration::from_secs(1),
        transaction.request(link, Request::default()),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response_link, link);
    assert_eq!(response.map_addr().unwrap(), client_addr);

    drop(transaction);
}
