mod common;

use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::{FutureExt, StreamExt, channel::mpsc, stream};
use qbase::net::Family;
use qconnection::{Scope, ServerRegistry};
use qprotocol::{AddressBook, Dock, UdpSocket};
use qresolve::{Record, Resolve, ResolveFuture, Resolver};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

#[derive(Debug)]
struct StreamingResolver {
    hostname: String,
    records: Mutex<Option<mpsc::UnboundedReceiver<Record>>>,
}

impl fmt::Display for StreamingResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("streaming test resolver")
    }
}

impl Resolve for StreamingResolver {
    fn lookup<'l>(
        &'l self,
        hostname: &'l str,
        servname: &'l str,
        _: Option<Family>,
    ) -> ResolveFuture<'l> {
        async move {
            assert_eq!(servname, "");
            if hostname == self.hostname {
                if let Some(records) = self.records.lock().unwrap().take() {
                    return Ok(records.boxed());
                }
            }
            Ok(stream::empty().boxed())
        }
        .boxed()
    }
}

struct Registration(Arc<UdpSocket>);

impl Registration {
    fn new(publish: bool) -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        Dock::global().add(socket.clone()).unwrap();
        if publish {
            AddressBook::global()
                .insert_inner(&socket, socket.local_addr().unwrap().into())
                .unwrap();
        }
        Self(socket)
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        AddressBook::global().remove_bound(self.0.local_addr().unwrap());
        Dock::global().remove(&self.0);
    }
}

// Global listeners and resolver registrations are isolated in this test process.
#[tokio::test]
async fn connect_uses_dns_and_global_addresses_and_closes_its_discovery_stream() {
    let server_socket = Registration::new(false);
    let _client_socket = Registration::new(true);
    let server = common::quic_endpoint();
    let client = common::quic_endpoint();
    let (accepted, mut incoming) = tokio::sync::mpsc::unbounded_channel();
    server
        .listen(Scope::Loopback, move |result| {
            let _ = accepted.send(result);
        })
        .unwrap();

    let server_name = format!("localhost:{}", server_socket.0.local_addr().unwrap().port());
    let (send, records) = mpsc::unbounded();
    Resolver::add(Arc::new(StreamingResolver {
        hostname: server_name.clone(),
        records: Mutex::new(Some(records)),
    }));
    send.unbounded_send((
        qresolve::Source::System,
        server_socket.0.local_addr().unwrap().into(),
    ))
    .unwrap();
    let ((_, _, client_conn), (_, _, server_conn)) = timeout(Duration::from_secs(5), async {
        let connected = client.connect(server_name).await.unwrap();
        let accepted = incoming.recv().await.unwrap().unwrap();
        assert_eq!(connected.1.name(), "localhost");
        assert_eq!(connected.2.alpn(), b"h3");
        assert_eq!(accepted.2.alpn(), b"h3");
        (connected, accepted)
    })
    .await
    .expect("DNS must bootstrap an actual QUIC connection");
    assert!(
        !send.is_closed(),
        "discovery continues after connection delivery"
    );

    timeout(Duration::from_secs(3), async {
        let echo = async {
            let (_, (mut read, mut write)) = server_conn.accept_bi_stream().await.unwrap();
            let mut data = [0; 4];
            read.read_exact(&mut data).await.unwrap();
            write.write_all(&data).await.unwrap();
        };
        let request = async {
            let (_, (mut read, mut write)) = client_conn.open_bi_stream().await.unwrap().unwrap();
            write.write_all(b"ping").await.unwrap();
            let mut data = [0; 4];
            read.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"ping");
        };
        tokio::join!(echo, request);
    })
    .await
    .expect("connection supports stream traffic");

    client_conn.close(0u32.into(), "test complete");
    timeout(Duration::from_secs(1), async {
        while !send.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("connection close cancels DNS discovery");
    server_conn.close(0u32.into(), "test complete");
    ServerRegistry::global().remove("localhost");
}
