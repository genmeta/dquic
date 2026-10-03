mod common;

use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use futures::{FutureExt, StreamExt, channel::mpsc, stream};
use qbase::{cid::ConnectionId, net::Family};
use qconnection::{QuicEndpoint, Scope, ServerRegistry};
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
    connect_case(false, b"h3").await;
    connect_case(true, b"test-quic").await;
    reject_wrong_server_identity().await;
    reject_invalid_client_certificate().await;
    cancel_queued_connection().await;
    for anonymous in [false, true] {
        cancel_lookup(anonymous).await;
        cancel_handshake(anonymous).await;
    }
}

async fn connect_case(anonymous: bool, alpn: &[u8]) {
    let server_socket = Registration::new(false);
    let _client_socket = Registration::new(true);
    let mut server = common::quic_endpoint();
    server.alpn = vec![alpn.to_vec()];
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
        let connected = connect(anonymous, server_name, alpn).await.unwrap();
        let accepted = incoming.recv().await.unwrap().unwrap();
        assert_eq!(connected.0.is_none(), anonymous);
        assert_eq!(accepted.0.is_none(), anonymous);
        assert_eq!(accepted.1.name(), "localhost");
        assert_eq!(connected.1.name(), "localhost");
        assert_eq!(connected.2.alpn(), alpn);
        assert_eq!(accepted.2.alpn(), alpn);
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

async fn wait_until(mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("connection resources must be released");
}

async fn connect(
    anonymous: bool,
    server_name: String,
    alpn: &[u8],
) -> Result<qconnection::Connected, qconnection::Error> {
    let parameters = qbase::param::handy::client_parameters();
    if anonymous {
        qconnection::connect_anonymously(server_name, parameters, vec![alpn.to_vec()]).await
    } else {
        let mut endpoint = common::quic_endpoint();
        endpoint.client_parameters = parameters;
        endpoint.alpn = vec![alpn.to_vec()];
        endpoint.connect(server_name).await
    }
}

struct DropProbe(Arc<AtomicBool>);

impl Drop for DropProbe {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct PendingResolver {
    hostname: String,
    started: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

impl fmt::Display for PendingResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("pending test lookup")
    }
}

impl Resolve for PendingResolver {
    fn lookup<'l>(&'l self, hostname: &'l str, _: &'l str, _: Option<Family>) -> ResolveFuture<'l> {
        async move {
            if hostname != self.hostname {
                return Ok(stream::empty().boxed());
            }
            let _probe = DropProbe(self.dropped.clone());
            self.started.store(true, Ordering::SeqCst);
            futures::future::pending().await
        }
        .boxed()
    }
}

async fn cancel_lookup(anonymous: bool) {
    let hostname = format!("pending-{anonymous}.test");
    let started = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    Resolver::add(Arc::new(PendingResolver {
        hostname: hostname.clone(),
        started: started.clone(),
        dropped: dropped.clone(),
    }));
    let connecting = tokio::spawn(async move { connect(anonymous, hostname, b"h3").await });
    wait_until(|| started.load(Ordering::SeqCst)).await;
    connecting.abort();
    assert!(matches!(connecting.await, Err(error) if error.is_cancelled()));
    wait_until(|| dropped.load(Ordering::SeqCst)).await;
}

// Inspect the actual client SCID route without exposing the router's private table.
fn route_exists(cid: ConnectionId) -> bool {
    use bytes::BytesMut;
    use qbase::{
        net::route::Link,
        packet::{DataHeader, DataPacket, LongHeaderBuilder, Packet, long},
    };
    let router = qtransport::router::QuicRouter::global();
    let incoming = Arc::new(AtomicBool::new(false));
    let observed = incoming.clone();
    router.on_incoming(move |_, _, _| {
        observed.store(true, Ordering::SeqCst);
    });
    let link = Link::new(
        "127.0.0.1:30001".parse().unwrap(),
        "127.0.0.1:30002".parse().unwrap(),
    );
    router.deliver(
        Packet::Data(DataPacket {
            header: DataHeader::Long(long::DataHeader::Initial(
                LongHeaderBuilder::with_cid(cid, cid).initial(vec![]),
            )),
            bytes: BytesMut::new(),
            offset: 0,
        }),
        link.into(),
        link,
    );
    !incoming.load(Ordering::SeqCst)
}

async fn cancel_handshake(anonymous: bool) {
    use bytes::BytesMut;
    use qbase::packet::{GetScid, Packet, PacketReader};
    let _local = Registration::new(true);
    // A silent peer lets the client emit Initial packets but never completes TLS.
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_nonblocking(true).unwrap();
    let hostname = format!("silent-{anonymous}.test");
    let (send, records) = mpsc::unbounded();
    Resolver::add(Arc::new(StreamingResolver {
        hostname: hostname.clone(),
        records: Mutex::new(Some(records)),
    }));
    send.unbounded_send((qresolve::Source::System, peer.local_addr().unwrap().into()))
        .unwrap();
    let connecting = tokio::spawn(async move { connect(anonymous, hostname, b"h3").await });
    let mut datagram = vec![0; 65536];
    let size = timeout(Duration::from_secs(5), async {
        loop {
            match peer.recv_from(&mut datagram) {
                Ok((size, _)) => break size,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await
                }
                Err(error) => panic!("receive Initial: {error}"),
            }
        }
    })
    .await
    .expect("client must start TLS on the discovered path");
    let packet = PacketReader::new(BytesMut::from(&datagram[..size]), 8)
        .next()
        .unwrap()
        .unwrap();
    let Packet::Data(packet) = packet else {
        panic!("expected Initial packet");
    };
    let qbase::packet::DataHeader::Long(qbase::packet::long::DataHeader::Initial(header)) =
        packet.header
    else {
        panic!("expected Initial header");
    };
    let cid = *header.scid();
    assert!(route_exists(cid));
    connecting.abort();
    assert!(matches!(connecting.await, Err(error) if error.is_cancelled()));
    wait_until(|| send.is_closed()).await;
    wait_until(|| !route_exists(cid)).await;
}

async fn cancel_queued_connection() {
    use std::{future::Future, task::Context};
    struct WakeFlag(AtomicBool);
    impl futures::task::ArcWake for WakeFlag {
        fn wake_by_ref(flag: &Arc<Self>) {
            flag.0.store(true, Ordering::SeqCst);
        }
    }
    let server_socket = Registration::new(false);
    let _local = Registration::new(true);
    let server = common::quic_endpoint();
    let (send_accepted, mut accepted) = tokio::sync::mpsc::unbounded_channel();
    server
        .listen(Scope::Loopback, move |result| {
            let _ = send_accepted.send(result);
        })
        .unwrap();
    let hostname = format!("localhost:{}", server_socket.0.local_addr().unwrap().port());
    let (send, records) = mpsc::unbounded();
    Resolver::add(Arc::new(StreamingResolver {
        hostname: hostname.clone(),
        records: Mutex::new(Some(records)),
    }));
    send.unbounded_send((
        qresolve::Source::System,
        server_socket.0.local_addr().unwrap().into(),
    ))
    .unwrap();
    let mut connecting = Box::pin(qconnection::connect_anonymously(
        hostname,
        qbase::param::handy::client_parameters(),
        vec![b"h3".to_vec()],
    ));
    // Poll once to start the lifecycle, then leave the delivery receiver unpolled.
    let ready = Arc::new(WakeFlag(AtomicBool::new(false)));
    let waker = futures::task::waker(ready.clone());
    assert!(
        connecting
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    let (_, _, connection) = timeout(Duration::from_secs(5), accepted.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // The delivery slot is ready, but its connection has not reached the caller.
    wait_until(|| ready.0.load(Ordering::SeqCst)).await;
    drop(connecting);
    wait_until(|| send.is_closed()).await;
    assert!(
        timeout(Duration::from_secs(5), connection.accept_uni_stream())
            .await
            .unwrap()
            .is_err()
    );
    ServerRegistry::global().remove("localhost");
}

async fn reject_wrong_server_identity() {
    let server_socket = Registration::new(false);
    let _local = Registration::new(true);
    let good = common::quic_endpoint();
    let identity = &good.identity;
    use tls_backend::pki_types::pem::PemObject;
    let wrong = qbase::endpoint::Endpoint::new(
        &qtls::default_provider(),
        "wrong.test",
        identity.cert_chain().to_vec(),
        qtls::PrivateKeyDer::from_pem_slice(include_bytes!(
            "../../tests/keychain/localhost/server.key"
        ))
        .unwrap(),
        identity.ocsp().to_vec(),
    )
    .unwrap();
    let mut server = QuicEndpoint::new(wrong);
    server.server_parameters = qbase::param::handy::server_parameters();
    server
        .listen(Scope::Loopback, |result| {
            assert!(result.is_err(), "wrong-name handshake must not be accepted")
        })
        .unwrap();
    let (send, records) = mpsc::unbounded();
    Resolver::add(Arc::new(StreamingResolver {
        hostname: "wrong.test".into(),
        records: Mutex::new(Some(records)),
    }));
    send.unbounded_send((
        qresolve::Source::System,
        server_socket.0.local_addr().unwrap().into(),
    ))
    .unwrap();
    assert!(
        timeout(
            Duration::from_secs(5),
            connect(true, "wrong.test".into(), b"h3")
        )
        .await
        .unwrap()
        .is_err()
    );
    wait_until(|| send.is_closed()).await;
    ServerRegistry::global().remove("wrong.test");
}

async fn reject_invalid_client_certificate() {
    use tls_backend::pki_types::pem::PemObject;
    let server_socket = Registration::new(false);
    let _local = Registration::new(true);
    let server = common::quic_endpoint();
    let (send_accepted, mut accepted) = tokio::sync::mpsc::unbounded_channel();
    server
        .listen(Scope::Loopback, move |result| {
            let _ = send_accepted.send(result);
        })
        .unwrap();
    let good = common::quic_endpoint();
    let identity = &good.identity;
    let invalid = qbase::endpoint::Endpoint::new(
        &qtls::default_provider(),
        "localhost",
        identity.cert_chain().to_vec(),
        qtls::PrivateKeyDer::from_pem_slice(include_bytes!(
            "../../tests/keychain/localhost/server.key"
        ))
        .unwrap(),
        b"invalid OCSP".to_vec(),
    )
    .unwrap();
    let mut client = QuicEndpoint::new(invalid);
    client.client_parameters = qbase::param::handy::client_parameters();
    let hostname = format!("localhost:{}", server_socket.0.local_addr().unwrap().port());
    let (send, records) = mpsc::unbounded();
    Resolver::add(Arc::new(StreamingResolver {
        hostname: hostname.clone(),
        records: Mutex::new(Some(records)),
    }));
    send.unbounded_send((
        qresolve::Source::System,
        server_socket.0.local_addr().unwrap().into(),
    ))
    .unwrap();
    timeout(Duration::from_secs(5), async {
        let (connected, rejected) = tokio::join!(client.connect(hostname), accepted.recv());
        assert!(
            rejected.unwrap().is_err(),
            "invalid credentials must not become an anonymous peer"
        );
        if let Ok((_, _, connection)) = connected {
            connection.close(0u32.into(), "rejected client");
        }
    })
    .await
    .unwrap();
    wait_until(|| send.is_closed()).await;
    ServerRegistry::global().remove("localhost");
}
