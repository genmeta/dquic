use std::{fmt, io, sync::Mutex, time::Duration};

use futures::{FutureExt, channel::mpsc, stream};
use qbase::{
    cid::ConnectionId,
    net::{Family, addr::EndpointAddr, route::Pathway},
    time::ArcConnIdle,
};
use qprotocol::UdpSocket;
use qresolve::{Resolve, ResolveFuture, ResolveResult, Source};

use super::*;
use crate::ArcConnPhase;

struct ScriptedResolver(Mutex<Option<ResolveResult>>);

impl fmt::Debug for ScriptedResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScriptedResolver")
    }
}

impl fmt::Display for ScriptedResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl Resolve for ScriptedResolver {
    fn lookup<'l>(
        &'l self,
        hostname: &'l str,
        servname: &'l str,
        family: Option<Family>,
    ) -> ResolveFuture<'l> {
        assert_eq!(hostname, "example.test:8443");
        assert_eq!(servname, "");
        assert_eq!(family, None);
        futures::future::ready(self.0.lock().unwrap().take().unwrap()).boxed()
    }
}

fn resolver(result: ResolveResult) -> Arc<dyn Resolve> {
    Arc::new(ScriptedResolver(Mutex::new(Some(result))))
}

fn paths() -> Arc<Paths> {
    let keys = qtls::default_provider()
        .cipher_suites
        .iter()
        .find_map(|suite| suite.tls13().and_then(|suite| suite.quic_suite()))
        .unwrap()
        .keys(
            b"original",
            tls_backend::Side::Client,
            tls_backend::quic::Version::V1,
        )
        .into();
    Paths::new(
        Role::Client,
        ArcConnPhase::initial(crate::tests::initial_phase(
            Role::Client,
            ConnectionId::from_slice(b"clientid"),
            ConnectionId::from_slice(b"original"),
            keys,
        )),
        ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO),
    )
}

struct LocalSocket(Arc<UdpSocket>);

impl LocalSocket {
    fn new(book: &AddressBook) -> Self {
        let interface = netdev::get_interfaces()
            .into_iter()
            .find(|interface| {
                interface
                    .ipv4
                    .iter()
                    .any(|ip| ip.addr() == std::net::Ipv4Addr::LOCALHOST)
            })
            .expect("loopback interface");
        let device = qudp::BoundDevice::new(interface.name, interface.index).unwrap();
        let socket = Arc::new(
            UdpSocket::bind_to_device("127.0.0.1:0".parse().unwrap(), device.clone()).unwrap(),
        );
        Dock::global().add(socket.clone()).unwrap();
        let bound = socket.local_addr().unwrap();
        let endpoint = EndpointAddr::direct(bound);
        QuicProtocol::global().register(endpoint, &socket).unwrap();
        book.insert_inner(&socket, endpoint).unwrap();
        Self(socket)
    }

    fn endpoint(&self) -> EndpointAddr {
        EndpointAddr::direct(self.0.local_addr().unwrap())
    }
}

impl Drop for LocalSocket {
    fn drop(&mut self) {
        QuicProtocol::global().unregister(self.endpoint(), &self.0);
        Dock::global().remove(&self.0);
    }
}

#[tokio::test]
async fn streaming_dns_pairs_each_record_with_the_current_book_and_deduplicates_paths() {
    let book = AddressBook::new();
    let first = LocalSocket::new(&book);
    let paths = paths();
    let (send, records) = mpsc::unbounded();
    let mut discovery = Box::pin(resolve_paths(
        &paths,
        &book,
        resolver(Ok(records.boxed())),
        "example.test:8443",
    ));
    send.unbounded_send((
        Source::System,
        EndpointAddr::direct("[::1]:8443".parse().unwrap()),
    ))
    .unwrap();
    assert!(futures::poll!(&mut discovery).is_pending());
    assert!(paths.snapshot().is_empty());

    let peer = EndpointAddr::direct("127.0.0.1:8443".parse().unwrap());
    send.unbounded_send((Source::System, peer)).unwrap();
    assert!(futures::poll!(&mut discovery).is_pending());
    let original = paths.get(&Pathway::new(first.endpoint(), peer)).unwrap();

    let second = LocalSocket::new(&book);
    send.unbounded_send((Source::Dht, peer)).unwrap();
    assert!(futures::poll!(&mut discovery).is_pending());
    assert_eq!(paths.snapshot().len(), 2);
    assert!(Arc::ptr_eq(
        &paths.get(&original.pathway).unwrap(),
        &original
    ));
    assert!(paths.get(&Pathway::new(second.endpoint(), peer)).is_some());
    drop(send);
    discovery.await.unwrap();
    paths.retire_all();
}

#[tokio::test]
async fn empty_failed_and_unregistered_results_report_no_viable_path() {
    let book = AddressBook::new();
    let socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = socket.local_addr().unwrap();
    book.insert_inner(&socket, EndpointAddr::direct(bound))
        .unwrap();
    let peer = EndpointAddr::direct("127.0.0.1:8443".parse().unwrap());
    let inputs: [ResolveResult; 3] = [
        Err(io::Error::new(io::ErrorKind::NotFound, "resolver failed")),
        Ok(stream::empty().boxed()),
        Ok(stream::iter([(Source::Dht, peer)]).boxed()),
    ];
    for input in inputs {
        let paths = paths();
        let error = resolve_paths(&paths, &book, resolver(input), "example.test:8443")
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Quic(error) if error.kind() == ErrorKind::NoViablePath));
        assert!(paths.snapshot().is_empty());
    }
}

#[tokio::test]
async fn dns_discovery_preserves_mdns_source_when_adding_paths() {
    let book = AddressBook::new();
    let local = LocalSocket::new(&book);
    let nic = local.0.bound_device().unwrap().name().to_owned();
    let paths = paths();
    let (send, records) = mpsc::unbounded();
    let mut discovery = Box::pin(resolve_paths(
        &paths,
        &book,
        resolver(Ok(records.boxed())),
        "example.test:8443",
    ));
    let peer = EndpointAddr::direct("127.0.0.1:8443".parse().unwrap());
    for source in [
        Source::Mdns {
            nic: "missing-interface".into(),
            family: Family::V4,
        },
        Source::Mdns {
            nic: nic.clone().into(),
            family: Family::V6,
        },
    ] {
        send.unbounded_send((source, peer)).unwrap();
        assert!(futures::poll!(&mut discovery).is_pending());
        assert!(paths.snapshot().is_empty());
    }
    send.unbounded_send((
        Source::Mdns {
            nic: nic.into(),
            family: Family::V4,
        },
        peer,
    ))
    .unwrap();
    assert!(futures::poll!(&mut discovery).is_pending());
    assert!(paths.get(&Pathway::new(local.endpoint(), peer)).is_some());
    assert_eq!(paths.snapshot().len(), 1);
    drop(send);
    discovery.await.unwrap();
    paths.retire_all();
}
