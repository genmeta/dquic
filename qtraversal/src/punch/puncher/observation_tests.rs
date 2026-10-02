use std::{future::pending, net::Ipv4Addr};

use qbase::net::route::{Scope, Scopes};
use qprotocol::AddressBook;
use tokio::sync::{Notify, mpsc, oneshot};

use super::*;

#[derive(Clone, Default)]
struct Frames(Arc<Mutex<Vec<ReliableFrame>>>, Arc<Notify>);

impl SendFrame<ReliableFrame> for Frames {
    fn send_frame<I: IntoIterator<Item = ReliableFrame>>(&self, frames: I) {
        self.0.lock().unwrap().extend(frames);
        self.1.notify_one();
    }
}

impl Frames {
    fn snapshot(&self) -> Vec<ReliableFrame> {
        self.0.lock().unwrap().clone()
    }

    async fn wait_for(&self, count: usize) -> Vec<ReliableFrame> {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let changed = self.1.notified();
                let frames = self.snapshot();
                if frames.len() >= count {
                    return frames;
                }
                changed.await;
            }
        })
        .await
        .expect("address events must reach the reliable queue")
    }
}

#[derive(Clone)]
struct Encoder;

impl PunchPacketEncoder for Encoder {
    fn encode_probe<P>(&self, _: P) -> io::Result<BytesMut>
    where
        P: for<'b> Package<&'b mut BytesMut>,
    {
        Ok(BytesMut::from(&b"probe"[..]))
    }
}

struct Binding {
    socket: Arc<UdpSocket>,
    registered: Vec<EndpointAddr>,
}

impl Binding {
    fn new(device: Option<qudp::BoundDevice>) -> Self {
        let bound = "127.0.0.1:0".parse().unwrap();
        let socket = Arc::new(
            match device {
                Some(device) => UdpSocket::bind_to_device(bound, device),
                None => UdpSocket::bind(bound),
            }
            .unwrap(),
        );
        Dock::global().add(socket.clone()).unwrap();
        let endpoint = EndpointAddr::direct(socket.local_addr().unwrap());
        Self {
            socket,
            registered: vec![endpoint],
        }
    }

    fn bound(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }
    fn inner(&self) -> EndpointAddr {
        self.bound().into()
    }
    fn outer(&self, ip: [u8; 4]) -> EndpointAddr {
        EndpointAddr::direct((ip, self.bound().port()).into())
    }

    fn register(&mut self, endpoint: EndpointAddr) {
        if !self.registered.contains(&endpoint) {
            QuicProtocol::global()
                .register(endpoint, &self.socket)
                .unwrap();
            self.registered.push(endpoint);
        }
    }

    fn publish(&mut self, book: &AddressBook, endpoint: EndpointAddr) {
        self.register(endpoint);
        if endpoint.scope() == Some(Scope::External) {
            book.insert_outer(&self.socket, endpoint)
        } else {
            book.insert_inner(&self.socket, endpoint)
        }
        .unwrap();
    }
}

impl Drop for Binding {
    fn drop(&mut self) {
        Dock::global().remove(&self.socket);
    }
}

#[tokio::test]
async fn replay_advertises_lan_immediately_and_external_aliases_after_nat_arrives() {
    let book = AddressBook::new();
    let mut binding = Binding::new(None);
    let inner = binding.inner();
    let outer = binding.outer([8, 8, 4, 4]);
    let alias = binding.outer([8, 8, 8, 8]);
    for endpoint in [inner, outer, alias] {
        binding.publish(&book, endpoint);
    }
    let frames = Frames::default();
    let puncher = ArcPuncher::new(frames.clone(), Encoder);
    let (close, closed) = oneshot::channel::<()>();
    let removed = Arc::new(Mutex::new(Vec::new()));
    let observed = removed.clone();
    let task =
        puncher.observe_endpoints(book.subscribe_punch(Scopes::ALL), closed, move |endpoint| {
            observed.lock().unwrap().push(endpoint);
        });
    assert!(
        matches!(frames.snapshot().as_slice(), [ReliableFrame::AddAddress(frame)]
        if **frame == inner.addr() && frame.nat_type() == NatType::FullCone && frame.tire() == 0)
    );
    assert_eq!(book.nat(binding.bound()), None);
    book.set_nat(binding.bound(), NatType::RestrictedCone);
    assert_eq!(frames.wait_for(3).await.len(), 3);
    assert_eq!(puncher.0.addresses.lock().unwrap().len_local(), 3);
    assert!(!book.set_nat(binding.bound(), NatType::RestrictedCone));
    book.set_nat(binding.bound(), NatType::Symmetric);
    let recorded = frames.wait_for(7).await;
    assert_eq!(recorded.len(), 7);
    let locals = puncher.0.addresses.lock().unwrap().local_frames();
    assert_eq!(
        locals
            .iter()
            .filter(|frame| frame.nat_type() == NatType::FullCone)
            .count(),
        1
    );
    assert_eq!(
        locals
            .iter()
            .filter(|frame| frame.nat_type() == NatType::Symmetric)
            .count(),
        2
    );
    assert!(
        removed.lock().unwrap().is_empty(),
        "classification changes do not retire paths"
    );
    close.send(()).unwrap();
    task.await.unwrap();
    book.remove(outer);
    assert_eq!(frames.snapshot().len(), 7);
    assert!(Dock::global().find_socket(binding.bound()).is_some());
}

#[tokio::test]
async fn replacement_and_binding_withdrawal_preserve_other_aliases_and_reset_nat() {
    let book = AddressBook::new();
    let mut binding = Binding::new(None);
    let inner = binding.inner();
    let outer = binding.outer([8, 8, 4, 4]);
    let alias = binding.outer([8, 8, 8, 8]);
    book.set_nat(binding.bound(), NatType::RestrictedCone);
    for endpoint in [inner, outer, alias] {
        binding.publish(&book, endpoint);
    }
    let frames = Frames::default();
    let puncher = ArcPuncher::new(frames.clone(), Encoder);
    let (close, closed) = oneshot::channel::<()>();
    let (removed, mut removals) = mpsc::unbounded_channel();
    let task =
        puncher.observe_endpoints(book.subscribe_punch(Scopes::ALL), closed, move |endpoint| {
            removed.send(endpoint).unwrap();
        });
    assert_eq!(frames.snapshot().len(), 3);
    book.remove(outer);
    assert_eq!(frames.wait_for(4).await.len(), 4);
    assert_eq!(removals.recv().await, Some(outer));
    assert_eq!(puncher.0.addresses.lock().unwrap().len_local(), 2);
    let replacement = binding.outer([142, 250, 1, 1]);
    binding.register(replacement);
    book.replace(alias, replacement).unwrap();
    let recorded = frames.wait_for(6).await;
    assert!(
        matches!(&recorded[4..], [ReliableFrame::RemoveAddress(_), ReliableFrame::AddAddress(frame)]
        if **frame == replacement.addr() && frame.nat_type() == NatType::RestrictedCone)
    );
    assert_eq!(removals.recv().await, Some(alias));
    book.remove_bound(binding.bound());
    frames.wait_for(8).await;
    // Removed(inner), Removed(replacement), then BoundRemoved's actual Direct address.
    for endpoint in [inner, replacement, inner] {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), removals.recv())
                .await
                .unwrap(),
            Some(endpoint)
        );
    }
    assert_eq!(puncher.0.addresses.lock().unwrap().len_local(), 0);
    binding.publish(&book, outer);
    book.set_nat(binding.bound(), NatType::FullCone);
    let recorded = frames.wait_for(9).await;
    assert_eq!(
        recorded.len(),
        9,
        "a reused binding must not inherit the old NAT classification"
    );
    assert!(
        matches!(recorded.last(), Some(ReliableFrame::AddAddress(frame)) if frame.nat_type() == NatType::FullCone)
    );
    close.send(()).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn scoped_subscription_and_pending_endpoint_removal_do_not_leak_advertisements() {
    let book = AddressBook::new();
    let mut binding = Binding::new(None);
    let inner = binding.inner();
    let outer = binding.outer([8, 8, 4, 4]);
    binding.publish(&book, inner);
    binding.publish(&book, outer);
    let frames = Frames::default();
    let puncher = ArcPuncher::new(frames.clone(), Encoder);
    let (removed, mut removals) = mpsc::unbounded_channel();
    let task = puncher.observe_endpoints(
        book.subscribe_punch(Scope::External),
        pending::<()>(),
        move |endpoint| {
            removed.send(endpoint).unwrap();
        },
    );
    assert!(frames.snapshot().is_empty());
    book.remove(outer);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), removals.recv())
            .await
            .unwrap(),
        Some(outer)
    );
    book.set_nat(binding.bound(), NatType::RestrictedCone);
    drop(book);
    task.await.unwrap();
    assert!(frames.snapshot().is_empty());
    assert_eq!(puncher.0.addresses.lock().unwrap().len_local(), 0);
}

#[tokio::test]
async fn nat_refresh_cancels_old_transactions_and_forgets_their_history() {
    let book = AddressBook::new();
    let mut binding = Binding::new(None);
    let outer = binding.outer([8, 8, 4, 4]);
    binding.publish(&book, outer);
    book.set_nat(binding.bound(), NatType::RestrictedCone);
    let frames = Frames::default();
    let puncher = ArcPuncher::new(frames.clone(), Encoder);
    let (close, closed) = oneshot::channel::<()>();
    let task = puncher.observe_endpoints(book.subscribe_punch(Scope::External), closed, |_| {});
    let seq = puncher.0.addresses.lock().unwrap().local_frames()[0].seq_num();
    let active_id = PunchId::new(seq, 10);
    let finished_id = PunchId::new(seq, 11);
    let active = tokio::spawn(pending::<()>());
    puncher.0.transaction.insert(
        active_id,
        (active.abort_handle(), Arc::new(Transaction::new())),
    );
    puncher.0.punch_history.insert(finished_id, ());
    book.set_nat(binding.bound(), NatType::Dynamic);
    assert_eq!(frames.wait_for(3).await.len(), 3);
    assert!(active.await.unwrap_err().is_cancelled());
    assert!(!puncher.0.transaction.contains_key(&active_id));
    assert!(!puncher.0.punch_history.contains_key(&finished_id));
    close.send(()).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn advertised_alias_keeps_the_bound_address_for_temporary_probes() {
    let interface = netdev::get_interfaces()
        .into_iter()
        .find(|interface| {
            interface
                .ipv4
                .iter()
                .any(|ip| ip.addr() == Ipv4Addr::LOCALHOST)
        })
        .expect("loopback interface");
    let device = qudp::BoundDevice::new(interface.name, interface.index).unwrap();
    let mut binding = Binding::new(Some(device.clone()));
    let book = AddressBook::new();
    let outer = binding.outer([8, 8, 4, 4]);
    binding.publish(&book, outer);
    book.set_nat(binding.bound(), NatType::Symmetric);
    let puncher = ArcPuncher::new(Frames::default(), Encoder);
    let (close, closed) = oneshot::channel::<()>();
    let task = puncher.observe_endpoints(book.subscribe_punch(Scope::External), closed, |_| {});
    let local = puncher
        .0
        .addresses
        .lock()
        .unwrap()
        .local_for_seq(0)
        .unwrap();
    assert_eq!(local.endpoint, outer);
    assert_eq!(local.bound, binding.bound());
    let mut target = local.bound;
    target.set_port(0);
    let temporary = EphemeralSocket::bind(target).unwrap();
    assert_eq!(
        temporary.udp_socket().local_addr().unwrap().ip(),
        binding.bound().ip()
    );
    close.send(()).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn alias_probes_use_the_actual_socket_source_address() {
    let book = AddressBook::new();
    let mut binding = Binding::new(None);
    let outer = binding.outer([8, 8, 4, 4]);
    binding.publish(&book, outer);
    book.set_nat(binding.bound(), NatType::RestrictedCone);
    let puncher = ArcPuncher::new(Frames::default(), Encoder);
    let (close, closed) = oneshot::channel::<()>();
    let observer = puncher.observe_endpoints(book.subscribe_punch(Scope::External), closed, |_| {});
    let local = puncher
        .0
        .addresses
        .lock()
        .unwrap()
        .local_for_seq(0)
        .unwrap();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote = AddAddressFrame::new(9, peer.local_addr().unwrap(), 0, NatType::FullCone);
    let active = tokio::spawn({
        let puncher = puncher.clone();
        async move {
            puncher
                .punch_actively(local, remote, Arc::new(Transaction::new()))
                .await
        }
    });
    let mut bytes = [0; 32];
    let (size, source) = tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..size], b"probe");
    assert_eq!(source, binding.bound());
    active.abort();
    let _ = active.await;
    close.send(()).unwrap();
    observer.await.unwrap();
}
