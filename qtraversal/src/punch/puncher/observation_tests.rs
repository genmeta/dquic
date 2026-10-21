use std::future::pending;

use qbase::net::route::Scope;
use qprotocol::AddressBook;
use tokio::sync::{Notify, oneshot};

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
