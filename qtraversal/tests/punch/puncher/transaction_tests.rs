use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    frame::{
        AddAddressFrame, Frame, PunchDoneFrame, PunchHelloFrame, PunchMeNowFrame, ReliableFrame,
        io::SendFrame,
    },
    net::{
        NatType,
        route::{Line, Link, Pathway},
    },
};
use qprotocol::{Dock, UdpSocket};
use qtraversal::punch::ArcPuncher;
use tokio::{sync::mpsc, task::Id};

use super::support::{Encoder, decode};

struct Binding(Arc<UdpSocket>);

impl Binding {
    fn new() -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        // This test controls delivery itself. Keep the public registration for
        // outgoing strategies, but receive through the fixture instead of Dock.
        Dock::global().add(socket.clone()).unwrap().unwrap().abort();
        Self(socket)
    }

    fn bound(&self) -> SocketAddr {
        self.0.local_addr().unwrap()
    }

    async fn receive_hello(&self, expected: PunchHelloFrame) -> SocketAddr {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut packets = [BytesMut::zeroed(128)];
            let mut lines = [Line::default()];
            loop {
                match self.0.receive(&mut packets, &mut lines).await {
                    // Collision probes intentionally target unbound loopback
                    // ports. Windows reports their ICMP replies on this socket;
                    // they are not a peer response in the arbitration scenario.
                    Err(error) if error.kind() == io::ErrorKind::ConnectionReset => continue,
                    result => {
                        result.unwrap();
                    }
                }
                let bytes = packets[0].split_to(lines[0].seg_size as usize);
                packets[0].resize(128, 0);
                if decode(bytes)
                    .into_iter()
                    .any(|frame| matches!(frame, Frame::PunchHello(hello) if hello == expected))
                {
                    return lines[0].link.src;
                }
            }
        })
        .await
        .expect("predicted probe must reach the peer")
    }
}

impl Drop for Binding {
    fn drop(&mut self) {
        Dock::global().remove(&self.0);
    }
}

#[derive(Clone)]
struct Frames(mpsc::UnboundedSender<(ReliableFrame, Option<Id>)>);

impl SendFrame<ReliableFrame> for Frames {
    fn send_frame<I: IntoIterator<Item = ReliableFrame>>(&self, frames: I) {
        for frame in frames {
            let _ = self.0.send((frame, tokio::task::try_id()));
        }
    }
}

async fn next_now(
    frames: &mut mpsc::UnboundedReceiver<(ReliableFrame, Option<Id>)>,
) -> (PunchMeNowFrame, Id) {
    let (frame, task) = tokio::time::timeout(Duration::from_secs(2), frames.recv())
        .await
        .unwrap()
        .unwrap();
    let ReliableFrame::PunchMeNow(frame) = frame else {
        panic!("both active strategies must send NOW first");
    };
    (frame, task.unwrap())
}

#[tokio::test]
async fn simultaneous_active_peers_agree_on_roles_in_both_delivery_orders() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
    for (low_nat, high_nat) in [
        (NatType::RestrictedPort, NatType::RestrictedPort),
        (NatType::RestrictedPort, NatType::Symmetric),
        (NatType::Symmetric, NatType::RestrictedPort),
    ] {
        for deliver_to_larger_first in [false, true] {
            println!(
                "arbitration {low_nat:?}/{high_nat:?}, larger first: {deliver_to_larger_first}"
            );
            let first = Binding::new();
            let second = Binding::new();
            let (low_socket, high_socket) = if first.bound() < second.bound() {
                (&first, &second)
            } else {
                (&second, &first)
            };
            let [lower, higher] = [low_socket.bound(), high_socket.bound()];
            let (low_frames, mut low_received) = mpsc::unbounded_channel();
            let (high_frames, mut high_received) = mpsc::unbounded_channel();
            let low_encoder = Encoder::default();
            let high_encoder = Encoder::default();
            let low = ArcPuncher::new(Frames(low_frames), low_encoder.clone());
            let high = ArcPuncher::new(Frames(high_frames), high_encoder.clone());
            for (puncher, bound, nat) in [(&low, lower, low_nat), (&high, higher, high_nat)] {
                puncher.on_local_added(bound, bound.into(), bound, 0, nat);
            }
            let ReliableFrame::AddAddress(low_address) = low_received.recv().await.unwrap().0
            else {
                panic!("expected ADD_ADDRESS");
            };
            let ReliableFrame::AddAddress(high_address) = high_received.recv().await.unwrap().0
            else {
                panic!("expected ADD_ADDRESS");
            };
            low.recv_add_address(high_address);
            high.recv_add_address(low_address);

            // Observe the calling task at the public SendFrame / encoder boundaries.
            // The smaller peer must switch owners; the larger must keep its owner.
            let ((low_now, low_active), (high_now, high_active)) =
                tokio::join!(next_now(&mut low_received), next_now(&mut high_received),);
            let low_path = Pathway::new(lower.into(), higher.into());
            let high_path = low_path.flip();
            if deliver_to_larger_first {
                high.recv_punch_me_now(high_path, low_now);
                low.recv_punch_me_now(low_path, high_now);
            } else {
                low.recv_punch_me_now(low_path, high_now);
                high.recv_punch_me_now(high_path, low_now);
            }

            for (puncher, encoder, frames, peer_socket, path, link, active, replaced, nat) in [
                (
                    &low,
                    &low_encoder,
                    &mut low_received,
                    high_socket,
                    low_path,
                    Link::new(lower, higher),
                    low_active,
                    true,
                    low_nat,
                ),
                (
                    &high,
                    &high_encoder,
                    &mut high_received,
                    low_socket,
                    high_path,
                    Link::new(higher, lower),
                    high_active,
                    false,
                    high_nat,
                ),
            ] {
                let hello = encoder
                    .wait_for_hello(|task| (task != active) == replaced)
                    .await;
                let temporary = if nat == NatType::Symmetric {
                    let source = peer_socket.receive_hello(hello).await;
                    assert_ne!(source, link.src);
                    // The actual predicted probe ID, not an injected private Transaction.
                    puncher.recv_punch_done(link, PunchDoneFrame::respond_to(&hello));
                    Some(source)
                } else {
                    let hello = PunchHelloFrame::new(hello.remote_seq(), hello.local_seq(), 19);
                    puncher.recv_punch_hello(path, link, hello);
                    let (done, owner) = tokio::time::timeout(Duration::from_secs(2), async {
                        loop {
                            let (frame, owner) = frames.recv().await.unwrap();
                            if let ReliableFrame::PunchDone(done) = frame {
                                break (done, owner.unwrap());
                            }
                        }
                    })
                    .await
                    .unwrap();
                    assert_eq!(done, PunchDoneFrame::respond_to(&hello));
                    assert_eq!(owner != active, replaced);
                    None
                };
                // Let the DONE receiver finish before checking replay suppression.
                tokio::time::sleep(Duration::from_millis(100)).await;
                puncher.abort_transactions();
                let before = encoder.hellos().len();
                puncher.recv_punch_me_now(
                    path,
                    PunchMeNowFrame::new(0, 0, link.dst, 0, NatType::FullCone),
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert_eq!(
                    encoder.hellos().len(),
                    before,
                    "completed pair must not restart"
                );
                if let Some(source) = temporary {
                    assert!(
                        Dock::global().find_socket(source).is_some(),
                        "winning socket is retained after completion"
                    );
                }
                puncher.release_temporary_sockets();
                if let Some(source) = temporary {
                    assert!(Dock::global().find_socket(source).is_none());
                }
                // Original bindings survive temporary-socket cleanup.
                assert!(Dock::global().find_socket(link.src).is_some());
                assert_eq!(hello.probe_id() != 0, temporary.is_some());
            }
        }
    }
}

#[tokio::test]
async fn stale_active_completion_preserves_passive_transaction_and_done_delivery() {
    type DoneCallback = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

    #[derive(Clone)]
    struct CallbackFrames {
        frames: Frames,
        on_done: DoneCallback,
    }

    impl SendFrame<ReliableFrame> for CallbackFrames {
        fn send_frame<I: IntoIterator<Item = ReliableFrame>>(&self, frames: I) {
            for frame in frames {
                if matches!(frame, ReliableFrame::PunchDone(_)) {
                    let callback = self.on_done.lock().unwrap().take();
                    if let Some(callback) = callback {
                        callback();
                    }
                }
                self.frames.send_frame([frame]);
            }
        }
    }

    let first = Binding::new();
    let second = Binding::new();
    let mut bounds = [first.bound(), second.bound()];
    bounds.sort();
    let [local, remote] = bounds;
    let path = Pathway::new(local.into(), remote.into());
    let link = Link::new(local, remote);
    let (sender, mut received) = mpsc::unbounded_channel();
    let on_done = DoneCallback::default();
    let encoder = Encoder::default();
    let puncher = ArcPuncher::new(
        CallbackFrames {
            frames: Frames(sender),
            on_done: on_done.clone(),
        },
        encoder.clone(),
    );
    puncher.on_local_added(local, local.into(), local, 0, NatType::FullCone);
    let ReliableFrame::AddAddress(address) = received.recv().await.unwrap().0 else {
        panic!("expected ADD_ADDRESS");
    };
    let local_seq = address.seq_num();
    let remote_seq = 7;
    puncher.recv_add_address(AddAddressFrame::new(
        remote_seq,
        remote,
        0,
        NatType::RestrictedPort,
    ));
    let (_, active) = next_now(&mut received).await;
    encoder.wait_for_hello(|task| task == active).await;

    let replacement = PunchMeNowFrame::new(remote_seq, local_seq, remote, 0, NatType::FullCone);
    *on_done.lock().unwrap() = Some(Box::new({
        let puncher = puncher.clone();
        move || puncher.recv_punch_me_now(path, replacement)
    }));
    // SendFrame runs synchronously after the active task receives HELLO and
    // immediately before it returns. Reentering here installs a passive owner;
    // abort cannot interrupt the old task's remaining synchronous cleanup.
    let hello = PunchHelloFrame::new(remote_seq, local_seq, 19);
    puncher.recv_punch_hello(path, link, hello);
    let (frame, owner) = tokio::time::timeout(Duration::from_secs(2), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(frame, ReliableFrame::PunchDone(done) if done == PunchDoneFrame::respond_to(&hello))
    );
    assert_eq!(owner, Some(active));
    assert!(on_done.lock().unwrap().is_none());

    let passive_hello = encoder.wait_for_hello(|task| task != active).await;
    puncher.recv_punch_done(link, PunchDoneFrame::respond_to(&passive_hello));
    let sent = encoder.hellos().len();
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        encoder.hellos().len(),
        sent,
        "DONE must reach the passive owner and stop its retries"
    );

    // Completion retires the selected owner and suppresses another request.
    puncher.recv_punch_me_now(path, replacement);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        encoder.hellos().len(),
        sent,
        "completed replacement must not restart"
    );
    let late_hello = PunchHelloFrame::new(remote_seq, local_seq, 23);
    puncher.recv_punch_hello(path, link, late_hello);
    let (frame, owner) = received
        .try_recv()
        .expect("completed pair answers HELLO immediately");
    assert!(
        matches!(frame, ReliableFrame::PunchDone(done) if done == PunchDoneFrame::respond_to(&late_hello))
    );
    assert_eq!(owner, tokio::task::try_id());
    puncher.abort_transactions();
}
