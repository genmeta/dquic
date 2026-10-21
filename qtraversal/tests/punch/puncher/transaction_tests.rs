use std::time::Duration;

use qbase::{
    frame::{
        Frame, PunchDoneFrame, PunchHelloFrame, PunchMeNowFrame, ReliableFrame, io::SendFrame,
    },
    net::{
        NatType,
        route::{Link, Pathway},
    },
};
use qprotocol::{Dock, EphemeralSocket, QuicProtocol};
use qtraversal::punch::ArcPuncher;
use tokio::{sync::mpsc, task::Id};

use super::support::{Encoder, PROBE, decode};

struct Receiver;

impl Drop for Receiver {
    fn drop(&mut self) {
        QuicProtocol::global().on_receive(|_, _, _| {});
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

#[tokio::test(start_paused = true)]
async fn simultaneous_active_peers_agree_on_roles_in_both_delivery_orders() {
    for (low_nat, high_nat) in [
        (NatType::RestrictedPort, NatType::RestrictedPort),
        (NatType::RestrictedPort, NatType::Symmetric),
        (NatType::Symmetric, NatType::RestrictedPort),
    ] {
        for deliver_to_larger_first in [false, true] {
            let (received, mut datagrams) = mpsc::unbounded_channel();
            QuicProtocol::global().on_receive(move |bytes, _, link| {
                if bytes.starts_with(PROBE) {
                    for frame in decode(bytes) {
                        if let Frame::PunchHello(hello) = frame {
                            let _ = received.send((hello, link));
                        }
                    }
                }
            });
            let _receiver = Receiver;
            let first = EphemeralSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let second = EphemeralSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let mut bounds = [
                first.udp_socket().local_addr().unwrap(),
                second.udp_socket().local_addr().unwrap(),
            ];
            bounds.sort();
            let [lower, higher] = bounds;
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

            for (puncher, encoder, frames, path, link, active, replaced, nat) in [
                (
                    &low,
                    &low_encoder,
                    &mut low_received,
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
                    let source = tokio::time::timeout(Duration::from_secs(2), async {
                        loop {
                            let (probe, received) = datagrams.recv().await.unwrap();
                            if probe == hello && received.src == link.dst {
                                break received.dst;
                            }
                        }
                    })
                    .await
                    .expect("predicted probe must reach the peer");
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
