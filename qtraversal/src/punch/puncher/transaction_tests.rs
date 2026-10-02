use super::*;

#[derive(Clone, Default)]
struct Frames(Option<tokio::sync::mpsc::UnboundedSender<ReliableFrame>>);

impl SendFrame<ReliableFrame> for Frames {
    fn send_frame<I: IntoIterator<Item = ReliableFrame>>(&self, frames: I) {
        if let Some(sender) = &self.0 {
            for frame in frames {
                let _ = sender.send(frame);
            }
        }
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

#[tokio::test]
async fn stale_active_completion_preserves_passive_transaction_and_done_delivery() {
    let puncher = ArcPuncher::new(Frames::default(), Encoder);
    let id = PunchId::new(2, 7);
    let active = Arc::new(Transaction::new());
    let passive = Arc::new(Transaction::new());
    let active_task = tokio::spawn(std::future::pending::<()>());
    let passive_task = tokio::spawn(std::future::pending::<()>());
    puncher
        .0
        .transaction
        .insert(id, (active_task.abort_handle(), active.clone()));
    active_task.abort();
    puncher
        .0
        .transaction
        .insert(id, (passive_task.abort_handle(), passive.clone()));

    // Reproduce a task already leaving punch_actively when arbitration aborts it.
    assert!(!puncher.finish_transaction(id, &active));
    assert!(!puncher.0.punch_history.contains_key(&id));
    let hello = PunchHelloFrame::new(id.local_seq, id.remote_seq, 19);
    let link = Link::new(
        "127.0.0.1:40000".parse().unwrap(),
        "127.0.0.1:50000".parse().unwrap(),
    );
    puncher.recv_punch_done(link, PunchDoneFrame::respond_to(&hello));
    let (received_link, done) = passive.try_punch_done().expect("replacement receives DONE");
    assert_eq!(received_link, link);
    assert_eq!(done.probe_id(), 19);
    assert!(active.try_punch_done().is_none());

    assert!(puncher.finish_transaction(id, &passive));
    assert!(!puncher.0.transaction.contains_key(&id));
    assert!(puncher.0.punch_history.contains_key(&id));
    assert!(!puncher.finish_transaction(id, &active));
    assert!(puncher.0.punch_history.contains_key(&id));
    passive_task.abort();
}

async fn next_punch_me_now(
    frames: &mut tokio::sync::mpsc::UnboundedReceiver<ReliableFrame>,
) -> PunchMeNowFrame {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let ReliableFrame::PunchMeNow(frame) = frames.recv().await.unwrap() {
                return frame;
            }
        }
    })
    .await
    .expect("both peers must send PUNCH_ME_NOW before either receives the other request")
}

#[tokio::test]
async fn simultaneous_active_peers_agree_on_roles_in_both_delivery_orders() {
    for (low_nat, high_nat) in [
        (NatType::RestrictedPort, NatType::RestrictedPort),
        (NatType::RestrictedPort, NatType::Symmetric),
        (NatType::Symmetric, NatType::RestrictedPort),
    ] {
        for deliver_to_larger_first in [false, true] {
            let first = EphemeralSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let second = EphemeralSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let mut bounds = [
                first.udp_socket().local_addr().unwrap(),
                second.udp_socket().local_addr().unwrap(),
            ];
            bounds.sort();
            let [lower, higher] = bounds;
            let (low_frames, mut low_received) = tokio::sync::mpsc::unbounded_channel();
            let (high_frames, mut high_received) = tokio::sync::mpsc::unbounded_channel();
            let low = ArcPuncher::new(Frames(Some(low_frames)), Encoder);
            let high = ArcPuncher::new(Frames(Some(high_frames)), Encoder);
            for (puncher, bound, nat) in [(&low, lower, low_nat), (&high, higher, high_nat)] {
                puncher.on_local_added(bound, bound.into(), bound, 0, nat);
            }
            let low_address = low.0.addresses.lock().unwrap().local_frames()[0];
            let high_address = high.0.addresses.lock().unwrap().local_frames()[0];
            low.recv_add_address(high_address);
            high.recv_add_address(low_address);

            // Hold both reliable requests at a barrier: neither peer can become
            // passive before both have actually run their active strategy.
            let (low_now, high_now) = tokio::join!(
                next_punch_me_now(&mut low_received),
                next_punch_me_now(&mut high_received),
            );
            let id = PunchId::new(low_address.seq_num(), high_address.seq_num());
            let low_active = low.0.transaction.get(&id).unwrap().1.clone();
            let high_active = high.0.transaction.get(&id.flip()).unwrap().1.clone();
            let low_path = Pathway::new(lower.into(), higher.into());
            let high_path = low_path.flip();
            if deliver_to_larger_first {
                high.recv_punch_me_now(high_path, low_now);
                low.recv_punch_me_now(low_path, high_now);
            } else {
                low.recv_punch_me_now(low_path, high_now);
                high.recv_punch_me_now(high_path, low_now);
            }

            let low_passive = low.0.transaction.get(&id).unwrap().1.clone();
            let high_retained = high.0.transaction.get(&id.flip()).unwrap().1.clone();
            assert!(!Arc::ptr_eq(&low_active, &low_passive));
            assert!(Arc::ptr_eq(&high_active, &high_retained));
            assert!(!low.finish_transaction(id, &low_active));
            assert!(high_retained.wait_punch_me_now().await == low_now);
            assert!(low_passive.wait_punch_me_now().await == high_now);

            // Complete both selected transactions, checking that late cleanup from
            // the cancelled active owner did not disconnect the passive receiver.
            for (puncher, path, link, own_id, nat) in [
                (&low, low_path, Link::new(lower, higher), id, low_nat),
                (
                    &high,
                    high_path,
                    Link::new(higher, lower),
                    id.flip(),
                    high_nat,
                ),
            ] {
                if nat == NatType::Symmetric {
                    puncher.recv_punch_done(
                        link,
                        PunchDoneFrame::respond_to(&PunchHelloFrame::new(
                            own_id.local_seq,
                            own_id.remote_seq,
                            1,
                        )),
                    );
                } else {
                    puncher.recv_punch_hello(
                        path,
                        link,
                        PunchHelloFrame::new(own_id.remote_seq, own_id.local_seq, 1),
                    );
                }
            }
            tokio::time::timeout(Duration::from_secs(1), async {
                while !low.0.transaction.is_empty() || !high.0.transaction.is_empty() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("both negotiated transactions must complete");
            assert!(low.0.punch_history.contains_key(&id));
            assert!(high.0.punch_history.contains_key(&id.flip()));
            assert_eq!(
                low.0.temporary_sockets.len(),
                usize::from(low_nat == NatType::Symmetric)
            );
            assert_eq!(
                high.0.temporary_sockets.len(),
                usize::from(high_nat == NatType::Symmetric)
            );
        }
    }
}
