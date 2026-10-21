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
