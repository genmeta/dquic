use std::{
    sync::{Arc, Mutex},
    task::Poll,
};

use qbase::{
    cid::{ArcRemoteCids, ConnectionId},
    error::{Error, ErrorKind},
    frame::{
        NewConnectionIdFrame, RetireConnectionIdFrame,
        io::{ReceiveFrame, SendFrame},
    },
    net::tx::ArcSendWakers,
    varint::VarInt,
};

#[derive(Clone, Default)]
struct Retired(Arc<Mutex<Vec<RetireConnectionIdFrame>>>);

impl SendFrame<RetireConnectionIdFrame> for Retired {
    fn send_frame<I: IntoIterator<Item = RetireConnectionIdFrame>>(&self, frames: I) {
        self.0.lock().unwrap().extend(frames);
    }
}

fn cid(seq: u64) -> ConnectionId {
    ConnectionId::from_slice(&seq.to_be_bytes())
}

fn frame(seq: u64, retire_prior_to: u64) -> NewConnectionIdFrame {
    NewConnectionIdFrame::new(
        cid(seq),
        VarInt::from_u64(seq).unwrap(),
        VarInt::from_u64(retire_prior_to).unwrap(),
    )
}

fn remote(limit: u64) -> (ArcRemoteCids<Retired>, Retired) {
    let retired = Retired::default();
    let remote = ArcRemoteCids::new(cid(0), limit, retired.clone());
    (remote, retired)
}

#[test]
fn replacing_nonconsecutive_retired_cids_preserves_capacity() {
    let (remote, retired) = remote(10);
    for seq in 1..10 {
        remote.recv_frame(frame(seq, 0)).unwrap();
    }
    let cells = (0..6).map(|_| remote.apply_dcid()).collect::<Vec<_>>();
    cells[1].retire();
    cells[4].retire();
    assert_eq!(
        retired
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|frame| frame.sequence())
            .collect::<Vec<_>>(),
        vec![1, 4]
    );

    remote.recv_frame(frame(10, 0)).unwrap();
    remote.recv_frame(frame(11, 0)).unwrap();
    assert!(matches!(
        remote.recv_frame(frame(12, 0)),
        Err(Error::Quic(error)) if error.kind() == ErrorKind::ConnectionIdLimit
    ));
}

#[test]
fn initial_and_out_of_order_cids_are_counted_once() {
    let (remote, _) = remote(3);
    let second = frame(2, 0);
    remote.recv_frame(second).unwrap();
    remote.recv_frame(second).unwrap();
    remote.recv_frame(frame(1, 0)).unwrap();
    assert!(matches!(
        remote.recv_frame(frame(3, 0)),
        Err(Error::Quic(error)) if error.kind() == ErrorKind::ConnectionIdLimit
    ));
    for seq in 0..3 {
        let cell = remote.apply_dcid();
        assert!(matches!(
            cell.borrow_cid(ArcSendWakers::default()),
            Poll::Ready(Some(borrowed)) if *borrowed == cid(seq)
        ));
    }
}

#[test]
fn retransmitting_a_locally_retired_cid_does_not_reactivate_it() {
    let (remote, _) = remote(2);
    let first = frame(1, 0);
    remote.recv_frame(first).unwrap();
    let _initial = remote.apply_dcid();
    let retired = remote.apply_dcid();
    retired.retire();
    remote.recv_frame(frame(2, 0)).unwrap();
    remote.recv_frame(first).unwrap();
    assert!(matches!(
        retired.borrow_cid(ArcSendWakers::default()),
        Poll::Ready(None)
    ));
    let replacement = remote.apply_dcid();
    assert!(matches!(
        replacement.borrow_cid(ArcSendWakers::default()),
        Poll::Ready(Some(borrowed)) if *borrowed == cid(2)
    ));
    assert!(matches!(
        remote.recv_frame(frame(3, 0)),
        Err(Error::Quic(error)) if error.kind() == ErrorKind::ConnectionIdLimit
    ));
}

#[test]
fn peer_retirement_frees_capacity_before_the_limit_check() {
    let (remote, _) = remote(2);
    let first = frame(1, 0);
    remote.recv_frame(first).unwrap();
    remote.recv_frame(frame(2, 1)).unwrap();
    remote.recv_frame(first).unwrap();
    remote.recv_frame(frame(3, 2)).unwrap();
    assert!(remote.recv_frame(frame(0, 0)).unwrap().is_none());
    for seq in 2..4 {
        let cell = remote.apply_dcid();
        assert!(matches!(
            cell.borrow_cid(ArcSendWakers::default()),
            Poll::Ready(Some(borrowed)) if *borrowed == cid(seq)
        ));
    }
}

#[derive(Default)]
struct WakeCounter(std::sync::atomic::AtomicUsize);

impl std::task::Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

fn retired_sequences(retired: &Retired) -> Vec<u64> {
    retired
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|frame| frame.sequence())
        .collect()
}

#[test]
fn retired_cid_waits_for_replacement_without_closing_its_binding() {
    let (remote, retired) = remote(4);
    remote.recv_frame(frame(1, 0)).unwrap();
    let first = remote.apply_dcid();
    let second = remote.apply_dcid();
    // Both paths lose their CID, but only one replacement is available.
    remote.recv_frame(frame(2, 2)).unwrap();
    assert_eq!(retired_sequences(&retired), [0, 1]);
    assert!(matches!(first.borrow_cid(ArcSendWakers::default()),
        Poll::Ready(Some(borrowed)) if *borrowed == cid(2)));
    let counter = Arc::new(WakeCounter::default());
    let wakers = ArcSendWakers::default();
    wakers.register(&std::task::Waker::from(counter.clone()));
    assert!(second.borrow_cid(wakers.clone()).is_pending());
    // Repeating the retirement does not reactivate CID 1 or retire it twice.
    remote.recv_frame(frame(2, 2)).unwrap();
    assert!(second.borrow_cid(wakers.clone()).is_pending());
    assert_eq!(retired_sequences(&retired), [0, 1]);
    remote.recv_frame(frame(3, 2)).unwrap();
    assert_eq!(counter.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert!(matches!(second.borrow_cid(wakers),
        Poll::Ready(Some(borrowed)) if *borrowed == cid(3)));
}

#[test]
fn pinned_retired_cid_is_not_reborrowed_and_is_released_without_a_replacement() {
    let (remote, retired) = remote(4);
    remote.recv_frame(frame(1, 0)).unwrap();
    let _first = remote.apply_dcid();
    let second = remote.apply_dcid();
    let Poll::Ready(Some(borrowed)) = second.borrow_cid(ArcSendWakers::default()) else {
        panic!("CID 1 is ready");
    };
    remote.recv_frame(frame(2, 2)).unwrap();
    assert_eq!(*borrowed, cid(1));
    assert_eq!(retired_sequences(&retired), [0]);
    assert!(second.borrow_cid(ArcSendWakers::default()).is_pending());
    drop(borrowed);
    assert_eq!(retired_sequences(&retired), [0, 1]);
    assert!(second.borrow_cid(ArcSendWakers::default()).is_pending());
    remote.recv_frame(frame(3, 2)).unwrap();
    assert!(matches!(second.borrow_cid(ArcSendWakers::default()),
        Poll::Ready(Some(borrowed)) if *borrowed == cid(3)));
    assert_eq!(retired_sequences(&retired), [0, 1]);
}

#[test]
fn closing_a_binding_waiting_for_replacement_wakes_it_and_does_not_reactivate_it() {
    let (remote, retired) = remote(4);
    remote.recv_frame(frame(1, 0)).unwrap();
    let _first = remote.apply_dcid();
    let second = remote.apply_dcid();
    let Poll::Ready(Some(borrowed)) = second.borrow_cid(ArcSendWakers::default()) else {
        panic!("CID 1 is ready");
    };
    remote.recv_frame(frame(2, 2)).unwrap();
    let counter = Arc::new(WakeCounter::default());
    let wakers = ArcSendWakers::default();
    wakers.register(&std::task::Waker::from(counter.clone()));
    assert!(second.borrow_cid(wakers.clone()).is_pending());
    second.retire();
    assert_eq!(counter.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert!(matches!(
        second.borrow_cid(wakers.clone()),
        Poll::Ready(None)
    ));
    assert_eq!(retired_sequences(&retired), [0]);
    drop(borrowed);
    assert_eq!(retired_sequences(&retired), [0, 1]);
    remote.recv_frame(frame(3, 2)).unwrap();
    assert!(matches!(second.borrow_cid(wakers), Poll::Ready(None)));
    let third = remote.apply_dcid();
    assert!(matches!(third.borrow_cid(ArcSendWakers::default()),
        Poll::Ready(Some(borrowed)) if *borrowed == cid(3)));
}
