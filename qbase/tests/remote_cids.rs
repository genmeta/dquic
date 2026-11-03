use std::{
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use qbase::{
    cid::{ArcRemoteCids, ConnectionId},
    error::{Error, ErrorKind},
    frame::{
        NewConnectionIdFrame, RetireConnectionIdFrame,
        io::{ReceiveFrame, SendFrame},
    },
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
    let remote = ArcRemoteCids::server(cid(0), retired.clone());
    remote.set_limit(limit);
    remote.upgrade();
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
            cell.poll_borrow(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(borrowed)) if borrowed == cid(seq)
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
        retired.poll_borrow(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(None)
    ));
    let replacement = remote.apply_dcid();
    assert!(matches!(
        replacement.poll_borrow(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(borrowed)) if borrowed == cid(2)
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
            cell.poll_borrow(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(borrowed)) if borrowed == cid(seq)
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
fn installing_the_initial_scid_wakes_the_first_cell_and_keeps_sequence_zero() {
    let retired = Retired::default();
    let remote = ArcRemoteCids::client(cid(9), retired.clone());
    remote.set_limit(4);
    let first = remote.apply_dcid();
    first.upgrade();
    let counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(first.poll_borrow(&mut cx).is_pending());
    remote.on_receive_from(cid(0));
    assert_eq!(counter.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(first.poll_borrow(&mut cx), Poll::Ready(Some(cid(0))));
    first.refresh();
    remote.on_receive_from(cid(0));
    remote.upgrade();
    let second = remote.apply_dcid();
    assert!(second.poll_borrow(&mut cx).is_pending());
    remote.recv_frame(frame(1, 0)).unwrap();
    assert_eq!(second.poll_borrow(&mut cx), Poll::Ready(Some(cid(1))));
    second.refresh();
    remote.recv_frame(frame(2, 1)).unwrap();
    remote.on_receive_from(cid(0));
    assert_eq!(first.poll_borrow(&mut cx), Poll::Ready(Some(cid(2))));
    first.refresh();
    assert_eq!(retired_sequences(&retired), [0]);
}

#[test]
fn repolling_a_pending_cell_replaces_the_waiter_for_allocation_and_retirement() {
    for close in [false, true] {
        let (remote, _) = remote(4);
        let _first = remote.apply_dcid();
        let pending = remote.apply_dcid();
        let old = Arc::new(WakeCounter::default());
        let current = Arc::new(WakeCounter::default());
        let old_waker = Waker::from(old.clone());
        let current_waker = Waker::from(current.clone());
        assert!(
            pending
                .poll_borrow(&mut Context::from_waker(&old_waker))
                .is_pending()
        );
        assert!(
            pending
                .poll_borrow(&mut Context::from_waker(&current_waker))
                .is_pending()
        );
        if close {
            pending.retire();
        } else {
            remote.recv_frame(frame(1, 0)).unwrap();
        }
        assert_eq!(old.0.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(current.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}

#[test]
fn replacement_requests_keep_the_old_cid_until_assignment_between_batches() {
    let (remote, retired) = remote(4);
    remote.recv_frame(frame(1, 0)).unwrap();
    let first = remote.apply_dcid();
    let second = remote.apply_dcid();
    // Only the first path can switch; the other path continues using CID 1.
    remote.recv_frame(frame(2, 2)).unwrap();
    assert_eq!(retired_sequences(&retired), [0]);
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(first.poll_borrow(&mut cx), Poll::Ready(Some(cid(2))));
    first.refresh();
    assert_eq!(second.poll_borrow(&mut cx), Poll::Ready(Some(cid(1))));
    second.refresh();
    remote.recv_frame(frame(2, 2)).unwrap();
    assert_eq!(second.poll_borrow(&mut cx), Poll::Ready(Some(cid(1))));
    second.refresh();
    assert_eq!(retired_sequences(&retired), [0]);
    remote.recv_frame(frame(3, 2)).unwrap();
    assert_eq!(retired_sequences(&retired), [0, 1]);
    assert_eq!(second.poll_borrow(&mut cx), Poll::Ready(Some(cid(3))));
    second.refresh();
}

#[test]
fn old_cid_stays_usable_across_refresh_until_its_replacement_arrives() {
    let (remote, retired) = remote(4);
    remote.recv_frame(frame(1, 0)).unwrap();
    let _first = remote.apply_dcid();
    let second = remote.apply_dcid();
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(second.poll_borrow(&mut cx), Poll::Ready(Some(cid(1))));
    remote.recv_frame(frame(2, 2)).unwrap();
    assert_eq!(retired_sequences(&retired), [0]);
    second.refresh();
    assert_eq!(retired_sequences(&retired), [0]);
    for _ in 0..3 {
        assert_eq!(second.poll_borrow(&mut cx), Poll::Ready(Some(cid(1))));
        second.refresh();
        assert_eq!(retired_sequences(&retired), [0]);
    }
    let snapshot = second.poll_borrow(&mut cx);
    remote.recv_frame(frame(3, 2)).unwrap();
    assert_eq!(snapshot, Poll::Ready(Some(cid(1))));
    assert_eq!(retired_sequences(&retired), [0]);
    second.refresh();
    assert_eq!(retired_sequences(&retired), [0, 1]);
    assert_eq!(second.poll_borrow(&mut cx), Poll::Ready(Some(cid(3))));
    second.refresh();
}

#[test]
fn closing_a_binding_awaiting_replacement_retires_its_last_cid_without_reactivation() {
    let (remote, retired) = remote(4);
    remote.recv_frame(frame(1, 0)).unwrap();
    let _first = remote.apply_dcid();
    let second = remote.apply_dcid();
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(second.poll_borrow(&mut cx), Poll::Ready(Some(cid(1))));
    remote.recv_frame(frame(2, 2)).unwrap();
    second.retire();
    assert_eq!(second.poll_borrow(&mut cx), Poll::Ready(None));
    assert_eq!(retired_sequences(&retired), [0]);
    second.refresh();
    assert_eq!(retired_sequences(&retired), [0, 1]);
    remote.recv_frame(frame(3, 2)).unwrap();
    assert_eq!(second.poll_borrow(&mut cx), Poll::Ready(None));
    let third = remote.apply_dcid();
    assert_eq!(third.poll_borrow(&mut cx), Poll::Ready(Some(cid(3))));
    third.refresh();
}
