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
    let remote = ArcRemoteCids::new(limit, retired.clone());
    remote.set_initial_dcid(cid(0));
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
