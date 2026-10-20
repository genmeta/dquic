use std::{
    sync::{Arc, Mutex},
    task::Poll,
};

use derive_more::Deref;
use qbase::{
    cid::*,
    error::{Error, ErrorKind},
    frame::{
        NewConnectionIdFrame, RetireConnectionIdFrame,
        io::{ReceiveFrame, SendFrame},
    },
    net::tx::ArcSendWakers,
    varint::VarInt,
};

#[derive(Debug, Clone, Default, Deref)]
struct RetiredCids(Arc<Mutex<Vec<RetireConnectionIdFrame>>>);

impl SendFrame<RetireConnectionIdFrame> for RetiredCids {
    fn send_frame<I: IntoIterator<Item = RetireConnectionIdFrame>>(&self, iter: I) {
        self.0.lock().unwrap().extend(iter);
    }
}

#[test]
fn borrowed_cid_outlives_the_cell_handle_and_defers_path_retirement() {
    let retired = RetiredCids::default();
    let cid = ConnectionId::from_slice(b"client00");
    let remote = ArcRemoteCids::new(cid, 2, retired.clone());
    let cell = remote.apply_dcid();
    let Poll::Ready(Some(borrowed)) = cell.borrow_cid(ArcSendWakers::default()) else {
        panic!("initial CID is ready");
    };
    cell.retire();
    assert!(retired.lock().unwrap().is_empty());
    assert!(matches!(
        cell.borrow_cid(ArcSendWakers::default()),
        Poll::Ready(None)
    ));
    drop(cell);
    assert_eq!(*borrowed, cid);
    drop(borrowed);
    assert_eq!(retired.lock().unwrap().len(), 1);
}

#[test]
fn initial_cid_can_be_retired_before_any_sender_requests_a_cell() {
    let remote = ArcRemoteCids::new(
        ConnectionId::from_slice(b"client00"),
        2,
        RetiredCids::default(),
    );
    let next = ConnectionId::from_slice(b"client01");
    remote
        .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 1u32.into()))
        .unwrap();
    let selected = remote.apply_dcid();
    assert!(matches!(selected.borrow_cid(ArcSendWakers::default()),
        Poll::Ready(Some(cid)) if *cid == next));
}

#[test]
fn selected_server_limit_counts_initial_and_new_cids() {
    let initial = ConnectionId::from_slice(b"client00");
    let remote = ArcRemoteCids::new(initial, 8, RetiredCids::default());
    let cell = remote.apply_dcid();

    for seq in 1..8u32 {
        let frame = NewConnectionIdFrame::new(
            ConnectionId::from_slice(&u64::from(seq).to_be_bytes()),
            VarInt::from_u32(seq),
            VarInt::from_u32(0),
        );
        assert!(remote.recv_frame(frame).is_ok());
    }
    assert!(matches!(
        cell.borrow_cid(ArcSendWakers::default()),
        Poll::Ready(Some(cid)) if *cid == initial
    ));

    let frame = NewConnectionIdFrame::new(
        ConnectionId::from_slice(b"client08"),
        VarInt::from_u32(8),
        VarInt::from_u32(0),
    );
    assert!(matches!(remote.recv_frame(frame), Err(Error::Quic(error))
        if error.kind() == ErrorKind::ConnectionIdLimit));
}

#[test]
fn construction_leaves_allocation_to_the_first_sender() {
    let initial = ConnectionId::from_slice(b"client00");
    let next = ConnectionId::from_slice(b"client01");
    let remote = ArcRemoteCids::new(initial, 4, RetiredCids::default());

    remote
        .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
        .unwrap();
    let selected = remote.apply_dcid();
    assert!(matches!(selected.borrow_cid(ArcSendWakers::default()),
        Poll::Ready(Some(cid)) if *cid == initial));
    let other = remote.apply_dcid();
    assert!(matches!(other.borrow_cid(ArcSendWakers::default()),
        Poll::Ready(Some(cid)) if *cid == next));
}

#[test]
fn test_remote_cids() {
    let retired_cids = RetiredCids::default();
    let initial_dcid = ConnectionId::random_gen(8);
    let remote_cids = ArcRemoteCids::new(initial_dcid, 8, retired_cids.clone());
    let cid_apply0 = remote_cids.apply_dcid();

    let waker = ArcSendWakers::default();
    assert!(matches!(
        cid_apply0.borrow_cid(waker.clone()),
        Poll::Ready(Some(cid)) if *cid == initial_dcid
    ));

    // Will return Pending, because the peer hasn't issue any connection id
    let cid_apply1 = remote_cids.apply_dcid();
    assert!(matches!(
        cid_apply1.borrow_cid(waker.clone()),
        Poll::Pending
    ));

    let new_dcid = ConnectionId::random_gen(8);
    let frame = NewConnectionIdFrame::new(new_dcid, VarInt::from_u32(1), VarInt::from_u32(0));
    assert!(remote_cids.recv_frame(frame).is_ok());

    assert!(matches!(
        cid_apply0.borrow_cid(waker.clone()),
        Poll::Ready(Some(cid)) if *cid == initial_dcid
    ));
    assert!(matches!(
        cid_apply1.borrow_cid(waker.clone()),
        Poll::Ready(Some(cid)) if *cid == new_dcid
    ));

    // Additionally, a new request will be made because if the peer-issued CID is
    // insufficient, it will still return Pending.
    remote_cids
        .recv_frame(NewConnectionIdFrame::new(
            new_dcid,
            1u32.into(),
            1u32.into(),
        ))
        .unwrap();
    assert_eq!(
        &*retired_cids.lock().unwrap(),
        &[RetireConnectionIdFrame::new(0u32.into())]
    );
    let cid_apply2 = remote_cids.apply_dcid();
    assert!(cid_apply2.borrow_cid(waker.clone()).is_pending());
    assert!(cid_apply0.borrow_cid(waker.clone()).is_pending());
}

#[test]
fn test_retire_in_remote_cids() {
    let retired_cids = RetiredCids::default();
    let initial_dcid = ConnectionId::random_gen(8);
    let remote_cids = ArcRemoteCids::new(initial_dcid, 8, retired_cids.clone());
    let cid_apply0 = remote_cids.apply_dcid();

    let cids: Vec<_> = std::iter::once(initial_dcid)
        .chain((1..8).map(|_| ConnectionId::random_gen(8)))
        .collect();
    // Leave replacement sequences 4..6 missing until after retirement.
    for seq in (1..4).chain(7..8) {
        let cid = cids[seq as usize];
        let frame = NewConnectionIdFrame::new(cid, VarInt::from_u32(seq), VarInt::from_u32(0));
        remote_cids.recv_frame(frame).unwrap();
    }

    let cid_apply1 = remote_cids.apply_dcid();

    let waker = ArcSendWakers::default();
    let Poll::Ready(Some(borrowed0)) = cid_apply0.borrow_cid(waker.clone()) else {
        panic!("initial CID is ready");
    };
    let Poll::Ready(Some(borrowed1)) = cid_apply1.borrow_cid(waker.clone()) else {
        panic!("second CID is ready");
    };

    remote_cids
        .recv_frame(NewConnectionIdFrame::new(cids[7], 7u32.into(), 4u32.into()))
        .unwrap();
    // delay retire cid
    assert_eq!(retired_cids.0.lock().unwrap().len(), 2);

    assert!(cid_apply0.borrow_cid(waker.clone()).is_pending());
    assert!(cid_apply1.borrow_cid(waker.clone()).is_pending());
    assert_eq!(*borrowed0, cids[0]);
    assert_eq!(*borrowed1, cids[1]);

    for seq in 4..7 {
        remote_cids
            .recv_frame(NewConnectionIdFrame::new(
                cids[seq as usize],
                VarInt::from_u32(seq),
                4u32.into(),
            ))
            .unwrap();
    }
    assert_eq!(retired_cids.0.lock().unwrap().len(), 2);
    drop(borrowed0);
    drop(borrowed1);
    assert_eq!(retired_cids.0.lock().unwrap().len(), 4);

    for seq in [1, 0, 3, 2] {
        assert_eq!(
            // like a stack, the last in the first out
            retired_cids.0.lock().unwrap().pop(),
            Some(RetireConnectionIdFrame::new(VarInt::from_u32(seq)))
        );
    }

    assert!(matches!(
        cid_apply0.borrow_cid(waker.clone()),
        Poll::Ready(Some(entry)) if *entry == cids[4]
    ));
    assert!(matches!(
        cid_apply1.borrow_cid(waker.clone()),
       Poll::Ready(Some(entry)) if *entry == cids[5]
    ));

    cid_apply1.retire();
    assert_eq!(retired_cids.lock().unwrap().len(), 1);
    assert_eq!(
        retired_cids.0.lock().unwrap().pop(),
        Some(RetireConnectionIdFrame::new(VarInt::from_u32(5)))
    );
}

#[test]
fn test_retire_without_apply() {
    let retired_cids = RetiredCids::default();
    let initial_dcid = ConnectionId::random_gen(8);
    let remote_cids = ArcRemoteCids::new(initial_dcid, 8, retired_cids.clone());
    let cid_apply0 = remote_cids.apply_dcid();

    let mut cids = vec![initial_dcid];
    for seq in 1..8 {
        let cid = ConnectionId::random_gen(8);
        cids.push(cid);
        let frame = NewConnectionIdFrame::new(cid, VarInt::from_u32(seq), VarInt::from_u32(0));
        remote_cids.recv_frame(frame).unwrap();
    }

    remote_cids
        .recv_frame(NewConnectionIdFrame::new(cids[7], 7u32.into(), 4u32.into()))
        .unwrap();
    assert_eq!(retired_cids.0.lock().unwrap().len(), 4);

    let cid_apply1 = remote_cids.apply_dcid();
    let waker = ArcSendWakers::default();
    assert!(matches!(
        cid_apply0.borrow_cid(waker.clone()),
       Poll::Ready(Some(entry)) if *entry == cids[4]
    ));
    assert!(matches!(
        cid_apply1.borrow_cid(waker.clone()),
        Poll::Ready(Some(entry)) if *entry == cids[5]
    ));
}
