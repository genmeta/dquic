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
