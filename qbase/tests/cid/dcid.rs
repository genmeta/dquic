use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use qbase::{
    cid::{ArcDcid, ArcRemoteCids, ConnectionId},
    frame::{
        NewConnectionIdFrame, RetireConnectionIdFrame,
        io::{ReceiveFrame, SendFrame},
    },
};

#[derive(Debug, Clone, Default)]
struct Retired(Arc<Mutex<Vec<RetireConnectionIdFrame>>>);

impl SendFrame<RetireConnectionIdFrame> for Retired {
    fn send_frame<I: IntoIterator<Item = RetireConnectionIdFrame>>(&self, frames: I) {
        self.0.lock().unwrap().extend(frames);
    }
}

fn cid(seq: u8) -> ConnectionId {
    ConnectionId::from_slice(&[seq; 8])
}

fn borrow(dcid: &ArcDcid<Retired>) -> Poll<Option<ConnectionId>> {
    dcid.poll_borrow(&mut Context::from_waker(Waker::noop()))
}

fn remote(retired: Retired) -> ArcRemoteCids<Retired> {
    let remote = ArcRemoteCids::server(cid(0), retired);
    remote.set_limit(4);
    remote
}

#[test]
fn handshake_source_updates_all_paths_but_upgrades_only_the_selected_path() {
    let remote = ArcRemoteCids::client(cid(9), Retired::default());
    remote.set_limit(4);
    let selected = remote.apply_dcid();
    let other = remote.apply_dcid();
    let snapshot = borrow(&selected);
    assert!(remote.on_receive_from(cid(0)));
    assert!(!remote.on_receive_from(cid(8)));
    assert_eq!(snapshot, Poll::Ready(Some(cid(9))));
    assert_eq!(borrow(&selected), Poll::Ready(Some(cid(0))));
    assert_eq!(borrow(&other), Poll::Ready(Some(cid(0))));
    assert_eq!(borrow(&remote.apply_dcid()), Poll::Ready(Some(cid(0))));
    selected.upgrade();
    selected.upgrade();
    assert!(selected.is_allocated());
    assert!(!other.is_allocated());
    assert_eq!(borrow(&selected), Poll::Ready(Some(cid(0))));
    remote.upgrade();
    let later = remote.apply_dcid();
    assert!(later.is_allocated());
    assert!(borrow(&later).is_pending());
    other.upgrade();
    assert!(other.is_allocated());
    assert!(borrow(&other).is_pending());
    remote.recv_frame(NewConnectionIdFrame::new(cid(1), 1u32.into(), 0u32.into())).unwrap();
    remote.recv_frame(NewConnectionIdFrame::new(cid(2), 2u32.into(), 0u32.into())).unwrap();
    assert_eq!(borrow(&later), Poll::Ready(Some(cid(1))));
    assert_eq!(borrow(&other), Poll::Ready(Some(cid(2))));
    selected.refresh();
    later.refresh();
    other.refresh();
}

#[test]
fn server_peer_scid_is_fixed_and_path_can_upgrade_without_an_external_manager() {
    let remote = remote(Retired::default());
    assert!(!remote.on_receive_from(cid(9)));
    let dcid = remote.apply_dcid();
    drop(remote);
    dcid.upgrade();
    assert_eq!(borrow(&dcid), Poll::Ready(Some(cid(0))));
    dcid.refresh();
}

#[test]
fn allocated_cid_retirement_waits_for_refresh_and_does_not_rotate_on_every_batch() {
    let retired = Retired::default();
    let remote = remote(retired.clone());
    let dcid = remote.apply_dcid();
    dcid.upgrade();
    assert_eq!(borrow(&dcid), Poll::Ready(Some(cid(0))));
    dcid.refresh();
    assert_eq!(borrow(&dcid), Poll::Ready(Some(cid(0))));
    remote.recv_frame(NewConnectionIdFrame::new(cid(1), 1u32.into(), 1u32.into())).unwrap();
    assert!(retired.0.lock().unwrap().is_empty());
    dcid.refresh();
    assert_eq!(retired.0.lock().unwrap()[0].sequence(), 0);
    assert_eq!(borrow(&dcid), Poll::Ready(Some(cid(1))));
    dcid.refresh();
    remote.on_receive_from(cid(0));
    assert_eq!(borrow(&dcid), Poll::Ready(Some(cid(1))));
    dcid.refresh();
}

#[derive(Default)]
struct Counter(AtomicUsize);

impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn closing_a_pending_path_wakes_it_without_closing_another_path() {
    let remote = remote(Retired::default());
    let first = remote.apply_dcid();
    first.upgrade();
    let other = remote.apply_dcid();
    other.upgrade();
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(other.poll_borrow(&mut cx).is_pending());
    other.retire();
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    assert_eq!(other.poll_borrow(&mut cx), Poll::Ready(None));
    remote.recv_frame(NewConnectionIdFrame::new(cid(1), 1u32.into(), 0u32.into())).unwrap();
    assert_eq!(borrow(&other), Poll::Ready(None));
    assert_eq!(borrow(&first), Poll::Ready(Some(cid(0))));
    first.refresh();
}

#[test]
fn refreshing_a_handshake_snapshot_after_binding_does_not_retire_the_new_cell() {
    let retired = Retired::default();
    let remote = remote(retired.clone());
    let dcid = remote.apply_dcid();
    assert_eq!(dcid.poll_borrow(&mut Context::from_waker(Waker::noop())), Poll::Ready(Some(cid(0))));
    dcid.upgrade();
    dcid.refresh();
    dcid.refresh();
    assert!(retired.0.lock().unwrap().is_empty());
    assert_eq!(dcid.poll_borrow(&mut Context::from_waker(Waker::noop())), Poll::Ready(Some(cid(0))));
    dcid.refresh();
}

#[test]
fn the_last_dcid_handle_retires_its_cell_after_the_batch_was_returned() {
    let retired = Retired::default();
    let remote = remote(retired.clone());
    let dcid = remote.apply_dcid();
    dcid.upgrade();
    let cloned = dcid.clone();
    assert_eq!(borrow(&dcid), Poll::Ready(Some(cid(0))));
    dcid.refresh();
    drop(dcid);
    assert!(retired.0.lock().unwrap().is_empty());
    drop(cloned);
    assert_eq!(retired.0.lock().unwrap()[0].sequence(), 0);
}

#[test]
fn upgrading_with_an_outstanding_handshake_batch_defers_retirement_until_refresh() {
    let retired = Retired::default();
    let remote = remote(retired.clone());
    let dcid = remote.apply_dcid();
    let snapshot = borrow(&dcid);
    dcid.upgrade();
    remote.recv_frame(NewConnectionIdFrame::new(cid(1), 1u32.into(), 1u32.into())).unwrap();
    assert_eq!(snapshot, Poll::Ready(Some(cid(0))));
    assert!(retired.0.lock().unwrap().is_empty());
    dcid.refresh();
    assert_eq!(retired.0.lock().unwrap()[0].sequence(), 0);
    assert_eq!(borrow(&dcid), Poll::Ready(Some(cid(1))));
    dcid.refresh();
}

#[test]
fn dropping_an_upgraded_path_without_another_batch_retires_its_cid() {
    let retired = Retired::default();
    let remote = remote(retired.clone());
    let dcid = remote.apply_dcid();
    dcid.upgrade();
    drop(dcid);
    assert_eq!(retired.0.lock().unwrap()[0].sequence(), 0);
}

#[test]
fn an_applied_handshake_handle_keeps_the_peer_identity_when_path_cids_rotate() {
    let retired = Retired::default();
    let remote = ArcRemoteCids::client(cid(9), retired.clone());
    remote.set_limit(4);
    let identity = remote.apply_dcid();
    let selected = remote.apply_dcid();
    assert_eq!(borrow(&identity), Poll::Ready(Some(cid(9))));
    remote.on_receive_from(cid(0));
    selected.upgrade();
    assert_eq!(borrow(&selected), Poll::Ready(Some(cid(0))));
    remote.recv_frame(NewConnectionIdFrame::new(cid(1), 1u32.into(), 1u32.into())).unwrap();
    selected.refresh();
    remote.upgrade();
    assert_eq!(borrow(&identity), Poll::Ready(Some(cid(0))));
    assert_eq!(borrow(&selected), Poll::Ready(Some(cid(1))));
    identity.refresh();
    selected.refresh();
    assert_eq!(retired.0.lock().unwrap().len(), 1);
    assert_eq!(retired.0.lock().unwrap()[0].sequence(), 0);
    assert!(borrow(&remote.apply_dcid()).is_pending());
}
