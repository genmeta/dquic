use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use qbase::{
    cid::{ArcRemoteCids, BorrowedCid, ConnectionId},
    frame::{NewConnectionIdFrame, io::ReceiveFrame},
    net::{addr::EndpointAddr, route::Pathway},
    time::heartbeat::ArcHeartbeat,
};
use qcongestion::HandshakeStatus;
use qtransport::{
    ArcReliableFrames,
    path::{Path, PathCids},
};

fn pathway(port: u16) -> Pathway {
    Pathway::new(
        EndpointAddr::direct(([127, 0, 0, 1], 4000).into()),
        EndpointAddr::direct(([127, 0, 0, 1], port).into()),
    )
}

fn register(cids: &Arc<PathCids>, port: u16) -> Path {
    Path::new(
        pathway(port),
        Arc::new(HandshakeStatus::new(true)),
        ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
        Default::default(),
        cids,
    )
}

fn remote(cid: ConnectionId) -> ArcRemoteCids<ArcReliableFrames> {
    ArcRemoteCids::new(cid, 8, ArcReliableFrames::with_capacity(0))
}

fn borrow(path: &Path) -> Poll<Option<BorrowedCid<ArcReliableFrames>>> {
    path.cid.borrow_cid(&mut Context::from_waker(Waker::noop()))
}

fn ready(path: &Path) -> BorrowedCid<ArcReliableFrames> {
    let Poll::Ready(Some(cid)) = borrow(path) else {
        panic!("expected a ready CID")
    };
    cid
}

#[tokio::test(start_paused = true)]
async fn racing_paths_share_cids_and_updates_apply_to_new_borrows() {
    let original = ConnectionId::from_slice(b"original");
    let peer = ConnectionId::from_slice(b"peer0000");
    let cids = PathCids::new(original);
    let a = register(&cids, 4001);
    let b = register(&cids, 4002);
    let a_cid = ready(&a);
    let b_cid = ready(&b);
    assert_eq!(*a_cid, *b_cid);
    cids.update_initial_dcid(peer);
    assert_eq!(*a_cid, original);
    assert_eq!(*b_cid, original);
    assert_eq!(*ready(&a), peer);
    assert_eq!(*ready(&b), peer);
}

#[tokio::test(start_paused = true)]
async fn selection_suspends_new_borrows_without_changing_existing_borrows() {
    let cids = PathCids::new(ConnectionId::from_slice(b"original"));
    let a = register(&cids, 4001);
    let b = register(&cids, 4002);
    let old = ready(&a);
    assert!(cids.select(&b.cid));
    assert!(!cids.select(&a.cid));
    assert!(borrow(&a).is_pending());
    assert_eq!(*old, cids.initial_dcid());
    assert_eq!(*ready(&b), *old);
}

#[tokio::test(start_paused = true)]
async fn selected_binding_precedes_lazy_independent_allocations_in_either_event_order() {
    for attach_first in [false, true] {
        let initial = ConnectionId::from_slice(b"peer0000");
        let next = ConnectionId::from_slice(b"peer0001");
        let remote = remote(initial);
        let cids = PathCids::new(initial);
        let other = register(&cids, 4001);
        let selected = register(&cids, 4002);
        let snapshot = ready(&selected);
        if attach_first {
            cids.attach_remote(remote.clone());
        }
        cids.select(&selected.cid);
        if !attach_first {
            cids.attach_remote(remote.clone());
        }
        assert_eq!(*snapshot, initial);
        cids.update_initial_dcid(initial);
        assert_eq!(*ready(&selected), initial);
        assert!(borrow(&other).is_pending());
        cids.confirm_handshake();
        assert!(!cids.is_selected(&selected.cid));
        cids.confirm_handshake();
        // The suspended borrow must not reserve an independent CID before confirmation.
        let later = register(&cids, 4003);
        remote
            .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
            .unwrap();
        assert_eq!(*ready(&later), next);
        assert!(borrow(&other).is_pending());
        let last = ConnectionId::from_slice(b"peer0002");
        remote
            .recv_frame(NewConnectionIdFrame::new(last, 2u32.into(), 0u32.into()))
            .unwrap();
        assert_eq!(*ready(&other), last);
        assert_eq!(*ready(&selected), initial);
    }
}

#[tokio::test(start_paused = true)]
async fn replacement_at_selected_address_does_not_inherit_selection_or_old_handle() {
    let cids = PathCids::new(ConnectionId::from_slice(b"original"));
    let old = register(&cids, 4001);
    cids.select(&old.cid);
    let snapshot = ready(&old);
    old.retire();
    let replacement = register(&cids, 4001);
    assert!(!cids.is_selected(&replacement.cid));
    assert!(!cids.select(&replacement.cid));
    assert!(borrow(&replacement).is_pending());
    assert!(matches!(borrow(&old), Poll::Ready(None)));
    assert_eq!(*snapshot, cids.initial_dcid());
    old.retire();
    drop(old);
    assert!(borrow(&replacement).is_pending());
    assert!(!cids.is_initial());
}

#[tokio::test(start_paused = true)]
async fn confirmation_survives_removal_of_every_path() {
    let initial = ConnectionId::from_slice(b"peer0000");
    let cids = PathCids::new(initial);
    let remote = remote(initial);
    let selected = register(&cids, 4001);
    cids.select(&selected.cid);
    cids.attach_remote(remote.clone());
    cids.confirm_handshake();
    selected.retire();
    let next = ConnectionId::from_slice(b"peer0001");
    remote
        .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
        .unwrap();
    let replacement = register(&cids, 4001);
    assert!(cids.is_confirmed());
    assert!(!cids.is_selected(&replacement.cid));
    assert_eq!(*ready(&replacement), next);
}

#[tokio::test(start_paused = true)]
async fn dropping_last_handle_unregisters_path_without_an_ownership_cycle() {
    for confirmed in [false, true] {
        let initial = ConnectionId::from_slice(b"peer0000");
        let cids = PathCids::new(initial);
        let weak_owner = Arc::downgrade(&cids);
        let path = register(&cids, 4001);
        let weak_path = Arc::downgrade(&path.cid);
        cids.select(&path.cid);
        cids.attach_remote(remote(initial));
        if confirmed {
            cids.confirm_handshake();
        }
        let borrowed = ready(&path);
        let cloned = path.cid.clone();
        drop(path);
        assert!(weak_path.upgrade().is_some());
        if !confirmed {
            assert!(cids.is_selected(&cloned));
        }
        drop(cloned);
        assert!(weak_path.upgrade().is_none());
        // Reusing the address proves the final CID handle withdrew its registration.
        drop(register(&cids, 4001));
        drop(cids);
        assert!(weak_owner.upgrade().is_none());
        // A CID borrow pins only the registry cell, not the path or connection.
        assert_eq!(*borrowed, initial);
        drop(borrowed);
    }
}

#[tokio::test(start_paused = true)]
async fn primary_cid_rotates_before_confirmation_and_borrow_outlives_retirement() {
    let initial = ConnectionId::from_slice(b"peer0000");
    let next = ConnectionId::from_slice(b"peer0001");
    let cids = PathCids::new(initial);
    let selected = register(&cids, 4001);
    cids.select(&selected.cid);
    let remote = remote(initial);
    cids.attach_remote(remote.clone());
    let pinned = ready(&selected);
    remote
        .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 1u32.into()))
        .unwrap();
    assert_eq!(*pinned, initial);
    drop(pinned);
    let current = ready(&selected);
    assert_eq!(*current, next);
    selected.retire();
    assert!(matches!(borrow(&selected), Poll::Ready(None)));
    assert_eq!(*current, next);
    drop(current);
}

#[derive(Default)]
struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test(start_paused = true)]
async fn confirmation_new_cid_and_retirement_wake_waiting_sender() {
    let initial = ConnectionId::from_slice(b"peer0000");
    let cids = PathCids::new(initial);
    let selected = register(&cids, 4001);
    let other = register(&cids, 4002);
    cids.select(&selected.cid);
    let remote = remote(initial);
    cids.attach_remote(remote.clone());
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(other.cid.borrow_cid(&mut cx).is_pending());
    cids.confirm_handshake();
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    cids.confirm_handshake();
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    assert!(other.cid.borrow_cid(&mut cx).is_pending());
    remote
        .recv_frame(NewConnectionIdFrame::new(
            ConnectionId::from_slice(b"peer0001"),
            1u32.into(),
            0u32.into(),
        ))
        .unwrap();
    assert_eq!(counter.0.load(Ordering::Relaxed), 2);
    drop(ready(&other));
    other.retire();
    assert!(counter.0.load(Ordering::Relaxed) >= 3);
    assert!(matches!(other.cid.borrow_cid(&mut cx), Poll::Ready(None)));
}
