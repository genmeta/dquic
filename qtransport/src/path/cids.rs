//! Connection-wide sending CID policy. Growing supplies lifecycle events;
//! paths borrow a CID for each batch according to the current handshake state.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard, Weak},
    task::{Context, Poll},
};

use qbase::{
    cid::{ArcCidCell, ArcRemoteCids, BorrowedCid, ConnectionId},
    net::{route::Pathway, tx::ArcSendWakers},
};

use crate::ArcReliableFrames;

pub struct PathCids {
    state: Mutex<State>,
}

struct State {
    phase: Phase,
    initial_dcid: ConnectionId,
    remote: Option<ArcRemoteCids<ArcReliableFrames>>,
    entries: BTreeMap<Pathway, Entry>,
}

struct Entry {
    path: Weak<PathCid>,
    cell: Option<ArcCidCell<ArcReliableFrames>>,
    send_waker: ArcSendWakers,
}

enum Phase {
    Initial,
    Selected(Weak<PathCid>),
    Confirmed,
}

/// A handle to this exact path registration, not a future path at the same address.
pub struct PathCid {
    owner: Arc<PathCids>,
    pathway: Pathway,
}

impl State {
    fn is_registered(&self, path: &PathCid) -> bool {
        // This also runs from Drop, when the weak reference can no longer upgrade.
        self.entries
            .get(&path.pathway)
            .is_some_and(|entry| std::ptr::eq(entry.path.as_ptr(), path))
    }

    fn selected(&self, path: &PathCid) -> bool {
        matches!(&self.phase, Phase::Selected(selected) if std::ptr::eq(selected.as_ptr(), path))
    }

    fn ensure_selected_cell(&mut self) {
        let (Phase::Selected(selected), Some(remote)) = (&self.phase, &self.remote) else {
            return;
        };
        // Drop may already be waiting for the state lock to unregister this path.
        if selected.strong_count() == 0 {
            return;
        }
        if let Some(entry) = self
            .entries
            .values_mut()
            .find(|entry| Weak::ptr_eq(&entry.path, selected))
        {
            entry.cell.get_or_insert_with(|| remote.apply_dcid());
        }
    }
}

fn wake_senders(state: MutexGuard<'_, State>) {
    let wakers: Vec<_> = state
        .entries
        .values()
        .map(|entry| entry.send_waker.clone())
        .collect();
    // Invoke sender wakers only after releasing the connection state lock.
    drop(state);
    for waker in wakers {
        waker.wake_all();
    }
}

impl PathCids {
    pub fn new(initial_dcid: ConnectionId) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                phase: Phase::Initial,
                initial_dcid,
                remote: None,
                entries: BTreeMap::new(),
            }),
        })
    }

    pub(super) fn register(
        self: &Arc<Self>,
        pathway: Pathway,
        send_waker: ArcSendWakers,
    ) -> Arc<PathCid> {
        // Declare the handle before the guard so unwinding releases the lock first.
        let path;
        let mut state = self.state.lock().unwrap();
        assert!(
            !state.entries.contains_key(&pathway),
            "path already registered"
        );
        path = Arc::new(PathCid {
            owner: self.clone(),
            pathway,
        });
        state.entries.insert(
            pathway,
            Entry {
                path: Arc::downgrade(&path),
                cell: None,
                send_waker,
            },
        );
        path
    }

    /// Shared handshake CID; a registry-backed path may already use a newer CID.
    pub fn initial_dcid(&self) -> ConnectionId {
        self.state.lock().unwrap().initial_dcid
    }

    pub fn update_initial_dcid(&self, cid: ConnectionId) {
        let mut state = self.state.lock().unwrap();
        if state.initial_dcid == cid {
            return;
        }
        state.initial_dcid = cid;
        wake_senders(state);
    }

    pub fn select(&self, path: &Arc<PathCid>) -> bool {
        let mut state = self.state.lock().unwrap();
        if !state.is_registered(path) || !matches!(state.phase, Phase::Initial) {
            return false;
        }
        state.phase = Phase::Selected(Arc::downgrade(path));
        state.ensure_selected_cell();
        wake_senders(state);
        true
    }

    /// Growing installs the registry. Selection may precede or follow this
    /// event, but only the selected path receives the first cell.
    pub fn attach_remote(&self, remote: ArcRemoteCids<ArcReliableFrames>) {
        let mut state = self.state.lock().unwrap();
        assert!(
            state.remote.is_none(),
            "remote CID registry already attached"
        );
        state.remote = Some(remote);
        state.ensure_selected_cell();
        wake_senders(state);
    }

    /// Open independent allocations after growing has prepared path validation.
    pub fn confirm_handshake(&self) {
        let mut state = self.state.lock().unwrap();
        if matches!(state.phase, Phase::Confirmed) {
            return;
        }
        assert!(
            matches!(state.phase, Phase::Selected(_)),
            "handshake confirmation requires a selected path"
        );
        assert!(
            state.remote.is_some(),
            "handshake confirmation requires remote CIDs"
        );
        state.phase = Phase::Confirmed;
        wake_senders(state);
    }

    /// No handshake path has been selected yet, independently of ConnPhase.
    pub fn is_initial(&self) -> bool {
        matches!(self.state.lock().unwrap().phase, Phase::Initial)
    }

    pub fn is_confirmed(&self) -> bool {
        matches!(self.state.lock().unwrap().phase, Phase::Confirmed)
    }

    /// Whether this live path is selected during the handshake.
    pub fn is_selected(&self, path: &PathCid) -> bool {
        let state = self.state.lock().unwrap();
        state.is_registered(path) && state.selected(path)
    }
}

impl PathCid {
    /// One outstanding borrow per path sender. Pending registers a wakeup for
    /// selection, handshake confirmation, or a newly available registry CID.
    pub fn borrow_cid(&self, cx: &mut Context<'_>) -> Poll<Option<BorrowedCid<ArcReliableFrames>>> {
        let mut state = self.owner.state.lock().unwrap();
        if !state.is_registered(self) {
            return Poll::Ready(None);
        }
        let suspended = matches!(state.phase, Phase::Selected(_)) && !state.selected(self);
        let State {
            phase,
            initial_dcid,
            remote,
            entries,
        } = &mut *state;
        let entry = entries.get_mut(&self.pathway).expect("registered path");
        entry.send_waker.register(cx.waker());
        if suspended {
            return Poll::Pending;
        }
        if matches!(phase, Phase::Confirmed) {
            entry
                .cell
                .get_or_insert_with(|| remote.as_ref().expect("confirmed registry").apply_dcid());
        }
        match &entry.cell {
            Some(cell) => cell.borrow_cid(entry.send_waker.clone()),
            None => Poll::Ready(Some(BorrowedCid::shared(*initial_dcid))),
        }
    }

    pub(super) fn retire(&self) {
        let mut state = self.owner.state.lock().unwrap();
        if !state.is_registered(self) {
            return;
        }
        let entry = state
            .entries
            .remove(&self.pathway)
            .expect("registered path");
        drop(state);
        if let Some(cell) = entry.cell {
            cell.retire();
        }
        entry.send_waker.wake_all();
    }
}

impl Drop for PathCid {
    fn drop(&mut self) {
        self.retire();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Wake, Waker},
    };

    use qbase::{
        frame::{NewConnectionIdFrame, io::ReceiveFrame},
        net::addr::EndpointAddr,
    };

    use super::*;

    fn pathway(port: u16) -> Pathway {
        Pathway::new(
            EndpointAddr::direct(([127, 0, 0, 1], 4000).into()),
            EndpointAddr::direct(([127, 0, 0, 1], port).into()),
        )
    }

    fn register(cids: &Arc<PathCids>, port: u16) -> Arc<PathCid> {
        cids.register(pathway(port), ArcSendWakers::default())
    }

    fn remote(cid: ConnectionId) -> ArcRemoteCids<ArcReliableFrames> {
        ArcRemoteCids::new(cid, 8, ArcReliableFrames::with_capacity(0))
    }

    fn borrow(path: &PathCid) -> Poll<Option<BorrowedCid<ArcReliableFrames>>> {
        path.borrow_cid(&mut Context::from_waker(Waker::noop()))
    }

    fn ready(path: &PathCid) -> BorrowedCid<ArcReliableFrames> {
        let Poll::Ready(Some(cid)) = borrow(path) else {
            panic!("expected a ready CID")
        };
        cid
    }

    #[test]
    fn racing_paths_share_cids_and_updates_apply_to_new_borrows() {
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

    #[test]
    fn selection_suspends_new_borrows_without_changing_existing_borrows() {
        let cids = PathCids::new(ConnectionId::from_slice(b"original"));
        let a = register(&cids, 4001);
        let b = register(&cids, 4002);
        let old = ready(&a);
        assert!(cids.select(&b));
        assert!(!cids.select(&a));
        assert!(borrow(&a).is_pending());
        assert_eq!(*old, cids.initial_dcid());
        assert_eq!(*ready(&b), *old);
    }

    #[test]
    fn selected_binding_precedes_lazy_independent_allocations_in_either_event_order() {
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
            cids.select(&selected);
            if !attach_first {
                cids.attach_remote(remote.clone());
            }
            assert_eq!(*snapshot, initial);
            cids.update_initial_dcid(initial);
            assert_eq!(*ready(&selected), initial);
            assert!(borrow(&other).is_pending());
            assert!(
                cids.state.lock().unwrap().entries[&other.pathway]
                    .cell
                    .is_none()
            );
            cids.confirm_handshake();
            assert!(!cids.is_selected(&selected));
            cids.confirm_handshake();
            assert!(borrow(&other).is_pending());
            assert!(
                cids.state.lock().unwrap().entries[&other.pathway]
                    .cell
                    .is_some()
            );
            remote
                .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
                .unwrap();
            assert_eq!(*ready(&other), next);
            assert_eq!(*ready(&selected), initial);
        }
    }

    #[test]
    fn replacement_at_selected_address_does_not_inherit_selection_or_old_handle() {
        let cids = PathCids::new(ConnectionId::from_slice(b"original"));
        let old = register(&cids, 4001);
        cids.select(&old);
        let snapshot = ready(&old);
        old.retire();
        let replacement = register(&cids, 4001);
        assert!(!cids.is_selected(&replacement));
        assert!(!cids.select(&replacement));
        assert!(borrow(&replacement).is_pending());
        assert!(matches!(borrow(&old), Poll::Ready(None)));
        assert_eq!(*snapshot, cids.initial_dcid());
        old.retire();
        drop(old);
        assert!(cids.state.lock().unwrap().is_registered(&replacement));
        assert!(!cids.is_initial());
    }

    #[test]
    fn confirmation_survives_removal_of_every_path() {
        let initial = ConnectionId::from_slice(b"peer0000");
        let cids = PathCids::new(initial);
        let remote = remote(initial);
        let selected = register(&cids, 4001);
        cids.select(&selected);
        cids.attach_remote(remote.clone());
        cids.confirm_handshake();
        selected.retire();
        assert!(cids.state.lock().unwrap().entries.is_empty());
        let next = ConnectionId::from_slice(b"peer0001");
        remote
            .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
            .unwrap();
        let replacement = register(&cids, 4001);
        assert!(cids.is_confirmed());
        assert!(!cids.is_selected(&replacement));
        assert_eq!(*ready(&replacement), next);
    }

    #[test]
    fn dropping_last_handle_unregisters_path_without_an_ownership_cycle() {
        for confirmed in [false, true] {
            let initial = ConnectionId::from_slice(b"peer0000");
            let cids = PathCids::new(initial);
            let weak_owner = Arc::downgrade(&cids);
            let path = register(&cids, 4001);
            let weak_path = Arc::downgrade(&path);
            cids.select(&path);
            cids.attach_remote(remote(initial));
            if confirmed {
                cids.confirm_handshake();
            }
            let borrowed = ready(&path);
            let cloned = path.clone();
            drop(path);
            assert!(cids.state.lock().unwrap().is_registered(&cloned));
            drop(cloned);
            assert!(weak_path.upgrade().is_none());
            assert!(cids.state.lock().unwrap().entries.is_empty());
            drop(cids);
            assert!(weak_owner.upgrade().is_none());
            // A CID borrow pins only the registry cell, not the path or connection.
            assert_eq!(*borrowed, initial);
            drop(borrowed);
        }
    }

    #[test]
    fn primary_cid_rotates_before_confirmation_and_borrow_outlives_retirement() {
        let initial = ConnectionId::from_slice(b"peer0000");
        let next = ConnectionId::from_slice(b"peer0001");
        let cids = PathCids::new(initial);
        let selected = register(&cids, 4001);
        cids.select(&selected);
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

    #[test]
    fn confirmation_new_cid_and_retirement_wake_waiting_sender() {
        let initial = ConnectionId::from_slice(b"peer0000");
        let cids = PathCids::new(initial);
        let selected = register(&cids, 4001);
        let other = register(&cids, 4002);
        cids.select(&selected);
        let remote = remote(initial);
        cids.attach_remote(remote.clone());
        let counter = Arc::new(Counter::default());
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(other.borrow_cid(&mut cx).is_pending());
        cids.confirm_handshake();
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
        cids.confirm_handshake();
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
        assert!(other.borrow_cid(&mut cx).is_pending());
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
        assert!(matches!(other.borrow_cid(&mut cx), Poll::Ready(None)));
    }
}
