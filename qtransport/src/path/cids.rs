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
