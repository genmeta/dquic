use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use qbase::{
    cid::*,
    frame::{
        NewConnectionIdFrame, RetireConnectionIdFrame,
        io::{ReceiveFrame, SendFrame},
    },
    role::Role,
    token::ResetToken,
    varint::VarInt,
};

#[derive(Clone, Default)]
struct IssuedCids {
    frames: Arc<Mutex<Vec<NewConnectionIdFrame>>>,
    active_cids: Arc<Mutex<HashMap<ConnectionId, ResetToken>>>,
}

impl IssuedCids {
    fn frames(&self) -> MutexGuard<'_, Vec<NewConnectionIdFrame>> {
        self.frames.lock().unwrap()
    }

    fn active_cids(&self) -> MutexGuard<'_, HashMap<ConnectionId, ResetToken>> {
        self.active_cids.lock().unwrap()
    }
}

impl GenUniqueCid for IssuedCids {
    fn gen_unique_cid(&self) -> ConnectionId {
        let mut local_cids = self.active_cids.lock().unwrap();
        let unique_cid =
            core::iter::from_fn(|| Some(ConnectionId::random_gen_with_mark(8, 0x80, 0x7F)))
                .find(|cid| !local_cids.contains_key(cid))
                .unwrap();

        local_cids.insert(unique_cid, ResetToken::default());
        unique_cid
    }
}

impl RetireCid for IssuedCids {
    fn retire_cid(&self, cid: ConnectionId) {
        self.active_cids.lock().unwrap().remove(&cid);
    }
}

impl SendFrame<NewConnectionIdFrame> for IssuedCids {
    fn send_frame<I: IntoIterator<Item = NewConnectionIdFrame>>(&self, iter: I) {
        self.frames.lock().unwrap().extend(iter);
    }
}

#[test]
fn test_issue_cid() {
    let issued = IssuedCids::default();
    let initial_scid = issued.gen_unique_cid();
    let local = ArcLocalCids::new(
        Role::Client,
        ConnectionId::random_gen(8),
        initial_scid,
        issued.clone(),
    );
    assert_eq!(local.initial_scid(), Some(initial_scid));
    assert_eq!(issued.active_cids().len(), 2);
    assert_eq!(issued.frames().len(), 1);
    assert_eq!(issued.frames()[0].sequence(), 1);
    local.set_limit(3).unwrap();
    assert_eq!(issued.active_cids().len(), 3);
    assert_eq!(issued.frames().len(), 2);
    assert_eq!(issued.frames()[1].sequence(), 2);
}

#[test]
fn test_recv_retire_cid_frame() {
    let issued = IssuedCids::default();
    let initial_scid = issued.gen_unique_cid();
    let local = ArcLocalCids::new(
        Role::Client,
        ConnectionId::random_gen(8),
        initial_scid,
        issued.clone(),
    );
    assert_eq!(issued.active_cids().len(), 2);
    assert_eq!(issued.frames().len(), 1);
    let issued_cid2 = *issued.frames()[0].connection_id();

    local
        .recv_frame(RetireConnectionIdFrame::new(VarInt::from_u32(1)))
        .unwrap();
    assert!(!issued.active_cids().contains_key(&issued_cid2));
    assert_eq!(issued.active_cids().len(), 2);
    assert_eq!(issued.frames().len(), 2);
    assert_eq!(issued.frames()[1].sequence(), 2);
    assert_eq!(issued.frames()[1].retire_prior_to(), 0);
    assert_eq!(local.initial_scid(), Some(initial_scid));
    // Retiring the same CID again must not issue another replacement.
    local
        .recv_frame(RetireConnectionIdFrame::new(VarInt::from_u32(1)))
        .unwrap();
    assert_eq!(issued.frames().len(), 2);

    local
        .recv_frame(RetireConnectionIdFrame::new(VarInt::from_u32(0)))
        .unwrap();
    assert!(!issued.active_cids().contains_key(&initial_scid));
    assert_eq!(local.initial_scid(), None);
    assert_eq!(issued.active_cids().len(), 2);
    assert_eq!(issued.frames().len(), 3);
    assert_eq!(issued.frames()[2].sequence(), 3);
    assert_eq!(issued.frames()[2].retire_prior_to(), 2);
    // Sequence zero has slid out of the active range.
    local
        .recv_frame(RetireConnectionIdFrame::new(VarInt::from_u32(0)))
        .unwrap();
    assert_eq!(issued.frames().len(), 3);

    let issued_cid3 = *issued.frames()[1].connection_id();
    local
        .recv_frame(RetireConnectionIdFrame::new(VarInt::from_u32(2)))
        .unwrap();
    assert!(!issued.active_cids().contains_key(&issued_cid3));
    assert_eq!(issued.active_cids().len(), 2);
    assert_eq!(issued.frames().len(), 4);
}
