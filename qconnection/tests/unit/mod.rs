mod discovery;
mod lifecycle;
mod paths;
mod punch;
mod recv;
mod send;
mod tls;

use crate::Paths;

impl Paths {
    fn retire_all(&self) {
        self.terminator.terminate();
        for path in self.snapshot() {
            self.remove(&path);
        }
    }
}

pub use crate::common::phase::{MatureFixture, SpaceFixture};
use crate::common::take_heartbeat;

pub fn enter_mature(paths: &Paths, mature: &MatureFixture) {
    if matches!(paths.phase().get(), crate::ConnPhase::Initial(_)) {
        enter_handshake(paths, mature.spaces.handshake.clone());
    }
    paths
        .resender
        .write()
        .unwrap()
        .push_back(mature.spaces.data.clone())
        .unwrap();
    paths
        .spaces
        .write()
        .unwrap()
        .0
        .push_back(mature.spaces.data.clone())
        .unwrap();
    paths.cids.attach_remote(mature.cid_registry.remote.clone());
    paths.phase().enter_mature(mature.phase.clone());
}

/// Install resources before switching phase, as growing does.
pub fn enter_handshake(
    paths: &Paths,
    handshake: std::sync::Arc<qtransport::space::HandshakeSpace>,
) {
    paths
        .resender
        .write()
        .unwrap()
        .push_back(handshake.clone())
        .unwrap();
    paths
        .spaces
        .write()
        .unwrap()
        .0
        .push_back(handshake)
        .unwrap();
    paths.handshake.got_handshake_key();
    paths.phase().enter_handshake();
}

/// Emulate lifecycle retirement in tests that do not run growing.
pub fn retire_spaces(paths: &Paths, end: qbase::Epoch) {
    let mut spaces = paths.spaces.write().unwrap();
    let mut resender = paths.resender.write().unwrap();
    while spaces
        .0
        .front()
        .is_some_and(|(epoch, _)| epoch < end as u64)
    {
        let (_, space) = spaces.0.pop_front().unwrap();
        space.retire();
        resender.pop_front();
    }
}

pub fn confirm_handshake(paths: &std::sync::Arc<Paths>) {
    retire_spaces(paths, qbase::Epoch::Data);
    paths.handshake_confirmed();
}

/// Observe the same four scenarios across existing sending and receiving tests.
fn selection(paths: &Paths, path: &qtransport::path::Path) -> u8 {
    if paths.cids.is_confirmed() {
        2
    } else if paths.cids.is_initial() {
        u8::MAX
    } else {
        u8::from(paths.cids.is_selected(&path.cid))
    }
}

fn borrow(
    path: &qtransport::path::Path,
) -> std::task::Poll<Option<qbase::cid::BorrowedCid<crate::ArcReliableFrames>>> {
    path.cid
        .borrow_cid(&mut std::task::Context::from_waker(std::task::Waker::noop()))
}
