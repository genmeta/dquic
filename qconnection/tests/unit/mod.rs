mod discovery;
mod lifecycle;
mod paths;
mod punch;
mod recv;
mod send;
mod tls;

use crate::Paths;

fn take_validation_frames(path: &qtransport::path::Path) -> Vec<qbase::frame::Frame<bytes::Bytes>> {
    use std::task::{Context, Waker};

    use bytes::BytesMut;
    use qbase::{
        frame::FrameReader,
        packet::{Constraints, GetType, OneRttHeader, Package, PacketBuffer},
    };

    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let mut limits = Constraints {
        send_quota: 256,
        credit: 256,
        max_size: 256,
        ..Default::default()
    };
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let result = path.validation.clone().poll_dump(
        &mut Context::from_waker(Waker::noop()),
        &mut PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0),
    );
    assert!(!matches!(result, std::task::Poll::Ready(Err(_))));
    FrameReader::new(bytes.freeze(), ty)
        .map(|frame| frame.unwrap().0)
        .collect()
}

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
        .loss_resender
        .write_guard()
        .push_back(mature.spaces.data.clone())
        .unwrap();
    paths
        .spaces
        .write_guard()
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
        .loss_resender
        .write_guard()
        .push_back(handshake.clone())
        .unwrap();
    paths.spaces.write_guard().push_back(handshake).unwrap();
    paths.handshake.got_handshake_key();
    paths.phase().enter_handshake();
}

/// Emulate lifecycle retirement in tests that do not run growing.
pub fn retire_spaces(paths: &Paths, end: qbase::Epoch) {
    let mut spaces = paths.spaces.write_guard();
    let mut resender = paths.loss_resender.write_guard();
    while spaces.front().is_some_and(|(epoch, _)| epoch < end as u64) {
        let (_, space) = spaces.pop_front().unwrap();
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
