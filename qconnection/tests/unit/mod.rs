mod cids;
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
        self.clean();
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
    paths.enter_mature(mature.phase.clone());
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
    paths.progress.facts().install_handshake_key();
    // The isolated TLS fixture uses its current CID as the simulated peer SCID.
    paths.update_initial_dcid(crate::common::cid_value(&paths.new_dcid()));
    paths.phase().enter_handshake();
}

pub fn confirm_handshake(paths: &std::sync::Arc<Paths>) {
    paths.progress.on_handshake_done(paths);
}

/// Observe the same four scenarios across existing sending and receiving tests.
fn selection(paths: &Paths, path: &qtransport::path::Path) -> u8 {
    if paths.is_confirmed() {
        2
    } else if paths.is_initial() {
        u8::MAX
    } else {
        u8::from(paths.is_selected(path))
    }
}

fn borrow(
    paths: &Paths,
    path: &qtransport::path::Path,
) -> std::task::Poll<Option<qbase::cid::ConnectionId>> {
    use std::task::{Context, Poll, Waker};
    if path.validation.is_cancelled() {
        return Poll::Ready(None);
    }
    if !paths.can_send(path) {
        return Poll::Pending;
    }
    let result = path
        .dcid
        .poll_borrow(&mut Context::from_waker(Waker::noop()));
    if matches!(result, Poll::Ready(Some(_))) {
        path.dcid.refresh();
    }
    result
}
