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
        packet::{GetType, OneRttHeader, Package, PacketBuffer},
    };

    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let limits_quota = 256;
    let limits_length = 256;
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let mut writer_0 = bytes::BufMut::limit(&mut bytes, limits_length);
    let result = path
        .validation
        .clone()
        .poll_dump(&mut Context::from_waker(Waker::noop()), &mut PacketBuffer::new(&mut writer_0, limits_quota, &mut frames, ty, 0, 0));
    assert!(!matches!(result, std::task::Poll::Ready(Err(_))));
    FrameReader::new(bytes.freeze(), ty).map(|frame| frame.unwrap().0).collect()
}

impl Paths {
    fn retire_all(&self) {
        self.terminator.terminate();
        self.clean();
    }
}

pub use crate::common::spaces::{DataFixture, SpaceFixture};
use crate::common::take_heartbeat;

pub fn install_data(paths: &Paths, data: &DataFixture) {
    if paths.spaces.read_guard().get(qbase::Epoch::Data as u64).is_some() {
        return;
    }
    if !paths.progress.facts().has_handshake_key() {
        install_handshake(paths, data.spaces.handshake.clone());
    }
    paths.progress.install_data(data.spaces.data.clone());
}

/// Install synthetic spaces without retiring the fixture's Initial CRYPTO source.
pub fn install_handshake(paths: &Paths, handshake: std::sync::Arc<qtransport::space::HandshakeSpace>) {
    paths.loss_resender.write_guard().push_back(handshake.clone()).unwrap();
    paths.spaces.write_guard().push_back(handshake).unwrap();
    paths.progress.facts().install_handshake_key();
    paths.progress.on_initial_received(crate::common::cid_value(&paths.cid_registry.remote.apply_dcid()));
}

pub fn confirm_handshake(paths: &std::sync::Arc<Paths>) {
    paths.progress.on_handshake_done(paths);
}

/// Observe the same four scenarios across existing sending and receiving tests.
fn selection(paths: &Paths, path: &qtransport::path::Path) -> u8 {
    let facts = paths.progress.facts();
    if facts.is_handshake_done() {
        2
    } else if !facts.has_selected_path() {
        u8::MAX
    } else {
        u8::from(path.is_active())
    }
}

/// Borrow a CID for payload collection on an active path.
fn borrow(path: &qtransport::path::Path) -> std::task::Poll<Option<qbase::cid::ConnectionId>> {
    use std::task::{Context, Poll, Waker};
    if path.validation.is_cancelled() {
        return Poll::Ready(None);
    }
    if !path.is_active() {
        return Poll::Pending;
    }
    let result = path.dcid.poll_borrow(&mut Context::from_waker(Waker::noop()));
    if matches!(result, Poll::Ready(Some(_))) {
        path.dcid.refresh();
    }
    result
}
