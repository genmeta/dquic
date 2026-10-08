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

fn take_heartbeat(path: &qtransport::path::Path) -> bool {
    use std::task::{Context, Poll, Waker};

    use bytes::BytesMut;
    use qbase::packet::{PacketBuffer, Constraints, GetType, OneRttHeader, Package};

    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let mut limits = Constraints {
        send_quota: 1,
        credit: 1,
        max_size: 1,
        ..Default::default()
    };
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    match path.heartbeat.clone().poll_dump(
        &mut Context::from_waker(Waker::noop()),
        &mut PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0),
    ) {
        Poll::Ready(Ok(1)) => {
            assert!(frames.is_empty());
            assert_eq!(&bytes[..], &[1]);
            true
        }
        Poll::Pending => false,
        other => panic!("unexpected heartbeat result: {other:?}"),
    }
}

/// Concrete handles owned by the receive side, including already retired spaces.
pub struct SpaceFixture {
    pub initial: std::sync::Arc<qtransport::space::Space<qtransport::keys::ArcKeys>>,
    pub handshake: std::sync::Arc<qtransport::space::HandshakeSpace>,
    pub data: std::sync::Arc<qtransport::space::DataSpace>,
}

pub struct MatureFixture {
    pub paths: std::sync::Arc<Paths>,
    pub phase: std::sync::Arc<crate::MaturePhase>,
    pub spaces: SpaceFixture,
}

impl MatureFixture {
    pub fn peer_cid(&self) -> qbase::cid::ConnectionId {
        self.parameters
            .remote(qbase::param::ParameterId::InitialSourceConnectionId)
    }
}

impl std::ops::Deref for MatureFixture {
    type Target = crate::MaturePhase;
    fn deref(&self) -> &Self::Target {
        &self.phase
    }
}

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
    paths.assign_initial_dcid(&mature.cid_registry.remote);
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
