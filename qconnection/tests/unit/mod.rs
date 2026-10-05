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
        self.phase().terminator().terminate();
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
    pub phase: std::sync::Arc<crate::MaturePhase>,
    pub spaces: SpaceFixture,
}

impl std::ops::Deref for MatureFixture {
    type Target = crate::MaturePhase;
    fn deref(&self) -> &Self::Target {
        &self.phase
    }
}

pub fn enter_mature(phase: &crate::ArcConnPhase, mature: &MatureFixture) {
    if matches!(phase.get(), crate::ConnPhase::Initial(_)) {
        enter_handshake(phase, mature.spaces.handshake.clone());
    }
    mature
        .resender
        .write()
        .unwrap()
        .push_back(mature.spaces.data.clone())
        .unwrap();
    mature
        .phase
        .spaces
        .write()
        .unwrap()
        .0
        .push_back(mature.spaces.data.clone())
        .unwrap();
    phase.enter_mature(mature.phase.clone());
}

/// Install resources before switching phase, as growing does.
pub fn enter_handshake(
    phase: &crate::ArcConnPhase,
    handshake: std::sync::Arc<qtransport::space::HandshakeSpace>,
) {
    let current = phase.get();
    current
        .resender()
        .write()
        .unwrap()
        .push_back(handshake.clone())
        .unwrap();
    current
        .spaces()
        .write()
        .unwrap()
        .0
        .push_back(handshake)
        .unwrap();
    phase.enter_handshake();
}

/// Emulate lifecycle retirement in tests that do not run growing.
pub fn retire_spaces(paths: &Paths, end: qbase::Epoch) {
    let phase = paths.phase().get();
    let mut spaces = phase.spaces().write().unwrap();
    let mut resender = phase.resender().write().unwrap();
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
