use std::sync::{Arc, Mutex, atomic::AtomicU16};

use qbase::{
    net::tx::ArcSendWakers,
    util::{ArcIndexDeque, IndexDeque},
};
use qcongestion::{Algorithm, ArcCC, HandshakeStatus, MSS, Resend};
use qevent::quic::recovery::PacketLostTrigger;
use tokio::time::Duration;

pub struct NoopFeedback;

impl Resend for NoopFeedback {
    fn resend(&self, _: PacketLostTrigger, _: &mut dyn Iterator<Item = u64>) {}
}

pub struct RecordingFeedback(pub Arc<Mutex<Vec<u64>>>);

impl Resend for RecordingFeedback {
    fn resend(&self, _: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        self.0.lock().unwrap().extend(pns);
    }
}

pub fn trackers(feedback: Arc<dyn Resend>) -> ArcIndexDeque<Arc<dyn Resend>, 2> {
    let mut entries = IndexDeque::with_capacity(3);
    for tracker in [feedback.clone(), feedback.clone(), feedback] {
        entries.push_back(tracker).unwrap();
    }
    ArcIndexDeque::from(entries)
}

pub fn controller_with(
    handshake: Arc<HandshakeStatus>,
    trackers: ArcIndexDeque<Arc<dyn Resend>, 2>,
) -> ArcCC {
    ArcCC::new(
        Algorithm::NewReno,
        Duration::from_millis(25),
        trackers,
        handshake,
        Arc::new(AtomicU16::new(MSS as u16)),
        ArcSendWakers::default(),
    )
}

pub fn controller_with_feedback(feedback: Arc<dyn Resend>) -> ArcCC {
    let handshake = Arc::new(HandshakeStatus::new(false));
    handshake.handshake_confirmed();
    controller_with(handshake, trackers(feedback))
}

pub fn controller() -> ArcCC {
    controller_with_feedback(Arc::new(NoopFeedback))
}
