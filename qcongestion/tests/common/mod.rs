use std::sync::{Arc, Mutex, atomic::AtomicU16};

use qbase::{
    handshake::HandshakeFacts,
    net::validate::ArcValidation,
    role::Role,
    util::{ArcIndexDeque, IndexDeque},
};
use qcongestion::{Algorithm, ArcCC, MSS, Resend};
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

pub fn controller_with(handshake: Arc<HandshakeFacts>, trackers: ArcIndexDeque<Arc<dyn Resend>, 2>) -> ArcCC {
    let validation = ArcValidation::new();
    validation.exempt().unwrap();
    controller_with_validation(handshake, trackers, validation)
}

pub fn controller_with_validation(
    handshake: Arc<HandshakeFacts>,
    trackers: ArcIndexDeque<Arc<dyn Resend>, 2>,
    validation: ArcValidation,
) -> ArcCC {
    ArcCC::new(Algorithm::NewReno, Duration::from_millis(25), trackers, handshake, validation, Arc::new(AtomicU16::new(MSS as u16)))
}

pub fn controller_with_feedback(feedback: Arc<dyn Resend>) -> ArcCC {
    let handshake = Arc::new(HandshakeFacts::with_role(Role::Client));
    handshake.on_handshake_done();
    controller_with(handshake, trackers(feedback))
}

pub fn controller() -> ArcCC {
    controller_with_feedback(Arc::new(NoopFeedback))
}
