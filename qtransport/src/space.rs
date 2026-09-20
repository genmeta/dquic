//! One packet-number space. No parent connection or transport back-reference.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use qbase::{
    Epoch,
    net::tx::{ArcSendWakers, Signals},
};
use qevent::quic::recovery::PacketLostTrigger;
use qrecovery::{crypto::CryptoStream, journal::ArcRcvdJournal};
use tokio::time::Instant;

use crate::{GuaranteedFrame, keys::ArcKeys, send::records::ArcSendJournal};

#[derive(Default)]
enum Feedback {
    #[default]
    Pending,
    Running(ArcSendJournal),
    Retired,
}

/// Shared recovery entry for a packet-number space, created before its components.
/// Every path keeps this same entry throughout the connection lifetime.
#[derive(Clone, Default)]
pub struct ArcFeedback(Arc<Mutex<Feedback>>);

impl ArcFeedback {
    /// Attach a ready space's journal to the shared pending entry.
    pub fn start(&self, journal: ArcSendJournal) {
        let mut state = self.0.lock().unwrap();
        if matches!(*state, Feedback::Pending) {
            *state = Feedback::Running(journal);
        }
    }

    /// End recovery permanently; a retired entry cannot be started again.
    pub fn retire(&self) {
        *self.0.lock().unwrap() = Feedback::Retired;
    }
}

impl From<ArcSendJournal> for ArcFeedback {
    fn from(journal: ArcSendJournal) -> Self {
        Self(Arc::new(Mutex::new(Feedback::Running(journal))))
    }
}

impl qcongestion::Feedback for ArcFeedback {
    fn may_loss(&self, _: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        if let Feedback::Running(journal) = &*self.0.lock().unwrap() {
            journal.mark_lost(pns, |frame| journal.recover(frame));
        }
    }
}

pub struct Space<K> {
    pub epoch: Epoch,
    pub keys: K,
    pub crypto: CryptoStream,
    pub send_journal: ArcSendJournal,
    pub rcvd_journal: ArcRcvdJournal,
    receiving: AtomicBool,
    sending: AtomicBool,
    pub send_wakers: ArcSendWakers,
}

impl<K> Space<K> {
    /// Capture this space's frame owners in on_loss before starting CC or timer tasks.
    /// Recovery callbacks must not reenter feedback, journal or CC.
    pub fn new(
        epoch: Epoch,
        keys: K,
        crypto: CryptoStream,
        send_wakers: ArcSendWakers,
        on_loss: impl Fn(&GuaranteedFrame) + Send + Sync + 'static,
    ) -> Self {
        Self {
            epoch,
            keys,
            crypto,
            send_journal: ArcSendJournal::new(on_loss),
            rcvd_journal: ArcRcvdJournal::with_capacity(0, None),
            receiving: true.into(),
            sending: true.into(),
            send_wakers,
        }
    }

    /// Notify the same frame owners as CC loss feedback, independent of path lifetime.
    pub fn on_tick(&self, now: Instant) {
        if self.can_send() {
            self.send_journal
                .on_tick(now, |frame| self.send_journal.recover(frame));
        }
    }

    pub fn can_receive(&self) -> bool {
        self.receiving.load(Ordering::Acquire)
    }

    pub fn can_send(&self) -> bool {
        self.sending.load(Ordering::Acquire)
    }

    pub fn stop_receiving(&self) {
        self.receiving.store(false, Ordering::Release);
    }

    pub fn stop_sending(&self) {
        self.sending.store(false, Ordering::Release);
        self.send_wakers.wake_all_by(Signals::all());
    }
}

impl<K> Space<ArcKeys<K>> {
    /// Discard this epoch permanently. Other spaces and the connection inbox remain live.
    pub fn retire(&self) {
        self.stop_receiving();
        self.stop_sending();
        self.keys.retire();
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::atomic::AtomicUsize, time::Duration};

    use qbase::frame::{MaxDataFrame, ReliableFrame};
    use qcongestion::Feedback as _;

    use super::*;

    fn record(journal: &ArcSendJournal) -> u64 {
        let frame =
            GuaranteedFrame::Reliable(ReliableFrame::MaxData(MaxDataFrame::new(10u32.into())));
        let (pn, _) = journal.record_pending(0, &mut vec![frame]).unwrap();
        journal.mark_sent(pn, true, Duration::from_secs(1), Duration::from_secs(3));
        pn
    }

    #[test]
    fn existing_paths_share_activation_and_retirement() {
        let feedback = ArcFeedback::default();
        let paths = [feedback.clone(), feedback.clone()];
        paths[0].may_loss(PacketLostTrigger::TimeThreshold, &mut [0].into_iter());
        assert!(matches!(*feedback.0.lock().unwrap(), Feedback::Pending));

        let recovered = Arc::new(AtomicUsize::new(0));
        let counter = recovered.clone();
        let space = Space::new(
            Epoch::Data,
            (),
            CryptoStream::new(Default::default()),
            Default::default(),
            move |_| {
                counter.fetch_add(1, Ordering::Relaxed);
            },
        );
        feedback.start(space.send_journal.clone());
        let first = record(&space.send_journal);
        paths[0].may_loss(PacketLostTrigger::TimeThreshold, &mut [first].into_iter());
        paths[1].may_loss(PacketLostTrigger::TimeThreshold, &mut [first].into_iter());
        assert_eq!(recovered.load(Ordering::Relaxed), 1);

        let second = record(&space.send_journal);
        paths[1].may_loss(PacketLostTrigger::TimeThreshold, &mut [second].into_iter());
        assert_eq!(recovered.load(Ordering::Relaxed), 2);
        let third = record(&space.send_journal);
        space.stop_sending();
        feedback.retire();
        paths[0].may_loss(PacketLostTrigger::TimeThreshold, &mut [third].into_iter());
        space.on_tick(Instant::now() + Duration::from_secs(2));
        assert_eq!(recovered.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn pending_retirement_cannot_be_reopened() {
        let feedback = ArcFeedback::default();
        feedback.retire();
        let recovered = Arc::new(AtomicUsize::new(0));
        let counter = recovered.clone();
        let journal = ArcSendJournal::new(move |_| {
            counter.fetch_add(1, Ordering::Relaxed);
        });
        let pn = record(&journal);
        feedback.start(journal);
        feedback.may_loss(PacketLostTrigger::TimeThreshold, &mut [pn].into_iter());
        assert!(matches!(*feedback.0.lock().unwrap(), Feedback::Retired));
        assert_eq!(recovered.load(Ordering::Relaxed), 0);
    }
}
