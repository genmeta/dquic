//! Packet-number spaces and recovery feedback. No parent connection back-reference.
use std::sync::{Arc, Mutex};

use qbase::{
    Epoch,
    error::{ErrorKind, QuicError},
    net::tx::{ArcSendWakers, Signals},
};
use qevent::quic::recovery::PacketLostTrigger;
use qrecovery::{crypto::CryptoStream, journal::ArcRcvdJournal};
use tokio::time::Instant;

use crate::{
    GuaranteedFrame,
    keys::{ArcKeys, ArcOneRttKeys},
    send::records::ArcSendJournal,
};

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

/// The complete set of packet-number spaces, sharing the already running early spaces.
pub struct Spaces {
    pub initial: Arc<Space<ArcKeys>>,
    pub handshake: Arc<Space<ArcKeys>>,
    pub data: Arc<Space<ArcOneRttKeys>>,
}

pub struct Space<K> {
    pub epoch: Epoch,
    pub keys: K,
    pub crypto: CryptoStream,
    pub send_journal: ArcSendJournal,
    pub rcvd_journal: ArcRcvdJournal,
    pub send_wakers: ArcSendWakers,
}

impl<K: Default> Space<K> {
    /// Create pending keys and the CRYPTO stream together. CRYPTO loss is recovered
    /// internally; on_loss only receives the remaining frame owners.
    pub fn new(
        epoch: Epoch,
        send_wakers: ArcSendWakers,
        on_loss: impl Fn(&GuaranteedFrame) + Send + Sync + 'static,
    ) -> Self {
        let crypto = CryptoStream::new(send_wakers.clone());
        let outgoing = crypto.outgoing();
        Self {
            epoch,
            keys: K::default(),
            crypto,
            send_journal: ArcSendJournal::new(move |frame| match frame {
                GuaranteedFrame::Crypto(frame) => outgoing.may_loss_data(frame),
                frame => on_loss(frame),
            }),
            rcvd_journal: ArcRcvdJournal::with_capacity(0, None),
            send_wakers,
        }
    }
}

impl Space<ArcKeys> {
    pub fn install_initial_keys(&self, keys: qtls::BidirectionalKeys) -> Result<(), crate::Error> {
        self.keys.install(Arc::new(keys))?;
        self.send_wakers.wake_all_by(Signals::KEYS);
        Ok(())
    }

    pub fn install_hs_keys(&self, keys: qtls::InstalledKeys) -> Result<(), crate::Error> {
        let qtls::InstalledKeys::Handshake(keys) = keys else {
            return Err(QuicError::with_default_fty(
                ErrorKind::Internal,
                "expected TLS Handshake keys",
            )
            .into());
        };
        self.install_initial_keys(keys)
    }
}

impl Space<ArcOneRttKeys> {
    pub fn install_1rtt_keys(&self, keys: qtls::InstalledKeys) -> Result<(), crate::Error> {
        let qtls::InstalledKeys::OneRtt(keys) = keys else {
            return Err(QuicError::with_default_fty(
                ErrorKind::Internal,
                "expected TLS 1-RTT keys",
            )
            .into());
        };
        self.keys.install(keys)?;
        self.send_wakers.wake_all_by(Signals::KEYS);
        Ok(())
    }
}

impl<K: Clone> Space<ArcKeys<K>> {
    /// Notify the same frame owners as CC loss feedback, independent of path lifetime.
    pub fn on_tick(&self, now: Instant) {
        if self.keys.try_get().is_ok() {
            self.send_journal
                .on_tick(now, |frame| self.send_journal.recover(frame));
        }
    }

    /// Discard this epoch permanently. Other spaces and the connection inbox remain live.
    pub fn retire(&self) {
        self.keys.retire();
        self.crypto.sender.retire();
        self.crypto.recver.retire();
    }
}

impl Space<ArcOneRttKeys> {
    /// Notify frame owners while Data packet keys remain live.
    pub fn on_tick(&self, now: Instant) {
        if self.keys.try_get().is_ok() {
            self.send_journal
                .on_tick(now, |frame| self.send_journal.recover(frame));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

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
        let space = Space::<ArcKeys<()>>::new(Epoch::Data, Default::default(), move |_| {
            counter.fetch_add(1, Ordering::Relaxed);
        });
        space.keys.install(()).unwrap();
        feedback.start(space.send_journal.clone());
        let first = record(&space.send_journal);
        paths[0].may_loss(PacketLostTrigger::TimeThreshold, &mut [first].into_iter());
        paths[1].may_loss(PacketLostTrigger::TimeThreshold, &mut [first].into_iter());
        assert_eq!(recovered.load(Ordering::Relaxed), 1);

        let second = record(&space.send_journal);
        paths[1].may_loss(PacketLostTrigger::TimeThreshold, &mut [second].into_iter());
        assert_eq!(recovered.load(Ordering::Relaxed), 2);
        let third = record(&space.send_journal);
        space.keys.retire();
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
