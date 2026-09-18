//! One packet-number space. No parent connection or transport back-reference.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use qbase::{
    Epoch,
    net::tx::{ArcSendWakers, Signals},
};
use qcongestion::Feedback;
use qevent::quic::recovery::PacketLostTrigger;
use qrecovery::{crypto::CryptoStream, journal::ArcRcvdJournal};
use tokio::time::Instant;

use crate::{
    GuaranteedFrame,
    keys::{ArcKeys, ArcOneRttKeys},
    send::records::ArcSendJournal,
};

pub struct Space<K> {
    pub epoch: Epoch,
    pub keys: K,
    pub crypto: CryptoStream,
    pub send_journal: ArcSendJournal,
    pub rcvd_packets: ArcRcvdJournal,
    receiving: AtomicBool,
    sending: AtomicBool,
    pub(crate) submission: Arc<Mutex<()>>,
    pub send_wakers: ArcSendWakers,
    on_loss: Box<dyn Fn(&GuaranteedFrame) + Send + Sync>,
}

impl<K> Space<K> {
    /// Capture this space's frame owners in on_loss before starting CC or timer tasks.
    /// It runs synchronously under the journal lock and must not reenter the journal or CC.
    pub fn new(
        epoch: Epoch,
        keys: K,
        crypto: CryptoStream,
        submission: Arc<Mutex<()>>,
        send_wakers: ArcSendWakers,
        on_loss: impl Fn(&GuaranteedFrame) + Send + Sync + 'static,
    ) -> Self {
        Self {
            epoch,
            keys,
            crypto,
            send_journal: ArcSendJournal::default(),
            rcvd_packets: ArcRcvdJournal::with_capacity(0, None),
            receiving: true.into(),
            sending: true.into(),
            submission,
            send_wakers,
            on_loss: Box::new(on_loss),
        }
    }

    /// Notify the same frame owners as CC loss feedback, independent of path lifetime.
    pub fn on_tick(&self, now: Instant) {
        self.send_journal.on_tick(now, &self.on_loss);
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
        let _submission = self.submission.lock().unwrap();
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

impl Space<ArcOneRttKeys> {
    pub fn retire(&self) {
        self.stop_receiving();
        self.stop_sending();
        self.keys.retire();
    }
}

impl<K: Send + Sync> Feedback for Space<K> {
    fn may_loss(&self, _: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        self.send_journal.mark_lost(pns, &self.on_loss);
    }
}
