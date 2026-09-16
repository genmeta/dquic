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

use crate::{
    keys::{ArcKeys, ArcOneRttKeys},
    send::records::SentPackets,
};

pub struct Space<K> {
    pub epoch: Epoch,
    pub keys: K,
    pub crypto: CryptoStream,
    pub sent_packets: SentPackets,
    pub rcvd_packets: ArcRcvdJournal,
    receiving: AtomicBool,
    sending: AtomicBool,
    pub(crate) submission: Arc<Mutex<()>>,
    pub send_wakers: ArcSendWakers,
}

impl<K> Space<K> {
    pub fn new(
        epoch: Epoch,
        keys: K,
        submission: Arc<Mutex<()>>,
        send_wakers: ArcSendWakers,
    ) -> Self {
        Self {
            epoch,
            keys,
            crypto: CryptoStream::new(send_wakers.clone()),
            sent_packets: SentPackets::default(),
            rcvd_packets: ArcRcvdJournal::with_capacity(0, None),
            receiving: true.into(),
            sending: true.into(),
            submission,
            send_wakers,
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
        self.sent_packets.mark_lost(pns);
        self.send_wakers.wake_all_by(Signals::TRANSPORT);
    }
}
