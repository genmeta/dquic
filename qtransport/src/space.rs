//! One packet-number space. No parent connection or transport back-reference.
use std::sync::Arc;

use qbase::{
    Epoch,
    net::tx::{ArcSendWakers, Signals},
};
use qcongestion::Feedback;
use qevent::quic::recovery::PacketLostTrigger;
use qrecovery::{crypto::CryptoStream, journal::ArcRcvdJournal};

use crate::{control::Control, send::records::SentPackets};

pub struct Space<K> {
    pub epoch: Epoch,
    pub keys: K,
    pub crypto: CryptoStream,
    pub sent_packets: SentPackets,
    pub rcvd_packets: ArcRcvdJournal,
    pub control: Arc<Control>,
    pub send_wakers: ArcSendWakers,
}

impl<K> Space<K> {
    pub fn new(epoch: Epoch, keys: K, control: Arc<Control>, send_wakers: ArcSendWakers) -> Self {
        Self {
            epoch,
            keys,
            crypto: CryptoStream::new(send_wakers.clone()),
            sent_packets: SentPackets::default(),
            rcvd_packets: ArcRcvdJournal::with_capacity(0, None),
            control,
            send_wakers,
        }
    }
}

impl<K: Send + Sync> Feedback for Space<K> {
    fn may_loss(&self, _: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        self.sent_packets.mark_lost(pns);
        self.send_wakers.wake_all_by(Signals::TRANSPORT);
    }
}
