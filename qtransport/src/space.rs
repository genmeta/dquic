//! Packet-number spaces and recovery feedback. No parent connection back-reference.
use std::{sync::Arc, time::Duration};

use derive_more::Deref;
use qbase::{
    Epoch,
    frame::{AckFrame, Frame, ReliableFrame, StreamCtlFrame, io::SendFrame},
    packet::PacketNumber,
};
use qevent::quic::recovery::PacketLostTrigger;
use qrecovery::{
    crypto::CryptoStream,
    journal::{ArcRcvdJournal, ArcSentJournal},
    streams::DataStreams,
};
use tokio::time::Instant;

use crate::{
    ArcReliableFrames, Error, GuaranteedFrame,
    keys::{ArcKeys, ArcOneRttKeys},
};

/// The complete set of packet-number spaces, sharing the already running early spaces.
pub struct Spaces {
    pub initial: Arc<Space<ArcKeys>>,
    pub handshake: Arc<Space<ArcKeys>>,
    pub data: Arc<DataSpace>,
}

pub struct Space<K> {
    pub epoch: Epoch,
    pub keys: K,
    pub crypto: CryptoStream,
    pub sent_journal: ArcSentJournal,
    pub rcvd_journal: ArcRcvdJournal,
}

impl<K> Space<K> {
    /// Create a packet-number space with ready keys.
    pub fn new(epoch: Epoch, keys: K) -> Self {
        Self {
            epoch,
            keys,
            crypto: CryptoStream::new(),
            sent_journal: ArcSentJournal::default(),
            rcvd_journal: ArcRcvdJournal::with_capacity(0, None),
        }
    }

    /// Reserve a packet number before assembly.
    pub fn next_pn(&self) -> Result<(u64, PacketNumber), Error> {
        self.sent_journal.next_pn()
    }

    /// Retain a sealed packet's frames before UDP submission.
    pub fn on_assembled(&self, pn: u64, frames: impl IntoIterator<Item = Frame>) {
        self.sent_journal.on_assembled(pn, None, frames);
    }

    /// Start timers for a successfully submitted batch, locking the journal once.
    pub fn on_sent(
        &self,
        packets: impl IntoIterator<Item = (u64, bool)>,
        retransmit_after: Duration,
        retention: Duration,
    ) {
        let mut journal = self.sent_journal.lock_guard();
        for (pn, in_flight) in packets {
            journal.on_sent(pn, in_flight, retransmit_after, retention);
        }
    }

    /// Release acknowledged CRYPTO data and report whether any bytes were acknowledged.
    pub fn on_acked(&self, ack: &AckFrame) -> Result<bool, Error> {
        let mut crypto_acked = false;
        self.sent_journal.on_acked(ack, |frame| {
            if let GuaranteedFrame::Crypto(frame) = frame {
                crypto_acked |= frame.len() > 0;
                self.crypto.outgoing().on_data_acked(frame);
            }
        })?;
        Ok(crypto_acked)
    }

    /// Cancel an unsubmitted packet and return its CRYPTO data for retransmission.
    pub fn cancel(&self, pn: u64) {
        self.sent_journal.cancel(pn, |frame| self.recover(&frame));
    }

    /// Recover CRYPTO data in an Initial or Handshake space.
    pub fn recover(&self, frame: &GuaranteedFrame) {
        if let GuaranteedFrame::Crypto(frame) = frame {
            self.crypto.outgoing().may_loss_data(frame);
        }
    }
}

impl<K: Clone> Space<ArcKeys<K>> {
    /// Drive CRYPTO recovery for an Initial or Handshake space without a path sender.
    pub fn on_tick(&self, now: Instant) {
        if self.keys.get().is_ok() {
            self.sent_journal.on_tick(now, |frame| self.recover(frame));
        }
    }

    /// Discard this epoch permanently. Other spaces and the connection inbox remain live.
    pub fn retire(&self) {
        self.keys.retire();
        self.crypto.sender.retire();
        self.crypto.recver.retire();
    }
}

impl<K: Clone + Send> qcongestion::Resend for Space<ArcKeys<K>> {
    fn resend(&self, _: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        self.sent_journal.resend(pns, |frame| self.recover(frame));
    }
}

/// Application-data space and all of its retransmittable frame sources.
#[derive(Deref)]
pub struct DataSpace {
    #[deref]
    pub space: Space<ArcOneRttKeys>,
    pub streams: DataStreams<ArcReliableFrames>,
    pub reliable_frames: ArcReliableFrames,
}

impl DataSpace {
    pub fn new(
        keys: ArcOneRttKeys,
        streams: DataStreams<ArcReliableFrames>,
        reliable_frames: ArcReliableFrames,
    ) -> Self {
        Self {
            space: Space::new(Epoch::Data, keys),
            streams,
            reliable_frames,
        }
    }

    /// Reserve a packet number before assembly.
    pub fn next_pn(&self) -> Result<(u64, PacketNumber), Error> {
        self.sent_journal.next_pn()
    }

    /// Retain a sealed packet's frames before UDP submission.
    pub fn on_assembled(&self, pn: u64, generation: u64, frames: impl IntoIterator<Item = Frame>) {
        self.sent_journal.on_assembled(pn, Some(generation), frames);
    }

    /// Start timers for a successfully submitted batch, locking the journal once.
    pub fn on_sent(
        &self,
        packets: impl IntoIterator<Item = (u64, bool)>,
        retransmit_after: Duration,
        retention: Duration,
    ) {
        let mut journal = self.sent_journal.lock_guard();
        for (pn, in_flight) in packets {
            journal.on_sent(pn, in_flight, retransmit_after, retention);
        }
    }

    /// Release acknowledged data and return the highest newly acknowledged key generation.
    pub fn on_acked(&self, ack: &AckFrame) -> Result<Option<u64>, Error> {
        self.sent_journal.on_acked(ack, |frame| match frame {
            GuaranteedFrame::Crypto(frame) => self.crypto.outgoing().on_data_acked(frame),
            GuaranteedFrame::Stream(frame) => self.streams.on_data_acked(*frame),
            GuaranteedFrame::Reliable(ReliableFrame::StreamCtl(StreamCtlFrame::ResetStream(
                frame,
            ))) => self.streams.on_reset_acked(*frame),
            _ => {}
        })
    }

    /// Cancel an unsubmitted packet and return its data to the frame sources.
    pub fn cancel(&self, pn: u64) {
        self.sent_journal.cancel(pn, |frame| self.recover(&frame));
    }

    /// Return lost or unsubmitted data to the components that own it.
    pub fn recover(&self, frame: &GuaranteedFrame) {
        match frame {
            GuaranteedFrame::Crypto(frame) => self.crypto.outgoing().may_loss_data(frame),
            GuaranteedFrame::Stream(frame) => self.streams.may_loss_data(frame),
            GuaranteedFrame::Reliable(frame) => self.reliable_frames.send_frame([frame.clone()]),
        }
    }

    /// Keep recovering while Data keys remain live, even without a path sender.
    pub fn on_tick(&self, now: Instant) {
        if self.keys.get().is_ok() {
            self.sent_journal.on_tick(now, |frame| self.recover(frame));
        }
    }
}

impl qcongestion::Resend for DataSpace {
    fn resend(&self, _: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        self.sent_journal.resend(pns, |frame| self.recover(frame));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;

    use super::*;

    fn record(space: &Space<ArcKeys<()>>) -> u64 {
        let frames = crate::tests::take_frames(&mut space.crypto.outgoing());
        assert_eq!(frames.len(), 1);
        let (pn, _) = space.next_pn().unwrap();
        space.on_assembled(pn, frames);
        space.on_sent([(pn, true)], Duration::from_secs(1), Duration::from_secs(3));
        pn
    }

    #[tokio::test]
    async fn shared_space_recovers_once_and_stops_after_key_retirement() {
        let space = Arc::new(Space::new(Epoch::Initial, ArcKeys::new(())));
        let paths: [Arc<dyn qcongestion::Resend>; 2] = [space.clone(), space.clone()];
        space.crypto.writer().write_all(b"first").await.unwrap();
        let first = record(&space);
        paths[0].resend(PacketLostTrigger::TimeThreshold, &mut [first].into_iter());
        paths[1].resend(PacketLostTrigger::TimeThreshold, &mut [first].into_iter());
        assert_eq!(
            crate::tests::take_frames(&mut space.crypto.outgoing()).len(),
            1
        );
        assert!(crate::tests::take_frames(&mut space.crypto.outgoing()).is_empty());

        space.crypto.writer().write_all(b"second").await.unwrap();
        record(&space);
        space.on_tick(Instant::now() + Duration::from_secs(2));
        assert_eq!(
            crate::tests::take_frames(&mut space.crypto.outgoing()).len(),
            1
        );

        space.crypto.writer().write_all(b"third").await.unwrap();
        let third = record(&space);
        space.keys.retire();
        paths[0].resend(PacketLostTrigger::TimeThreshold, &mut [third].into_iter());
        space.on_tick(Instant::now() + Duration::from_secs(2));
        assert!(crate::tests::take_frames(&mut space.crypto.outgoing()).is_empty());
    }

    #[tokio::test]
    async fn late_ack_cancels_crypto_recovery() {
        use qcongestion::Resend as _;

        let space = Space::new(Epoch::Handshake, ArcKeys::new(()));
        space.crypto.writer().write_all(b"crypto").await.unwrap();
        let pn = record(&space);
        space.resend(PacketLostTrigger::TimeThreshold, &mut [pn].into_iter());
        let ack = AckFrame::new(
            pn.try_into().unwrap(),
            0u32.into(),
            0u32.into(),
            vec![],
            None,
        );
        assert!(space.on_acked(&ack).unwrap());
        space.resend(PacketLostTrigger::TimeThreshold, &mut [pn].into_iter());
        space.on_tick(Instant::now() + Duration::from_secs(2));
        assert!(crate::tests::take_frames(&mut space.crypto.outgoing()).is_empty());
        assert!(!space.on_acked(&ack).unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn batch_submission_allows_early_ack_and_leaves_suffix_pending() {
        for epoch in [Epoch::Initial, Epoch::Handshake] {
            let space = Space::new(epoch, ArcKeys::new(()));
            let mut pns = Vec::new();
            for bytes in [b"first".as_slice(), b"second", b"third"] {
                space.crypto.writer().write_all(bytes).await.unwrap();
                let pn = space.next_pn().unwrap().0;
                space.on_assembled(pn, crate::tests::take_frames(&mut space.crypto.outgoing()));
                pns.push(pn);
            }
            let ack = AckFrame::new(
                pns[0].try_into().unwrap(),
                0u32.into(),
                0u32.into(),
                vec![],
                None,
            );
            assert!(space.on_acked(&ack).unwrap());
            space.on_sent(
                pns[..2].iter().map(|&pn| (pn, true)),
                Duration::from_secs(1),
                Duration::from_secs(3),
            );
            space.on_tick(Instant::now() + Duration::from_secs(2));
            let recovered = crate::tests::take_frames(&mut space.crypto.outgoing());
            assert!(
                matches!(recovered.as_slice(), [Frame::Crypto(frame, _)] if frame.offset() == 5 && frame.len() == 6)
            );
            space.cancel(pns[2]);
            let recovered = crate::tests::take_frames(&mut space.crypto.outgoing());
            assert!(
                matches!(recovered.as_slice(), [Frame::Crypto(frame, _)] if frame.offset() == 11 && frame.len() == 5)
            );
            assert!(!space.on_acked(&ack).unwrap());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn data_pending_ack_reports_generation_and_prevents_retransmission() {
        use qbase::frame::MaxDataFrame;

        let [(_connection, transport, _path), _] = crate::tests::pair(1);
        let data = &transport.data;
        let pn = data.next_pn().unwrap().0;
        data.on_assembled(pn, 7, [Frame::MaxData(MaxDataFrame::new(123u32.into()))]);
        let ack = AckFrame::new(
            pn.try_into().unwrap(),
            0u32.into(),
            0u32.into(),
            vec![],
            None,
        );
        assert_eq!(data.on_acked(&ack).unwrap(), Some(7));
        data.on_sent([(pn, true)], Duration::from_secs(1), Duration::from_secs(3));
        data.on_tick(Instant::now() + Duration::from_secs(2));
        assert!(crate::tests::take_frames(&mut data.reliable_frames.clone()).is_empty());
        assert!(data.on_acked(&ack).unwrap().is_none());
    }

    #[tokio::test]
    async fn retired_data_keys_stop_loss_and_timer_recovery() {
        use qbase::frame::MaxDataFrame;
        use qcongestion::Resend as _;

        let [(_connection, transport, _path), _] = crate::tests::pair(1);
        let data = &transport.data;
        data.reliable_frames
            .send_frame([MaxDataFrame::new(123u32.into())]);
        let frames = crate::tests::take_frames(&mut data.reliable_frames.clone());
        assert_eq!(frames.len(), 1);
        let (pn, _) = data.next_pn().unwrap();
        data.on_assembled(pn, 0, frames);
        data.on_sent([(pn, true)], Duration::from_secs(1), Duration::from_secs(3));
        data.keys.retire();
        data.resend(PacketLostTrigger::TimeThreshold, &mut [pn].into_iter());
        data.on_tick(Instant::now() + Duration::from_secs(2));
        assert!(crate::tests::take_frames(&mut data.reliable_frames.clone()).is_empty());
    }
}
