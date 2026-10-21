//! Application-data space and its CRYPTO, reliable-frame and stream sources.
use std::{
    sync::{Arc, atomic::AtomicBool},
    task::{Context, Poll, Waker},
    time::Duration,
};

use derive_more::Deref;
use qbase::{
    Epoch,
    cid::ConnectionId,
    frame::{AckFrame, ReliableFrame, StreamCtlFrame, io::SendFrame},
    net::tx::UnregisterWaker,
    packet::{
        OneRttHeader, PacketNumber,
        assemble::{Assemble, Package, PacketBuffer},
    },
};
use qevent::quic::recovery::PacketLostTrigger;
use qrecovery::{
    crypto::CryptoStream,
    journal::{ArcRcvdJournal, ArcSentJournal},
    streams::DataStreams,
};
use smallvec::SmallVec;
use tokio::time::Instant;

use super::{Allocate, Encapsulate, Keys, Recover, Space, Transmit};
use crate::{ArcReliableFrames, Error, GuaranteedFrame, keys::ArcOneRttKeys};

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
        initial_scid: ConnectionId,
        keys: ArcOneRttKeys,
        streams: DataStreams<ArcReliableFrames>,
        reliable_frames: ArcReliableFrames,
        is_mp_handshaking: Arc<AtomicBool>,
    ) -> Self {
        Self {
            space: Space::new(Epoch::Data, initial_scid, keys, is_mp_handshaking),
            streams,
            reliable_frames,
        }
    }
}

impl Allocate for DataSpace {
    fn pn_and_keys(&self) -> Result<Option<((u64, PacketNumber), Keys)>, Error> {
        // Serialize generation selection and PN allocation across every sending path.
        let mut journal = self.sent_journal.lock_guard();
        let keys = match self.keys.get() {
            Ok(keys) => keys,
            Err(crate::keys::PacketError::Retired(_)) => return Ok(None),
            Err(error) => return Err(super::packet_error(error)),
        };
        let pn = journal.next_pn()?;
        Ok(Some((pn, Keys::Short(keys))))
    }
}

impl Transmit for DataSpace {
    fn epoch(&self) -> Epoch {
        self.epoch
    }

    fn crypto(&self) -> &CryptoStream {
        &self.crypto
    }

    fn sent_journal(&self) -> &ArcSentJournal {
        &self.sent_journal
    }

    fn rcvd_journal(&self) -> &ArcRcvdJournal {
        &self.rcvd_journal
    }

    fn on_sent(&self, pn: u64, in_flight: bool, retransmit_after: Duration, retention: Duration) {
        self.space
            .on_sent(pn, in_flight, retransmit_after, retention);
    }
}

impl qcongestion::Resend for DataSpace {
    fn resend(&self, _: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        if !self.keys.is_retired() {
            self.sent_journal.resend(pns, |frame| self.recover(frame));
        }
    }
}

impl Recover for DataSpace {
    /// Release acknowledged data and return the highest newly acknowledged key generation.
    fn on_acked(&self, ack: &AckFrame) -> Result<Option<u64>, Error> {
        self.sent_journal.on_acked(ack, |frame| match frame {
            GuaranteedFrame::Crypto(frame) => self.crypto.outgoing().on_data_acked(frame),
            GuaranteedFrame::Stream(frame) => self.streams.on_data_acked(*frame),
            GuaranteedFrame::Reliable(ReliableFrame::StreamCtl(StreamCtlFrame::ResetStream(
                frame,
            ))) => self.streams.on_reset_acked(*frame),
            _ => {}
        })
    }

    fn recover(&self, frame: &GuaranteedFrame) {
        match frame {
            GuaranteedFrame::Crypto(frame) => self.crypto.outgoing().may_loss_data(frame),
            GuaranteedFrame::Stream(frame) => self.streams.may_loss_data(frame),
            GuaranteedFrame::Reliable(frame) => self.reliable_frames.send_frame([frame.clone()]),
        }
    }

    fn retire(&self) {
        self.keys.retire();
    }

    fn on_tick(&self, now: Instant) {
        if !self.keys.is_retired() {
            self.sent_journal.on_tick(now, |frame| self.recover(frame));
        }
    }

    fn fresh_bytes(&self) -> usize {
        self.streams.fresh_bytes()
    }

    fn fresh_bytes_up_to(&self, limit: usize) -> usize {
        self.streams.fresh_bytes_up_to(limit)
    }

    fn cancel(&self, pn: u64, frames: &mut dyn Iterator<Item = GuaranteedFrame>) {
        for frame in frames {
            self.recover(&frame);
        }
        self.sent_journal.cancel(pn, |frame| self.recover(&frame));
    }
}

impl UnregisterWaker for DataSpace {
    fn unregister(&self, waker: &Waker) {
        self.space.unregister(waker);
        self.reliable_frames.unregister(waker);
        self.streams.unregister(waker);
    }
}

impl Encapsulate for DataSpace {
    fn encapsulate(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        pn: (u64, PacketNumber),
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
        buffer: &mut PacketBuffer<'_, &mut [u8]>,
        min_size: Option<usize>,
    ) -> Poll<Result<usize, Error>> {
        let header = OneRttHeader::new(Default::default(), dcid);
        if !buffer.begin(&header, pn.1, min_size) {
            return Poll::Ready(Ok(0));
        }
        let mut crypto = self.crypto.outgoing();
        let mut reliable = self.reliable_frames.clone();
        let mut streams = self.streams.clone();
        let internal: [&mut dyn Package<&mut [u8]>; 3] = [&mut crypto, &mut reliable, &mut streams];
        let mut sources: SmallVec<[&mut dyn Package<&mut [u8]>; 12]> = external
            .iter_mut()
            .map(|source| &mut **source as &mut dyn Package<&mut [u8]>)
            .chain(internal)
            .collect();
        buffer.assemble(cx, &mut sources)
    }
}
