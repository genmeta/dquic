//! Application-data space and its CRYPTO, reliable-frame and stream sources.
use std::task::{Context, Poll, Waker};

use derive_more::Deref;
use qbase::{
    Epoch,
    cid::ConnectionId,
    frame::{AckFrame, ReliableFrame, StreamCtlFrame, io::SendFrame},
    net::tx::UnregisterWaker,
    packet::{
        OneRttHeader, PacketNumber,
        assemble::{Assemble, PacketBuffer, Package},
    },
};
use qevent::quic::recovery::PacketLostTrigger;
use qrecovery::streams::DataStreams;
use smallvec::SmallVec;
use tokio::time::Instant;

use super::{Encapsulate, Recover, Space};
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
    ) -> Self {
        Self {
            space: Space::new(Epoch::Data, initial_scid, keys),
            streams,
            reliable_frames,
        }
    }
}

impl qcongestion::Resend for DataSpace {
    fn resend(&self, _: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        if self.keys.get().is_ok() {
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
        if self.keys.get().is_ok() {
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
        _: bool,
    ) -> Poll<Result<usize, Error>> {
        let header = OneRttHeader::new(Default::default(), dcid);
        if !buffer.begin(&header, pn.1, min_size) {
            return Poll::Ready(Ok(0));
        }
        let mut crypto = self.crypto.outgoing();
        let mut reliable = self.reliable_frames.clone();
        let mut streams = self.streams.clone();
        let internal: [&mut dyn Package<&mut [u8]>; 3] =
            [&mut crypto, &mut reliable, &mut streams];
        let mut sources: SmallVec<[&mut dyn Package<&mut [u8]>; 12]> = external
            .iter_mut()
            .map(|source| &mut **source as &mut dyn Package<&mut [u8]>)
            .chain(internal)
            .collect();
        buffer.assemble(cx, &mut sources)
    }
}
