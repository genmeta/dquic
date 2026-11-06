//! Application-data space and its CRYPTO, reliable-frame and stream sources.
use std::{
    io::Cursor,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use derive_more::Deref;
use qbase::{
    Epoch,
    cid::ConnectionId,
    frame::{AckFrame, ReliableFrame, StreamCtlFrame, io::SendFrame},
    handshake::HandshakeFacts,
    net::tx::UnregisterWaker,
    packet::{DataHeader, OneRttHeader, PacketContent, PacketNumber, assemble::Package},
};
use qcongestion::{ArcCC, Transport as _};
use qevent::quic::recovery::PacketLostTrigger;
use qrecovery::{
    crypto::CryptoStream,
    journal::{ArcRcvdJournal, ArcSentJournal},
    streams::DataStreams,
};
use smallvec::SmallVec;
use tokio::time::Instant;

use super::{Allocate, Encapsulate, Keys, Recover, Space, Transmit};
use crate::{
    ArcReliableFrames, Error, GuaranteedFrame, keys::ArcOneRttKeys, packet::encrypt::Packet,
};

/// Application-data space and all of its retransmittable frame sources.
#[derive(Deref)]
pub struct DataSpace {
    #[deref]
    pub space: Space<ArcOneRttKeys>,
    pub streams: DataStreams<ArcReliableFrames>,
    pub reliable_frames: ArcReliableFrames,
    pub peer_ack_delay_exponent: u32,
}

impl DataSpace {
    pub fn new(
        initial_scid: ConnectionId,
        keys: ArcOneRttKeys,
        streams: DataStreams<ArcReliableFrames>,
        reliable_frames: ArcReliableFrames,
        local_ack_delay_exponent: u32,
        peer_ack_delay_exponent: u32,
        facts: Arc<HandshakeFacts>,
    ) -> Self {
        let mut space = Space::new(Epoch::Data, initial_scid, keys, facts);
        space.rcvd_journal = space
            .rcvd_journal
            .with_ack_delay_exponent(local_ack_delay_exponent);
        Self {
            space,
            streams,
            reliable_frames,
            peer_ack_delay_exponent,
        }
    }
}

impl Allocate for DataSpace {
    fn pn_and_keys(&self) -> Option<((u64, PacketNumber), Keys)> {
        // Serialize generation selection and PN allocation across every sending path.
        let mut journal = self.sent_journal.lock_guard();
        let keys = match self.keys.get() {
            Ok(keys) => keys,
            Err(crate::keys::PacketError::Retired(_)) => return None,
            result => result.expect("不可能达到上限，忽略这种错误就行了"),
        };
        let pn = journal
            .next_pn()
            .expect("不可能达到上限，忽略这种错误就行了");
        Some((pn, Keys::Short(keys)))
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
    fn probe_size(&self, dcid: ConnectionId) -> Option<usize> {
        if self.keys.is_retired() {
            return None;
        }
        let header = OneRttHeader::new(Default::default(), dcid);
        Some(super::probe_size(
            &header,
            self.sent_journal.lock_guard().next_pn_len(),
            self.keys.tag_len(),
        ))
    }

    fn packet(&self, dcid: ConnectionId) -> Option<Packet> {
        let header = OneRttHeader::new(Default::default(), dcid);
        let (pn, keys) = self.pn_and_keys()?;
        Some(Packet::new(DataHeader::Short(header), pn, keys))
    }

    #[allow(clippy::too_many_arguments)]
    fn poll_dump(
        &self,
        cx: &mut Context<'_>,
        cc: &ArcCC,
        dcid: ConnectionId,
        datagram: &mut Cursor<&mut [u8]>,
        packet_content: PacketContent,
        frames: &mut Vec<GuaranteedFrame>,
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
    ) -> Poll<(Option<Packet>, usize)> {
        if !self.sent_journal().has_capacity() {
            return Poll::Ready((None, 0));
        }
        let Some(mut packet) = self.packet(dcid) else {
            return Poll::Ready((None, 0));
        };
        let start = frames.len();
        let offset = datagram.position() as usize;
        let quota = cc
            .send_quota()
            .max(if cc.need_send_ack_eliciting(self.epoch()) > 0 {
                1200
            } else {
                0
            });
        let mut crypto = self.crypto().outgoing();
        let mut reliable = self.reliable_frames.clone();
        let mut streams = self.streams.clone();
        let mut sources: SmallVec<[&mut dyn Package<&mut [u8]>; 12]> = external
            .iter_mut()
            .map(|source| &mut **source as &mut dyn Package<&mut [u8]>)
            .collect();
        sources.push(&mut crypto);
        sources.push(&mut reliable);
        sources.push(&mut streams);
        let result = packet.assemble(cx, datagram, quota, packet_content, frames, &mut sources);
        drop(sources);
        match result {
            Poll::Ready((mut size, min_size)) if size > 0 => {
                let padlen = min_size.saturating_sub(size);
                size += packet.padding(&mut datagram.get_mut()[offset..], padlen);
                datagram.set_position((offset + size) as u64);
                Poll::Ready((Some(packet), size))
            }
            result => {
                self.cancel(packet.pn.0, &mut frames.drain(start..));
                result.map(|_| (None, 0))
            }
        }
    }
}
