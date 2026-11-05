//! Packet-number spaces and recovery feedback. No parent connection back-reference.
use std::{
    any::Any,
    ops::Deref,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use qbase::{
    Epoch,
    cid::ConnectionId,
    frame::AckFrame,
    handshake::HandshakeFacts,
    net::tx::UnregisterWaker,
    packet::{
        GetType, HeaderSize, PacketNumber, Type,
        assemble::{Constraints, Metadata, Package},
    },
    time::heartbeat::ArcHeartbeat,
};
use qevent::quic::recovery::PacketLostTrigger;
use qrecovery::{
    crypto::CryptoStream,
    journal::{AckPackege, ArcRcvdJournal, ArcSentJournal},
};
use smallvec::SmallVec;
use tokio::time::Instant;

use crate::{Error, GuaranteedFrame, keys::ArcKeys, packet::assemble::Packet};

pub mod assemble;
pub mod data;
pub mod handshake;
pub mod initial;

pub use assemble::{ArcSpaces, Spaces};
pub use data::DataSpace;
pub use handshake::HandshakeSpace;
pub use initial::InitialSpace;

pub use crate::keys::Keys;

#[derive(Clone)]
pub struct Space<K> {
    pub initial_scid: ConnectionId,
    pub epoch: Epoch,
    pub keys: K,
    pub crypto: CryptoStream,
    pub sent_journal: ArcSentJournal,
    pub rcvd_journal: ArcRcvdJournal,
}

impl<K> AsRef<Space<K>> for Space<K> {
    fn as_ref(&self) -> &Space<K> {
        self
    }
}

impl<K> Space<K> {
    /// Create a packet-number space with ready keys.
    pub fn new(
        epoch: Epoch,
        initial_scid: ConnectionId,
        keys: K,
        facts: Arc<HandshakeFacts>,
    ) -> Self {
        Self {
            initial_scid,
            epoch,
            keys,
            crypto: CryptoStream::with_facts(facts),
            sent_journal: ArcSentJournal::default(),
            rcvd_journal: ArcRcvdJournal::with_capacity(0, None),
        }
    }

    /// Reserve a packet number before assembly.
    pub fn next_pn(&self) -> Result<(u64, PacketNumber), Error> {
        self.sent_journal.next_pn()
    }

    /// Start recovery timers after successful submission, under the path's CC lock.
    pub fn on_sent(
        &self,
        pn: u64,
        in_flight: bool,
        retransmit_after: Duration,
        retention: Duration,
    ) {
        self.sent_journal
            .on_sent(pn, in_flight, retransmit_after, retention);
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
        if self.keys.get().is_ok() {
            self.sent_journal.resend(pns, |frame| self.recover(frame));
        }
    }
}

impl Allocate for Space<ArcKeys> {
    fn pn_and_keys(&self) -> Result<Option<((u64, PacketNumber), Keys)>, Error> {
        let Ok(keys) = self.keys.get() else {
            return Ok(None);
        };
        Ok(Some((self.next_pn()?, Keys::Long(keys))))
    }
}

impl<K> UnregisterWaker for Space<K> {
    fn unregister(&self, waker: &Waker) {
        self.crypto.outgoing().unregister(waker);
        self.rcvd_journal.unregister(waker);
    }
}

impl<K: Clone> Recover for Space<ArcKeys<K>> {
    fn on_acked(&self, ack: &AckFrame) -> Result<Option<u64>, Error> {
        self.sent_journal.on_acked(ack, |frame| {
            if let GuaranteedFrame::Crypto(frame) = frame {
                self.crypto.outgoing().on_data_acked(frame);
            }
        })
    }

    fn recover(&self, frame: &GuaranteedFrame) {
        Space::recover(self, frame);
    }

    fn cancel(&self, pn: u64, frames: &mut dyn Iterator<Item = GuaranteedFrame>) {
        for frame in frames {
            self.recover(&frame);
        }
        Space::cancel(self, pn);
    }

    fn on_tick(&self, now: Instant) {
        Space::on_tick(self, now);
    }

    fn retire(&self) {
        Space::retire(self);
    }
}

/// Recovery and retirement of a space's own frame sources.
pub trait Recover {
    /// Release acknowledged frames and return the highest acknowledged key generation.
    fn on_acked(&self, ack: &AckFrame) -> Result<Option<u64>, Error>;
    fn recover(&self, frame: &GuaranteedFrame);
    fn cancel(&self, pn: u64, frames: &mut dyn Iterator<Item = GuaranteedFrame>);
    fn on_tick(&self, now: Instant);
    fn retire(&self);
}

/// Reserve a packet number together with its fixed key generation.
pub trait Allocate {
    /// Returns `None` when the space's keys have been retired.
    #[allow(clippy::type_complexity)]
    fn pn_and_keys(&self) -> Result<Option<((u64, PacketNumber), Keys)>, Error>;
}

impl<T: Deref> Allocate for T
where
    T::Target: Allocate,
{
    fn pn_and_keys(&self) -> Result<Option<((u64, PacketNumber), Keys)>, Error> {
        self.deref().pn_and_keys()
    }
}

impl<K> Transmit for Space<K>
where
    K: Any + Send + Sync,
    Self: Allocate + Recover,
{
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
        Space::on_sent(self, pn, in_flight, retransmit_after, retention)
    }
}

/// Shared packet-number, key reservation and journal operations.
pub trait Transmit: Allocate + Recover + UnregisterWaker + Any + Send + Sync {
    fn epoch(&self) -> Epoch;

    fn crypto(&self) -> &CryptoStream;

    fn sent_journal(&self) -> &ArcSentJournal;

    fn rcvd_journal(&self) -> &ArcRcvdJournal;

    /// Commit one packet under the sending path's CC lock, then account it on that path.
    fn on_sent(&self, pn: u64, in_flight: bool, retransmit_after: Duration, retention: Duration);

    fn on_sealed(
        &self,
        pn: u64,
        generation: Option<u64>,
        pktlen: usize,
        meta: Metadata,
        frames: &mut dyn Iterator<Item = GuaranteedFrame>,
    ) {
        self.sent_journal()
            .on_sealed(pn, generation, pktlen, meta, frames);
    }
}

impl<T> Transmit for T
where
    T: Deref + Recover + UnregisterWaker + Any + Send + Sync,
    T::Target: Transmit,
{
    fn epoch(&self) -> Epoch {
        self.deref().epoch()
    }

    fn crypto(&self) -> &CryptoStream {
        self.deref().crypto()
    }

    fn sent_journal(&self) -> &ArcSentJournal {
        self.deref().sent_journal()
    }

    fn rcvd_journal(&self) -> &ArcRcvdJournal {
        self.deref().rcvd_journal()
    }

    fn on_sent(&self, pn: u64, in_flight: bool, retransmit_after: Duration, retention: Duration) {
        self.deref()
            .on_sent(pn, in_flight, retransmit_after, retention)
    }
}

/// Space-specific packet header and frame assembly.
pub trait Encapsulate: Transmit {
    fn probe_size(&self, dcid: ConnectionId) -> Option<usize>;

    fn packet(&self, dcid: ConnectionId) -> Result<Option<Packet>, Error>;

    fn poll_dump(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        limits: &mut Constraints,
        bytes: &mut [u8],
        frames: &mut Vec<GuaranteedFrame>,
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
    ) -> Poll<Result<(Option<Packet>, usize), Error>> {
        if !self.sent_journal().has_capacity() {
            return Poll::Ready(Ok((None, 0)));
        }
        let Some(mut packet) = self.packet(dcid)? else {
            return Poll::Ready(Ok((None, 0)));
        };
        let start = frames.len();
        let mut crypto = self.crypto().outgoing();
        let mut sources: SmallVec<[&mut dyn Package<&mut [u8]>; 12]> = external
            .iter_mut()
            .map(|source| &mut **source as &mut dyn Package<&mut [u8]>)
            .collect();
        sources.push(&mut crypto);
        let mut writer = &mut bytes[..];
        match packet.assemble(cx, &mut writer, limits, frames, &mut sources) {
            Poll::Ready(Ok(size)) if size > 0 => Poll::Ready(Ok((Some(packet), size))),
            result => {
                self.cancel(packet.pn.0, &mut frames.drain(start..));
                result.map(|result| result.map(|_| (None, 0)))
            }
        }
    }

    /// Assemble only the space ACK and the path heartbeat.
    fn poll_ping(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        limits: &mut Constraints,
        bytes: &mut [u8],
        heartbeat: &mut ArcHeartbeat,
        ack: &mut Option<AckPackege<'_>>,
        frames: &mut Vec<GuaranteedFrame>,
    ) -> Poll<Result<(Option<Packet>, usize), Error>> {
        if !self.sent_journal().has_capacity() {
            return Poll::Ready(Ok((None, 0)));
        }
        let Some(mut packet) = self.packet(dcid)? else {
            return Poll::Ready(Ok((None, 0)));
        };
        let start = frames.len();
        let mut sources: [&mut dyn Package<&mut [u8]>; 2] = [ack, heartbeat];
        let mut writer = &mut bytes[..];
        match packet.assemble(cx, &mut writer, limits, frames, &mut sources) {
            Poll::Ready(Ok(size)) if size > 0 => Poll::Ready(Ok((Some(packet), size))),
            result => {
                self.cancel(packet.pn.0, &mut frames.drain(start..));
                result.map(|result| result.map(|_| (None, 0)))
            }
        }
    }
}

fn probe_size(header: &(impl HeaderSize + GetType), pn_len: usize, tag_len: usize) -> usize {
    let pn_offset = header.size() + usize::from(matches!(header.get_type(), Type::Long(_))) * 2;
    // A PING occupies one byte. Header protection also needs a full sample.
    (pn_offset + pn_len + 1 + tag_len).max(pn_offset + 4 + 16)
}

fn packet_error(error: crate::keys::PacketError) -> Error {
    match error {
        crate::keys::PacketError::Connection(error) => error,
        error => qbase::error::QuicError::with_default_fty(
            qbase::error::ErrorKind::Internal,
            error.to_string(),
        )
        .into(),
    }
}
