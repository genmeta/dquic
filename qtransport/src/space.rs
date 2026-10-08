//! Packet-number spaces and recovery feedback. No parent connection back-reference.
use std::{
    any::Any,
    ops::Deref,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::BufMut;
use qbase::{
    Epoch,
    cid::ConnectionId,
    frame::AckFrame,
    net::tx::UnregisterWaker,
    packet::{
        LongSpecificBits, PacketNumber, ShortSpecificBits,
        assemble::{Metadata, Package, PacketBuffer},
    },
};
use qevent::quic::recovery::PacketLostTrigger;
use qrecovery::{
    crypto::CryptoStream,
    journal::{ArcRcvdJournal, ArcSentJournal},
};
use tokio::time::Instant;

use crate::{
    Error, GuaranteedFrame,
    keys::{ArcKeys, ArcOneRttKeys, OneRttSealingKey, Seal},
};

pub mod assemble;
pub mod data;
pub mod handshake;
pub mod initial;

pub use assemble::{ArcSpaces, Spaces};
pub use data::DataSpace;
pub use handshake::HandshakeSpace;
pub use initial::InitialSpace;

#[derive(Clone)]
pub struct Space<K> {
    pub initial_scid: ConnectionId,
    pub epoch: Epoch,
    pub keys: K,
    pub crypto: CryptoStream,
    pub sent_journal: ArcSentJournal,
    pub rcvd_journal: ArcRcvdJournal,
}

impl<K> Space<K> {
    /// Create a packet-number space with ready keys.
    pub fn new(epoch: Epoch, initial_scid: ConnectionId, keys: K) -> Self {
        Self {
            initial_scid,
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

    /// Start recovery timers after successful submission, under the path's CC lock.
    pub fn on_sent(&self, pn: u64, in_flight: bool, retransmit_after: Duration, retention: Duration) {
        self.sent_journal.on_sent(pn, in_flight, retransmit_after, retention);
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

impl Allocate for Space<ArcOneRttKeys> {
    fn pn_and_keys(&self) -> Result<Option<((u64, PacketNumber), Keys)>, Error> {
        let Ok(keys) = self.keys.get() else {
            return Ok(None);
        };
        let (pn, keys) = keys
            .reserve(|_| self.next_pn().map_err(Into::into))
            .map_err(packet_error)?;
        Ok(Some((pn, Keys::Short(keys))))
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
    fn fresh_bytes(&self) -> usize {
        0
    }

    /// Count at most the fresh bytes that fit the caller's send allowance.
    fn fresh_bytes_up_to(&self, limit: usize) -> usize {
        self.fresh_bytes().min(limit)
    }
}

/// Reserve a packet number together with its sealing-key snapshot.
pub trait Allocate {
    /// Returns `None` when the space's keys have been retired.
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
        self.deref().on_sent(pn, in_flight, retransmit_after, retention)
    }
}

/// Space-specific packet header and frame assembly.
pub trait Encapsulate: Transmit {
    fn encapsulate(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        pn: (u64, PacketNumber),
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
        buffer: &mut PacketBuffer<'_, &mut [u8]>,
        min_size: Option<usize>,
        multipath: bool,
    ) -> Poll<Result<usize, Error>>;
}

pub enum Keys {
    Long(Arc<qtls::BidirectionalKeys>),
    Short(OneRttSealingKey),
}

impl Keys {
    fn tag_len(&self) -> usize {
        match self {
            Self::Long(keys) => keys.sealing.tag_len(),
            Self::Short(keys) => keys.tag_len(),
        }
    }

    fn seal(
        &self,
        pn: (u64, PacketNumber),
        pn_offset: usize,
        bytes: &mut [u8],
        long: bool,
    ) -> Result<Option<u64>, Error> {
        bytes[0] |= if long {
            *LongSpecificBits::from_pn(&pn.1)
        } else {
            *ShortSpecificBits::from_pn(&pn.1)
        };
        if long {
            let length = bytes.len() - pn_offset;
            (&mut bytes[pn_offset - 2..pn_offset]).put_u16(0x4000 | length as u16);
        }
        let body_offset = pn_offset + pn.1.size();
        match self {
            Self::Long(keys) => keys
                .sealing
                .seal(pn.0, bytes, pn_offset, body_offset, self.tag_len())
                .map(|()| None),
            Self::Short(keys) => keys
                .seal(pn.0, bytes, pn_offset, body_offset, self.tag_len())
                .map(|(generation, _)| Some(generation)),
        }
        .map_err(packet_error)
    }
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
