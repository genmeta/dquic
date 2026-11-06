//! Handshake packet-number space.
use std::{sync::Arc, task::Waker};

use derive_more::Deref;
use qbase::{
    Epoch,
    cid::ConnectionId,
    frame::AckFrame,
    handshake::HandshakeFacts,
    net::tx::UnregisterWaker,
    packet::{DataHeader, LongHeaderBuilder},
};
use qevent::quic::recovery::PacketLostTrigger;
use tokio::time::Instant;

use super::{Allocate, Encapsulate, Recover, Space};
use crate::{
    Error, GuaranteedFrame,
    keys::{ArcKeys, Seal},
    packet::encrypt::Packet,
};

/// Handshake headers carry no token or application-data sources.
#[derive(Deref)]
pub struct HandshakeSpace<K = ArcKeys>(pub Space<K>);

impl<K> HandshakeSpace<K> {
    pub fn new(initial_scid: ConnectionId, keys: K, facts: Arc<HandshakeFacts>) -> Self {
        Self(Space::new(Epoch::Handshake, initial_scid, keys, facts))
    }
}

impl<K> AsRef<Space<K>> for HandshakeSpace<K> {
    fn as_ref(&self) -> &Space<K> {
        &self.0
    }
}

impl<K: Clone + Send> qcongestion::Resend for HandshakeSpace<ArcKeys<K>> {
    fn resend(&self, trigger: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        self.0.resend(trigger, pns);
    }
}

impl<K: Clone> Recover for HandshakeSpace<ArcKeys<K>> {
    fn on_acked(&self, ack: &AckFrame) -> Result<Option<u64>, Error> {
        Recover::on_acked(&self.0, ack)
    }

    fn recover(&self, frame: &GuaranteedFrame) {
        self.0.recover(frame);
    }

    fn retire(&self) {
        self.0.retire();
    }

    fn on_tick(&self, now: Instant) {
        self.0.on_tick(now);
    }

    fn cancel(&self, pn: u64, frames: &mut dyn Iterator<Item = GuaranteedFrame>) {
        Recover::cancel(&self.0, pn, frames);
    }
}

impl<K> UnregisterWaker for HandshakeSpace<K> {
    fn unregister(&self, waker: &Waker) {
        self.0.unregister(waker);
    }
}

impl Encapsulate for HandshakeSpace<ArcKeys> {
    fn probe_size(&self, dcid: ConnectionId) -> Option<usize> {
        let keys = self.keys.get().ok()?;
        let header = LongHeaderBuilder::with_cid(dcid, self.initial_scid).handshake();
        Some(super::probe_size(
            &header,
            self.sent_journal.lock_guard().next_pn_len(),
            keys.sealing.tag_len(),
        ))
    }

    fn packet(&self, dcid: ConnectionId) -> Option<Packet> {
        let header = LongHeaderBuilder::with_cid(dcid, self.initial_scid).handshake();
        let (pn, keys) = self.pn_and_keys()?;
        Some(Packet::new(DataHeader::Long(header.into()), pn, keys))
    }
}
