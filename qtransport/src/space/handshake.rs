//! Handshake packet-number space.
use std::{
    sync::{Arc, atomic::AtomicBool},
    task::{Context, Poll, Waker},
};

use derive_more::Deref;
use qbase::{
    Epoch,
    cid::ConnectionId,
    frame::AckFrame,
    net::tx::UnregisterWaker,
    packet::{
        LongHeaderBuilder, PacketNumber,
        assemble::{Assemble, Package, PacketBuffer},
    },
};
use qevent::quic::recovery::PacketLostTrigger;
use smallvec::SmallVec;
use tokio::time::Instant;

use super::{Encapsulate, Recover, Space};
use crate::{
    Error, GuaranteedFrame,
    keys::{ArcKeys, Seal},
};

/// Handshake headers carry no token or application-data sources.
#[derive(Deref)]
pub struct HandshakeSpace<K = ArcKeys>(pub Space<K>);

impl<K> HandshakeSpace<K> {
    pub fn new(initial_scid: ConnectionId, keys: K, is_mp_handshaking: Arc<AtomicBool>) -> Self {
        Self(Space::new(
            Epoch::Handshake,
            initial_scid,
            keys,
            is_mp_handshaking,
        ))
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

    fn encapsulate(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        pn: (u64, PacketNumber),
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
        buffer: &mut PacketBuffer<'_, &mut [u8]>,
        min_size: Option<usize>,
    ) -> Poll<Result<usize, Error>> {
        let header = LongHeaderBuilder::with_cid(dcid, self.initial_scid).handshake();
        if !buffer.begin(&header, pn.1, min_size) {
            return Poll::Ready(Ok(0));
        }
        let mut crypto = self.crypto.outgoing();
        let crypto: &mut dyn for<'b> Package<&'b mut [u8]> = &mut crypto;
        let mut sources: SmallVec<[&mut dyn Package<&mut [u8]>; 12]> = external
            .iter_mut()
            .map(|source| &mut **source as &mut dyn Package<&mut [u8]>)
            .chain([crypto as &mut dyn Package<&mut [u8]>])
            .collect();
        buffer.assemble(cx, &mut sources)
    }
}
