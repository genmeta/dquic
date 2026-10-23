//! Initial packet-number space and token-bearing headers.
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

/// Initial headers retain their token across every packet in this space.
#[derive(Deref)]
pub struct InitialSpace {
    #[deref]
    pub space: Space<ArcKeys>,
    pub token: Option<Vec<u8>>,
}

impl InitialSpace {
    pub fn new(
        initial_scid: ConnectionId,
        keys: ArcKeys,
        token: Option<Vec<u8>>,
        is_mp_handshaking: Arc<AtomicBool>,
    ) -> Self {
        Self {
            space: Space::new(Epoch::Initial, initial_scid, keys, is_mp_handshaking),
            token,
        }
    }
}

impl AsRef<Space<ArcKeys>> for InitialSpace {
    fn as_ref(&self) -> &Space<ArcKeys> {
        &self.space
    }
}

impl qcongestion::Resend for InitialSpace {
    fn resend(&self, trigger: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>) {
        self.space.resend(trigger, pns);
    }
}

impl Recover for InitialSpace {
    fn on_acked(&self, ack: &AckFrame) -> Result<Option<u64>, Error> {
        Recover::on_acked(&self.space, ack)
    }

    fn recover(&self, frame: &GuaranteedFrame) {
        self.space.recover(frame);
    }

    fn retire(&self) {
        self.space.retire();
    }

    fn on_tick(&self, now: Instant) {
        self.space.on_tick(now);
    }

    fn cancel(&self, pn: u64, frames: &mut dyn Iterator<Item = GuaranteedFrame>) {
        Recover::cancel(&self.space, pn, frames);
    }
}

impl UnregisterWaker for InitialSpace {
    fn unregister(&self, waker: &Waker) {
        self.space.unregister(waker);
    }
}

impl Encapsulate for InitialSpace {
    fn probe_size(&self, dcid: ConnectionId) -> Option<usize> {
        let keys = self.keys.get().ok()?;
        let header = LongHeaderBuilder::with_cid(dcid, self.initial_scid)
            .initial(self.token.clone().unwrap_or_default());
        Some(
            super::probe_size(
                &header,
                self.sent_journal.lock_guard().next_pn_len(),
                keys.sealing.tag_len(),
            )
            .max(1200),
        )
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
        let header = LongHeaderBuilder::with_cid(dcid, self.initial_scid)
            .initial(self.token.clone().unwrap_or_default());
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
