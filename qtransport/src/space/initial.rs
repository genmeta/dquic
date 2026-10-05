//! Initial packet-number space and token-bearing headers.
use std::task::{Context, Poll, Waker};

use derive_more::Deref;
use qbase::{
    Epoch,
    cid::ConnectionId,
    frame::AckFrame,
    net::tx::UnregisterWaker,
    packet::{
        LongHeaderBuilder, PacketNumber,
        assemble::{PacketBuffer, Package},
    },
};
use qevent::quic::recovery::PacketLostTrigger;
use tokio::time::Instant;

use super::{Encapsulate, Recover, Space, dump_sources};
use crate::{Error, GuaranteedFrame, keys::ArcKeys};

/// Initial headers retain their token across every packet in this space.
#[derive(Deref)]
pub struct InitialSpace {
    #[deref]
    pub space: Space<ArcKeys>,
    pub token: Option<Vec<u8>>,
}

impl InitialSpace {
    pub fn new(initial_scid: ConnectionId, keys: ArcKeys, token: Option<Vec<u8>>) -> Self {
        Self {
            space: Space::new(Epoch::Initial, initial_scid, keys),
            token,
        }
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
    fn encapsulate(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        pn: (u64, PacketNumber),
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
        buffer: &mut PacketBuffer<'_, &mut [u8]>,
        min_size: Option<usize>,
        multipath: bool,
    ) -> Poll<Result<usize, Error>> {
        let header = LongHeaderBuilder::with_cid(dcid, self.initial_scid)
            .initial(self.token.clone().unwrap_or_default());
        if !buffer.begin(&header, pn.1, min_size) {
            return Poll::Ready(Ok(0));
        }
        let start = buffer.meta.nframes;
        if let Poll::Ready(Err(error)) = dump_sources(cx, buffer, external, start) {
            return Poll::Ready(Err(error));
        }
        let mut outgoing = self.crypto.outgoing();
        let mut replay = self.crypto.multipath();
        let crypto: &mut dyn for<'b> Package<&'b mut [u8]> = if multipath {
            &mut replay
        } else {
            &mut outgoing
        };
        dump_sources(cx, buffer, &mut [crypto], start)
    }
}
