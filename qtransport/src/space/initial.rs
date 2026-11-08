//! Initial packet-number space and token-bearing headers.
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
use crate::{Error, GuaranteedFrame, keys::ArcKeys, packet::encrypt::Packet};

/// Initial headers retain their token across every packet in this space.
#[derive(Deref)]
pub struct InitialSpace {
    #[deref]
    pub space: Space<ArcKeys>,
    pub token: Option<Vec<u8>>,
}

impl InitialSpace {
    pub fn new(initial_scid: ConnectionId, keys: ArcKeys, token: Option<Vec<u8>>, facts: Arc<HandshakeFacts>) -> Self {
        Self { space: Space::new(Epoch::Initial, initial_scid, keys, facts), token }
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
    fn packet(&self, dcid: ConnectionId) -> Option<Packet> {
        let header = LongHeaderBuilder::with_cid(dcid, self.initial_scid).initial(self.token.clone().unwrap_or_default());
        let (pn, keys) = self.pn_and_keys()?;
        Some(Packet::new(DataHeader::Long(header.into()), pn, keys))
    }
}
