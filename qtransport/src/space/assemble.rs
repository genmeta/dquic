//! Ordered packet-number spaces and recursive datagram assembly.
use std::{
    any::Any,
    io::Cursor,
    sync::{Arc, RwLock},
    task::{Context, Poll, Waker},
};

use qbase::{
    Epoch,
    cid::ConnectionId,
    frame::GuaranteedFrame,
    net::tx::UnregisterWaker,
    packet::{
        PacketContent,
        assemble::{Metadata, Package},
    },
    util::IndexDeque,
};
use qcongestion::ArcCC;
use smallvec::SmallVec;
use tokio::time::Instant;

use super::Encapsulate;

#[derive(Clone)]
struct Spaces(IndexDeque<Arc<dyn Encapsulate>, 2>);

/// Shared packet-number spaces. Queue membership is accessed through space operations.
#[derive(Clone)]
pub struct ArcSpaces(Arc<RwLock<Spaces>>);

impl Default for ArcSpaces {
    fn default() -> Self {
        Self(Arc::new(RwLock::new(Spaces(IndexDeque::with_capacity(Epoch::count())))))
    }
}

impl ArcSpaces {
    /// Add the next space in epoch order.
    pub fn add(&self, space: Arc<dyn Encapsulate>) {
        self.0.write().unwrap().0.push_back(space).expect("space epoch fits the queue");
    }

    /// Retire spaces through `epoch` and advance the next installation index.
    pub fn retire(&self, epoch: Epoch) {
        let mut spaces = self.0.write().unwrap();
        let end = (epoch as u64 + 1).max(spaces.0.offset());
        let drain_end = end.min(spaces.0.largest());
        spaces.0.drain_to(drain_end).for_each(|space| space.retire());
        spaces.0.reset_offset(end);
    }

    /// Obtain a space handle without retaining the collection lock.
    pub fn get(&self, epoch: Epoch) -> Option<Arc<dyn Encapsulate>> {
        self.0.read().unwrap().0.get(epoch as u64).cloned()
    }

    /// Obtain a concrete handle when starting a receiver or encoding a probe.
    pub fn get_as<T: Encapsulate>(&self, epoch: Epoch) -> Option<Arc<T>> {
        let space: Arc<dyn Any + Send + Sync> = self.get(epoch)?;
        space.downcast().ok()
    }

    fn iter(&self) -> impl Iterator<Item = Arc<dyn Encapsulate>> {
        let spaces: SmallVec<[_; 3]> = self.0.read().unwrap().0.iter().cloned().collect();
        spaces.into_iter()
    }

    /// Drive recovery timers for the installed spaces.
    pub fn on_tick(&self, now: Instant) {
        for space in self.iter() {
            space.on_tick(now);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn poll_dump(
        &self,
        cx: &mut Context<'_>,
        cc: &ArcCC,
        dcid: ConnectionId,
        bytes: &mut Cursor<&mut [u8]>,
        packet_content: PacketContent,
        frames: &mut Vec<GuaranteedFrame>,
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
    ) -> (usize, SmallVec<[Metadata; 1]>) {
        let spaces = self.0.read().unwrap().clone();
        spaces.poll_dump(cx, cc, dcid, bytes, packet_content, frames, external)
    }
}

impl UnregisterWaker for ArcSpaces {
    fn unregister(&self, waker: &Waker) {
        for space in self.iter() {
            space.unregister(waker);
        }
    }
}

impl Spaces {
    #[allow(clippy::too_many_arguments)]
    fn poll_dump(
        &self,
        cx: &mut Context<'_>,
        cc: &ArcCC,
        dcid: ConnectionId,
        bytes: &mut Cursor<&mut [u8]>,
        packet_content: PacketContent,
        frames: &mut Vec<GuaranteedFrame>,
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
    ) -> (usize, SmallVec<[Metadata; 1]>) {
        self.poll_dump_at(cx, cc, dcid, Epoch::Initial, bytes, packet_content, None, frames, external)
    }

    #[allow(clippy::too_many_arguments)]
    fn poll_dump_at(
        &self,
        cx: &mut Context<'_>,
        cc: &ArcCC,
        dcid: ConnectionId,
        epoch: Epoch,
        datagram: &mut Cursor<&mut [u8]>,
        packet_content: PacketContent,
        min_size: Option<usize>,
        frames: &mut Vec<GuaranteedFrame>,
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
    ) -> (usize, SmallVec<[Metadata; 1]>) {
        match self.0.get(epoch as u64) {
            None if epoch == Epoch::Data => (0, SmallVec::new()),
            None => self.poll_dump_at(cx, cc, dcid, epoch.next(), datagram, packet_content, min_size, frames, external),
            Some(space) => {
                let start = frames.len();
                let offset = datagram.position() as usize;
                let (packet, mut pktlen) = match space.poll_dump(cx, cc, dcid, datagram, packet_content, frames, external) {
                    Poll::Ready(result) => result,
                    Poll::Pending => (None, 0),
                };
                let min_size = Self::adjust_min_size(min_size, epoch, pktlen);
                match packet {
                    None if epoch == Epoch::Data => (0, SmallVec::new()),
                    None => self.poll_dump_at(cx, cc, dcid, epoch.next(), datagram, packet_content, min_size, frames, external),
                    Some(mut packet) => {
                        let (n, mut packets) = if epoch == Epoch::Data {
                            (0, SmallVec::new())
                        } else {
                            self.poll_dump_at(cx, cc, dcid, epoch.next(), datagram, packet_content, min_size, frames, external)
                        };
                        if n == 0 {
                            let padlen = min_size.unwrap_or(0);
                            pktlen += packet.padding(&mut datagram.get_mut()[offset..], padlen);
                            datagram.set_position((offset + pktlen) as u64);
                        }
                        let generation = packet.seal(&mut datagram.get_mut()[offset..offset + pktlen]);
                        space.on_sealed(packet.pn.0, generation, pktlen, packet.meta, &mut frames.drain(start..));
                        packets.insert(0, packet.meta);
                        (pktlen + n, packets)
                    }
                }
            }
        }
    }

    fn adjust_min_size(min_size: Option<usize>, epoch: Epoch, pktlen: usize) -> Option<usize> {
        (epoch == Epoch::Initial && pktlen > 0).then_some(1200).or(min_size).map(|size| size.saturating_sub(pktlen))
    }
}
