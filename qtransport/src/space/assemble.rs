//! Ordered packet-number spaces and recursive datagram assembly.
use std::{
    any::Any,
    io::Cursor,
    sync::Arc,
    task::{Context, Poll},
};

use qbase::{
    Epoch,
    cid::ConnectionId,
    frame::GuaranteedFrame,
    packet::assemble::{Metadata, Package},
    time::heartbeat::ArcHeartbeat,
    util::{ArcIndexDeque, IndexDeque},
};
use qcongestion::ArcCC;
use qrecovery::journal::AckPackege;
use smallvec::SmallVec;

use super::Encapsulate;

pub struct Spaces(pub IndexDeque<Arc<dyn Encapsulate>, 2>);
pub type ArcSpaces = ArcIndexDeque<Arc<dyn Encapsulate>, 2>;

impl Spaces {
    #[allow(clippy::too_many_arguments)]
    pub fn poll_dump(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        cc: &ArcCC,
        bytes: &mut Cursor<&mut [u8]>,
        frames: &mut Vec<GuaranteedFrame>,
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
    ) -> (usize, SmallVec<[Metadata; 1]>) {
        self.poll_dump_at(cx, cc, dcid, 0, bytes, None, frames, external)
    }

    #[allow(clippy::too_many_arguments)]
    fn poll_dump_at(
        &self,
        cx: &mut Context<'_>,
        cc: &ArcCC,
        dcid: ConnectionId,
        level: u64,
        datagram: &mut Cursor<&mut [u8]>,
        min_size: Option<usize>,
        frames: &mut Vec<GuaranteedFrame>,
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
    ) -> (usize, SmallVec<[Metadata; 1]>) {
        if level > Epoch::Data as u64 {
            return (0, SmallVec::new());
        }
        match self.0.get(level) {
            None => self.poll_dump_at(
                cx,
                cc,
                dcid,
                level + 1,
                datagram,
                min_size,
                frames,
                external,
            ),
            Some(space) => {
                let start = frames.len();
                let offset = datagram.position() as usize;
                let (packet, mut pktlen) =
                    match space.poll_dump(cx, cc, dcid, datagram, frames, external) {
                        Poll::Ready(result) => result,
                        Poll::Pending => (None, 0),
                    };
                let has_initial_packet = pktlen > 0 && level == Epoch::Initial as u64;
                let min_size = Self::adjust_min_size(min_size, has_initial_packet);
                let (n, mut packets) = self.poll_dump_at(
                    cx,
                    cc,
                    dcid,
                    level + 1,
                    datagram,
                    min_size.map(|size| size.saturating_sub(pktlen)),
                    frames,
                    external,
                );
                match packet {
                    None => (n, packets),
                    Some(mut packet) => {
                        if n == 0 {
                            let padlen = min_size.unwrap_or(0).saturating_sub(pktlen);
                            pktlen += packet.padding(&mut datagram.get_mut()[offset..], padlen);
                            datagram.set_position((offset + pktlen) as u64);
                        }
                        let generation =
                            packet.seal(&mut datagram.get_mut()[offset..offset + pktlen]);
                        space.on_sealed(
                            packet.pn.0,
                            generation,
                            pktlen,
                            packet.meta,
                            &mut frames.drain(start..),
                        );
                        packets.insert(0, packet.meta);
                        (pktlen + n, packets)
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn poll_ping(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        cc: &ArcCC,
        bytes: &mut Cursor<&mut [u8]>,
        frames: &mut Vec<GuaranteedFrame>,
        heartbeat: &mut ArcHeartbeat,
        acks: &mut [(Epoch, Option<AckPackege<'_>>); 3],
    ) -> (usize, SmallVec<[Metadata; 1]>) {
        self.poll_ping_at(cx, dcid, cc, 0, None, bytes, frames, heartbeat, acks)
    }

    #[allow(clippy::too_many_arguments)]
    fn poll_ping_at(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        cc: &ArcCC,
        level: u64,
        min_size: Option<usize>,
        bytes: &mut Cursor<&mut [u8]>,
        frames: &mut Vec<GuaranteedFrame>,
        heartbeat: &mut ArcHeartbeat,
        acks: &mut [(Epoch, Option<AckPackege<'_>>); 3],
    ) -> (usize, SmallVec<[Metadata; 1]>) {
        if level > Epoch::Data as u64 {
            return (0, SmallVec::new());
        }
        match self.0.get(level) {
            None => self.poll_ping_at(
                cx,
                dcid,
                cc,
                level + 1,
                min_size,
                bytes,
                frames,
                heartbeat,
                acks,
            ),
            Some(space) => {
                let start = frames.len();
                let offset = bytes.position() as usize;
                let (packet, mut pktlen) = match space.poll_ping(
                    cx,
                    dcid,
                    cc,
                    bytes,
                    frames,
                    heartbeat,
                    &mut acks[level as usize].1,
                ) {
                    Poll::Ready(result) => result,
                    Poll::Pending => (None, 0),
                };
                let has_initial_packet = pktlen > 0 && level == Epoch::Initial as u64;
                let min_size = Self::adjust_min_size(min_size, has_initial_packet);
                let (n, mut packets) = self.poll_ping_at(
                    cx,
                    dcid,
                    cc,
                    level + 1,
                    min_size.map(|size| size.saturating_sub(pktlen)),
                    bytes,
                    frames,
                    heartbeat,
                    acks,
                );
                match packet {
                    None => (n, packets),
                    Some(mut packet) => {
                        if n == 0 {
                            let padlen = min_size.unwrap_or(0).saturating_sub(pktlen);
                            pktlen += packet.padding(&mut bytes.get_mut()[offset..], padlen);
                            bytes.set_position((offset + pktlen) as u64);
                        }
                        let generation = packet.seal(&mut bytes.get_mut()[offset..offset + pktlen]);
                        space.on_sealed(
                            packet.pn.0,
                            generation,
                            pktlen,
                            packet.meta,
                            &mut frames.drain(start..),
                        );
                        packets.insert(0, packet.meta);
                        (pktlen + n, packets)
                    }
                }
            }
        }
    }

    fn adjust_min_size(min_size: Option<usize>, has_initial_packet: bool) -> Option<usize> {
        has_initial_packet.then_some(1200).or(min_size)
    }

    /// Obtain a concrete handle when starting a receiver or encoding a probe.
    pub fn get<T: Encapsulate>(
        spaces: &IndexDeque<Arc<dyn Encapsulate>, 2>,
        epoch: Epoch,
    ) -> Option<Arc<T>> {
        let space: Arc<dyn Any + Send + Sync> = spaces.get(epoch as u64)?.clone();
        space.downcast().ok()
    }
}
