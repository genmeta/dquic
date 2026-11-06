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
    packet::{
        PacketContent,
        assemble::{Metadata, Package},
    },
    util::{ArcIndexDeque, IndexDeque},
};
use qcongestion::ArcCC;
use smallvec::SmallVec;

use super::Encapsulate;

pub struct Spaces(pub IndexDeque<Arc<dyn Encapsulate>, 2>);
pub type ArcSpaces = ArcIndexDeque<Arc<dyn Encapsulate>, 2>;

impl Spaces {
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
        self.poll_dump_at(cx, cc, dcid, 0, bytes, packet_content, None, frames, external)
    }

    #[allow(clippy::too_many_arguments)]
    fn poll_dump_at(
        &self,
        cx: &mut Context<'_>,
        cc: &ArcCC,
        dcid: ConnectionId,
        level: u64,
        datagram: &mut Cursor<&mut [u8]>,
        packet_content: PacketContent,
        min_size: Option<usize>,
        frames: &mut Vec<GuaranteedFrame>,
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
    ) -> (usize, SmallVec<[Metadata; 1]>) {
        if level > Epoch::Data as u64 {
            return (0, SmallVec::new());
        }
        match self.0.get(level) {
            None => self.poll_dump_at(cx, cc, dcid, level + 1, datagram, packet_content, min_size, frames, external),
            Some(space) => {
                let start = frames.len();
                let offset = datagram.position() as usize;
                let (packet, mut pktlen) = match space.poll_dump(cx, cc, dcid, datagram, packet_content, frames, external) {
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
                    packet_content,
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
                        let generation = packet.seal(&mut datagram.get_mut()[offset..offset + pktlen]);
                        space.on_sealed(packet.pn.0, generation, pktlen, packet.meta, &mut frames.drain(start..));
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
    pub fn get<T: Encapsulate>(spaces: &IndexDeque<Arc<dyn Encapsulate>, 2>, epoch: Epoch) -> Option<Arc<T>> {
        let space: Arc<dyn Any + Send + Sync> = spaces.get(epoch as u64)?.clone();
        space.downcast().ok()
    }
}
