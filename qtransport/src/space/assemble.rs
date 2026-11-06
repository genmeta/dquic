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
    packet::assemble::{Constraints as PacketLimits, Metadata, Package},
    time::heartbeat::ArcHeartbeat,
    util::{ArcIndexDeque, IndexDeque},
};
use qrecovery::journal::AckPackege;
use smallvec::SmallVec;

use super::Encapsulate;
use crate::Error;

/// Balances reserved once for a burst. Packet bounds belong to its slice and recursion.
#[derive(Clone, Default)]
pub struct Constraints {
    pub send_quota: usize,
    pub credit: usize,
    pub probe_quota: [usize; 3],
    /// Datagram envelope bytes, charged once when a datagram is assembled.
    pub overhead: usize,
}

pub struct Spaces(pub IndexDeque<Arc<dyn Encapsulate>, 2>);
pub type ArcSpaces = ArcIndexDeque<Arc<dyn Encapsulate>, 2>;

impl Spaces {
    pub fn poll_dump(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        bytes: &mut [u8],
        limits: &mut Constraints,
        frames: &mut Vec<GuaranteedFrame>,
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
    ) -> Result<(usize, SmallVec<[Metadata; 1]>), Error> {
        let credit = limits.credit.saturating_sub(limits.overhead);
        if credit == 0 {
            return Ok((0, SmallVec::new()));
        }
        let send_quota = limits.send_quota.saturating_sub(limits.overhead);
        let probe_quota = limits
            .probe_quota
            .map(|quota| quota.saturating_sub(limits.overhead));
        let quota = if send_quota > 0 {
            send_quota
        } else {
            probe_quota.into_iter().max().unwrap_or(0)
        };
        let capacity = bytes
            .len()
            .min(credit)
            .min(if quota == 0 { 1200 } else { quota.min(1200) });
        let packet_limits = Epoch::EPOCHS.map(|epoch| PacketLimits {
            send_quota,
            probe_quota: probe_quota[epoch],
            credit,
            max_size: if epoch == Epoch::Initial
                && (capacity < 1200 || send_quota.max(probe_quota[epoch]) < 1200)
            {
                0
            } else {
                1200
            },
            ..Default::default()
        });
        let (mut size, mut packets) = {
            let mut datagram = Cursor::new(&mut bytes[..capacity]);
            self.poll_dump_at(
                cx,
                0,
                None,
                dcid,
                &mut datagram,
                &packet_limits,
                frames,
                external,
            )?
        };
        // A small payload window must not trap ACKs or an available PTO probe.
        let control_capacity = bytes.len().min(credit).min(1200);
        if size == 0 && control_capacity > capacity {
            let capacity = control_capacity;
            let mut packet_limits = packet_limits.map(|mut limits| {
                limits.send_quota = 0;
                limits.max_size = 1200;
                limits
            });
            if capacity < 1200 || packet_limits[Epoch::Initial].probe_quota < 1200 {
                packet_limits[Epoch::Initial].max_size = 0;
            }
            let mut datagram = Cursor::new(&mut bytes[..capacity]);
            (size, packets) = self.poll_dump_at(
                cx,
                0,
                None,
                dcid,
                &mut datagram,
                &packet_limits,
                frames,
                external,
            )?;
        }
        if size > 0 {
            limits.credit -= size + limits.overhead;
            let in_flight: usize = packets
                .iter()
                .filter(|meta| meta.in_flight)
                .map(|meta| meta.pktlen)
                .sum();
            if in_flight > 0 {
                limits.send_quota = limits
                    .send_quota
                    .saturating_sub(in_flight + limits.overhead);
            }
            for meta in &packets {
                limits.probe_quota[meta.epoch()] = 0;
            }
        }
        Ok((size, packets))
    }

    #[allow(clippy::too_many_arguments)]
    fn poll_dump_at(
        &self,
        cx: &mut Context<'_>,
        level: u64,
        min_size: Option<usize>,
        dcid: ConnectionId,
        bytes: &mut Cursor<&mut [u8]>,
        limits: &[PacketLimits; 3],
        frames: &mut Vec<GuaranteedFrame>,
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
    ) -> Result<(usize, SmallVec<[Metadata; 1]>), Error> {
        if level > Epoch::Data as u64 {
            return Ok((0, SmallVec::new()));
        }
        match self.0.get(level) {
            None => self.poll_dump_at(
                cx,
                level + 1,
                min_size,
                dcid,
                bytes,
                limits,
                frames,
                external,
            ),
            Some(space) => {
                let start = frames.len();
                let offset = bytes.position() as usize;
                let (mut packet, pktlen) = match space.poll_dump(
                    cx,
                    dcid,
                    &limits[level as usize],
                    bytes,
                    frames,
                    external,
                ) {
                    Poll::Ready(result) => result?,
                    Poll::Pending => (None, 0),
                };
                let min_size = if pktlen != 0 && level == Epoch::Initial as u64 {
                    Some(1200)
                } else {
                    min_size
                };
                let mut packets = SmallVec::new();
                let result = (|| {
                    bytes.set_position((offset + pktlen) as u64);
                    let (n, following) = self.poll_dump_at(
                        cx,
                        level + 1,
                        min_size.map(|size| size.saturating_sub(pktlen)),
                        dcid,
                        bytes,
                        limits,
                        frames,
                        external,
                    )?;
                    packets = following;
                    let bytes = &mut bytes.get_mut()[offset..];
                    let mut padlen = 0;
                    if let Some(packet) = packet.as_mut() {
                        if pktlen > 0
                            && n == 0
                            && let Some(min_size) = min_size
                        {
                            padlen = packet.padding(bytes, min_size.saturating_sub(pktlen))?;
                        }
                        let generation = packet.seal(&mut bytes[..pktlen + padlen])?;
                        space.on_sealed(
                            packet.pn.0,
                            generation,
                            pktlen + padlen,
                            packet.meta,
                            &mut frames.drain(start..),
                        );
                        packets.insert(0, packet.meta);
                    }
                    Ok(pktlen + n + padlen)
                })();
                if result.is_err() {
                    if let Some(packet) = packet {
                        space.cancel(packet.pn.0, &mut frames.drain(start..));
                    }
                    for meta in packets.drain(..) {
                        let space = self.0.get(meta.epoch() as u64).unwrap();
                        space.cancel(meta.pn, &mut std::iter::empty());
                    }
                }
                result.map(|size| (size, packets))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn poll_ping(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        bytes: &mut [u8],
        limits: &mut Constraints,
        frames: &mut Vec<GuaranteedFrame>,
        heartbeat: &mut ArcHeartbeat,
        acks: &mut [(Epoch, Option<AckPackege<'_>>); 3],
    ) -> Result<(usize, SmallVec<[Metadata; 1]>), Error> {
        let credit = limits.credit.saturating_sub(limits.overhead);
        if credit == 0 {
            return Ok((0, SmallVec::new()));
        }
        let send_quota = limits.send_quota.saturating_sub(limits.overhead);
        let probe_quota = limits
            .probe_quota
            .map(|quota| quota.saturating_sub(limits.overhead));
        let quota = if send_quota > 0 {
            send_quota
        } else {
            probe_quota.into_iter().max().unwrap_or(0)
        };
        let capacity = bytes
            .len()
            .min(credit)
            .min(if quota == 0 { 1200 } else { quota.min(1200) });
        let packet_limits = Epoch::EPOCHS.map(|epoch| PacketLimits {
            send_quota,
            probe_quota: probe_quota[epoch],
            credit,
            max_size: if epoch == Epoch::Initial
                && (capacity < 1200 || send_quota.max(probe_quota[epoch]) < 1200)
            {
                0
            } else {
                1200
            },
            ..Default::default()
        });
        let (mut size, mut packets) = {
            let mut datagram = Cursor::new(&mut bytes[..capacity]);
            self.poll_ping_at(
                cx,
                0,
                None,
                dcid,
                &mut datagram,
                &packet_limits,
                frames,
                heartbeat,
                acks,
            )?
        };
        // A small payload window must not trap ACKs or an available PTO probe.
        let control_capacity = bytes.len().min(credit).min(1200);
        if size == 0 && control_capacity > capacity {
            let capacity = control_capacity;
            let mut packet_limits = packet_limits.map(|mut limits| {
                limits.send_quota = 0;
                limits.max_size = 1200;
                limits
            });
            if capacity < 1200 || packet_limits[Epoch::Initial].probe_quota < 1200 {
                packet_limits[Epoch::Initial].max_size = 0;
            }
            let mut datagram = Cursor::new(&mut bytes[..capacity]);
            (size, packets) = self.poll_ping_at(
                cx,
                0,
                None,
                dcid,
                &mut datagram,
                &packet_limits,
                frames,
                heartbeat,
                acks,
            )?;
        }
        if size > 0 {
            limits.credit -= size + limits.overhead;
            let in_flight: usize = packets
                .iter()
                .filter(|meta| meta.in_flight)
                .map(|meta| meta.pktlen)
                .sum();
            if in_flight > 0 {
                limits.send_quota = limits
                    .send_quota
                    .saturating_sub(in_flight + limits.overhead);
            }
            for meta in &packets {
                limits.probe_quota[meta.epoch()] = 0;
            }
        }
        Ok((size, packets))
    }

    #[allow(clippy::too_many_arguments)]
    fn poll_ping_at(
        &self,
        cx: &mut Context<'_>,
        level: u64,
        min_size: Option<usize>,
        dcid: ConnectionId,
        bytes: &mut Cursor<&mut [u8]>,
        limits: &[PacketLimits; 3],
        frames: &mut Vec<GuaranteedFrame>,
        heartbeat: &mut ArcHeartbeat,
        acks: &mut [(Epoch, Option<AckPackege<'_>>); 3],
    ) -> Result<(usize, SmallVec<[Metadata; 1]>), Error> {
        if level > Epoch::Data as u64 {
            return Ok((0, SmallVec::new()));
        }
        match self.0.get(level) {
            None => self.poll_ping_at(
                cx,
                level + 1,
                min_size,
                dcid,
                bytes,
                limits,
                frames,
                heartbeat,
                acks,
            ),
            Some(space) => {
                let start = frames.len();
                let offset = bytes.position() as usize;
                let (mut packet, pktlen) = match space.poll_ping(
                    cx,
                    dcid,
                    &limits[level as usize],
                    bytes,
                    heartbeat,
                    &mut acks[level as usize].1,
                    frames,
                ) {
                    Poll::Ready(result) => result?,
                    Poll::Pending => (None, 0),
                };
                let min_size = if pktlen != 0 && level == Epoch::Initial as u64 {
                    Some(1200)
                } else {
                    min_size
                };
                let mut packets = SmallVec::new();
                let result = (|| {
                    bytes.set_position((offset + pktlen) as u64);
                    let (n, following) = self.poll_ping_at(
                        cx,
                        level + 1,
                        min_size.map(|size| size.saturating_sub(pktlen)),
                        dcid,
                        bytes,
                        limits,
                        frames,
                        heartbeat,
                        acks,
                    )?;
                    packets = following;
                    let bytes = &mut bytes.get_mut()[offset..];
                    let mut padlen = 0;
                    if let Some(packet) = packet.as_mut() {
                        if pktlen > 0
                            && n == 0
                            && let Some(min_size) = min_size
                        {
                            padlen = packet.padding(bytes, min_size.saturating_sub(pktlen))?;
                        }
                        let generation = packet.seal(&mut bytes[..pktlen + padlen])?;
                        space.on_sealed(
                            packet.pn.0,
                            generation,
                            pktlen + padlen,
                            packet.meta,
                            &mut frames.drain(start..),
                        );
                        packets.insert(0, packet.meta);
                    }
                    Ok(pktlen + n + padlen)
                })();
                if result.is_err() {
                    if let Some(packet) = packet {
                        space.cancel(packet.pn.0, &mut frames.drain(start..));
                    }
                    for meta in packets.drain(..) {
                        let space = self.0.get(meta.epoch() as u64).unwrap();
                        space.cancel(meta.pn, &mut std::iter::empty());
                    }
                }
                result.map(|size| (size, packets))
            }
        }
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
