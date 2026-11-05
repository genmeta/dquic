//! Ordered packet-number spaces and recursive datagram assembly.
use std::{
    any::Any,
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

impl Constraints {
    fn take(&mut self, epoch: Epoch, sent: usize, credit: usize) {
        self.send_quota = self.send_quota.saturating_sub(sent);
        self.probe_quota[epoch] = self.probe_quota[epoch].saturating_sub(sent);
        self.credit -= credit;
    }
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
        packets: &mut [Option<Metadata>; 3],
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
    ) -> Result<usize, Error> {
        self.package(cx, dcid, external, bytes, limits, frames, packets, None)
    }

    pub fn poll_ping(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        heartbeat: &mut ArcHeartbeat,
        acks: &mut [(Epoch, Option<AckPackege<'_>>); 3],
        bytes: &mut [u8],
        limits: &mut Constraints,
        frames: &mut Vec<GuaranteedFrame>,
        packets: &mut [Option<Metadata>; 3],
    ) -> Result<usize, Error> {
        self.package(
            cx,
            dcid,
            &mut [],
            bytes,
            limits,
            frames,
            packets,
            Some((heartbeat, acks)),
        )
    }

    fn package(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
        bytes: &mut [u8],
        limits: &mut Constraints,
        frames: &mut Vec<GuaranteedFrame>,
        packets: &mut [Option<Metadata>; 3],
        mut ping: Option<(&mut ArcHeartbeat, &mut [(Epoch, Option<AckPackege<'_>>); 3])>,
    ) -> Result<usize, Error> {
        if limits.credit <= limits.overhead {
            return Ok(0);
        }
        let mut remaining = limits.clone();
        remaining.credit -= remaining.overhead;
        remaining.send_quota = remaining.send_quota.saturating_sub(remaining.overhead);
        for quota in &mut remaining.probe_quota {
            *quota = quota.saturating_sub(remaining.overhead);
        }
        let start = frames.len();
        let result = self.poll_dump_at(
            0,
            bytes,
            None,
            cx,
            dcid,
            &mut remaining,
            external,
            frames,
            packets,
            &mut ping,
            0,
        );
        match result {
            Ok(size) if size > 0 => {
                if !packets.iter().flatten().any(|meta| meta.in_flight) {
                    remaining.send_quota = limits.send_quota;
                }
                for epoch in Epoch::EPOCHS {
                    if packets[epoch].is_none() {
                        remaining.probe_quota[epoch] = limits.probe_quota[epoch];
                    }
                }
                *limits = remaining;
            }
            Err(_) => {
                for (epoch, space) in self.0.enumerate() {
                    if let Some(meta) = packets[epoch as usize].take() {
                        space.cancel(meta.pn, &mut frames.drain(start..));
                    }
                }
            }
            _ => {}
        }
        result
    }

    fn poll_dump_at(
        &self,
        level: u64,
        bytes: &mut [u8],
        min_size: Option<usize>,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        limits: &mut Constraints,
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
        frames: &mut Vec<GuaranteedFrame>,
        packets: &mut [Option<Metadata>; 3],
        ping: &mut Option<(&mut ArcHeartbeat, &mut [(Epoch, Option<AckPackege<'_>>); 3])>,
        prefix: usize,
    ) -> Result<usize, Error> {
        if level > Epoch::Data as u64 {
            return Ok(0);
        }
        let Some(space) = self.0.get(level) else {
            return self.poll_dump_at(
                level + 1,
                bytes,
                min_size,
                cx,
                dcid,
                limits,
                external,
                frames,
                packets,
                ping,
                prefix,
            );
        };
        let epoch = space.epoch();
        let start = frames.len();
        let mut packet_limits = PacketLimits {
            flow_ctrl: usize::MAX,
            send_quota: limits.send_quota,
            probe_quota: limits.probe_quota[epoch],
            credit: limits.credit,
            min_size: if epoch == Epoch::Initial {
                min_size.unwrap_or(0).max(1200usize.saturating_sub(prefix))
            } else {
                min_size.unwrap_or(0)
            },
            max_size: 1200usize.saturating_sub(prefix),
            ..Default::default()
        };
        let result = match ping {
            Some((heartbeat, acks)) => space.poll_ping(
                cx,
                dcid,
                &mut packet_limits,
                bytes,
                heartbeat,
                &mut acks[epoch].1,
                frames,
            ),
            None => space.poll_dump(cx, dcid, &mut packet_limits, bytes, frames, external),
        };
        let (packet, pktlen) = match result {
            Poll::Ready(result) => result?,
            Poll::Pending => (None, 0),
        };
        let min_size = if pktlen > 0 && epoch == Epoch::Initial {
            Some(1200usize.saturating_sub(prefix))
        } else {
            min_size
        };
        let min_size = if pktlen > 0 {
            Some(min_size.unwrap_or(0).max(packet_limits.min_size))
        } else {
            min_size
        };
        let Some(mut packet) = packet else {
            return self.poll_dump_at(
                level + 1,
                bytes,
                min_size,
                cx,
                dcid,
                limits,
                external,
                frames,
                packets,
                ping,
                prefix,
            );
        };
        let result = (|| {
            let in_flight = packet.meta.in_flight;
            limits.take(epoch, if in_flight { pktlen } else { 0 }, pktlen);
            let n = self.poll_dump_at(
                level + 1,
                &mut bytes[pktlen..],
                min_size.map(|size| size.saturating_sub(pktlen)),
                cx,
                dcid,
                limits,
                external,
                frames,
                packets,
                ping,
                prefix + pktlen,
            )?;
            let mut padlen = 0;
            if pktlen > 0
                && n == 0
                && let Some(min_size) = min_size
            {
                padlen = packet.padding(bytes, min_size.saturating_sub(pktlen))?;
            }
            if padlen > 0 {
                limits.take(
                    epoch,
                    if in_flight { padlen } else { pktlen + padlen },
                    padlen,
                );
            }
            let generation = packet.seal(&mut bytes[..pktlen + padlen])?;
            space.on_sealed(
                packet.pn.0,
                generation,
                pktlen + padlen,
                packet.meta,
                &mut frames.drain(start..),
            );
            packets[epoch] = Some(packet.meta);
            limits.probe_quota[epoch] = 0;
            Ok(pktlen + n + padlen)
        })();
        if result.is_err() {
            space.cancel(packet.pn.0, &mut frames.drain(start..));
        }
        result
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
