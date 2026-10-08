//! Ordered packet-number spaces and recursive datagram assembly.
use std::{
    any::Any,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use qbase::{
    Epoch,
    cid::ConnectionId,
    frame::{Frame, GuaranteedFrame, PaddingFrame},
    packet::{
        GetType, OneRttHeader,
        assemble::{Metadata, PacketBuffer, Limit, Package},
    },
    util::IndexDeque,
};

use super::Encapsulate;
use crate::Error;

/// Balances reserved once for a burst. Packet bounds belong to its slice and recursion.
#[derive(Clone, Default)]
pub struct Constraints {
    pub flow_ctrl: usize,
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

struct PacketLimit<'a> {
    shared: &'a mut Constraints,
    epoch: Epoch,
    max_size: usize,
}

impl Limit for PacketLimit<'_> {
    fn flow_ctrl(&self) -> usize {
        self.shared.flow_ctrl
    }
    fn send_quota(&self) -> usize {
        self.shared
            .send_quota
            .max(self.shared.probe_quota[self.epoch])
    }
    fn credit(&self) -> usize {
        self.shared.credit
    }
    fn min_size(&self) -> usize {
        0
    }
    fn max_size(&self) -> usize {
        self.max_size
    }
    fn set_max_size(&mut self, size: usize) {
        self.max_size = size;
    }
    fn fresh(&mut self, amount: usize) {
        self.shared.flow_ctrl -= amount;
    }
    fn take(&mut self, sent: usize, credit: usize) {
        self.shared.take(self.epoch, sent, credit);
    }
}

pub struct Spaces(pub IndexDeque<Arc<dyn Encapsulate>, 2>);
pub type ArcSpaces = Arc<RwLock<Spaces>>;

impl Spaces {
    pub fn package(
        &self,
        cx: &mut Context<'_>,
        dcids: [Option<ConnectionId>; 3],
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
        buffer: &mut [u8],
        limits: &mut Constraints,
        frames: &mut Vec<GuaranteedFrame>,
        packets: &mut [Option<Metadata>; 3],
        multipath: bool,
    ) -> Result<(usize, usize), Error> {
        if limits.credit <= limits.overhead {
            return Ok((0, 0));
        }
        let before = limits.clone();
        limits.credit -= limits.overhead;
        limits.send_quota = limits.send_quota.saturating_sub(limits.overhead);
        for quota in &mut limits.probe_quota {
            *quota = quota.saturating_sub(limits.overhead);
        }
        let start = frames.len();
        let result = self.package_at(
            self.0.offset(),
            cx,
            dcids,
            external,
            buffer,
            limits,
            frames,
            packets,
            multipath,
            0,
            None,
        );
        if result.is_err() {
            for (index, space) in self.0.enumerate() {
                if let Some(meta) = packets[index as usize].take() {
                    space.cancel(
                        meta.pn,
                        &mut frames.drain(start..),
                    );
                }
            }
        }
        match result {
            Ok((size, nframes, flight)) if size > 0 => {
                if !flight {
                    limits.send_quota = before.send_quota;
                }
                for epoch in qbase::Epoch::EPOCHS {
                    if packets[epoch].is_none() {
                        limits.probe_quota[epoch] = before.probe_quota[epoch];
                    }
                }
                Ok((size, nframes))
            }
            result => {
                // Consumed STREAM bytes are recovered as retransmissions, not fresh data.
                let fresh = limits.flow_ctrl;
                *limits = before;
                limits.flow_ctrl = fresh;
                result.map(|_| (0, 0))
            }
        }
    }

    fn package_at(
        &self,
        index: u64,
        cx: &mut Context<'_>,
        dcids: [Option<ConnectionId>; 3],
        external: &mut [&mut dyn for<'b> Package<&'b mut [u8]>],
        buffer: &mut [u8],
        limits: &mut Constraints,
        frames: &mut Vec<GuaranteedFrame>,
        packets: &mut [Option<Metadata>; 3],
        multipath: bool,
        prefix: usize,
        min_bytes: Option<usize>,
    ) -> Result<(usize, usize, bool), Error> {
        let Some(space) = self.0.get(index) else {
            return Ok((0, 0, false));
        };
        let epoch = space.epoch();
        let reserved = match dcids[epoch] {
            Some(dcid) if space.sent_journal().has_capacity() => {
                space.pn_and_keys()?.map(|(pn, keys)| (dcid, pn, keys))
            }
            _ => None,
        };
        let Some((dcid, pn, keys)) = reserved else {
            return self.package_at(
                index + 1,
                cx,
                dcids,
                external,
                buffer,
                limits,
                frames,
                packets,
                multipath,
                prefix,
                min_bytes,
            );
        };
        let start = frames.len();
        let required = if epoch == Epoch::Initial {
            Some(min_bytes.unwrap_or(0).max(1200usize.saturating_sub(prefix)))
        } else {
            min_bytes
        };
        let tag = keys.tag_len();
        let (result, pn_offset, cursor, mut meta, required) = {
            let mut limit = PacketLimit {
                shared: limits,
                epoch,
                max_size: buffer.len().min(16383),
            };
            let mut writer = &mut buffer[..];
            let mut constrained = PacketBuffer::new(
                &mut writer,
                &mut limit,
                frames,
                OneRttHeader::new(Default::default(), dcid).get_type(),
                0,
                tag,
            );
            constrained.meta.pn = pn.0;
            // RFC 9000 Sections 8.2.1 and 8.2.2 require datagrams containing
            // PATH_CHALLENGE or PATH_RESPONSE to be at least 1200 bytes, except
            // when the path's anti-amplification limit prevents expansion.
            // Congestion limits are enforced separately by PacketBuffer (RFC 9000
            // Section 8.2.2 and RFC 9002 Section 7, including its PTO/recovery exceptions).
            let validation_min_size = 1200usize.saturating_sub(prefix);
            constrained.scope(if constrained.limits.credit() >= validation_min_size {
                validation_min_size
            } else {
                0
            });
            let result = space.encapsulate(
                cx,
                dcid,
                pn,
                external,
                &mut constrained,
                required,
                multipath,
            );
            (
                result,
                constrained.pn_offset(),
                constrained.written(),
                constrained.meta,
                constrained.min_size(),
            )
        };
        match result {
            Poll::Ready(Err(error)) => {
                space.cancel(
                    pn.0,
                    &mut frames.drain(start..),
                );
                return Err(error);
            }
            Poll::Ready(Ok(n)) if n > 0 => {}
            _ => {
                space.cancel(
                    pn.0,
                    &mut frames.drain(start..),
                );
                return self.package_at(
                    index + 1,
                    cx,
                    dcids,
                    external,
                    buffer,
                    limits,
                    frames,
                    packets,
                    multipath,
                    prefix,
                    min_bytes,
                );
            }
        }
        let size = (cursor + tag).max(pn_offset + 4 + 16);
        if size > cursor + tag {
            buffer[cursor..size - tag].fill(0);
            meta.record(&Frame::Padding(PaddingFrame));
        }
        let flight = meta.in_flight;
        limits.take(epoch, if flight { size } else { 0 }, size);
        let tail = self.package_at(
            index + 1,
            cx,
            dcids,
            external,
            &mut buffer[size..],
            limits,
            frames,
            packets,
            multipath,
            prefix + size,
            Some(required.saturating_sub(size)).filter(|&min| min != 0),
        );
        let (tail_size, tail_frames, tail_flight) = match tail {
            Ok(tail) => tail,
            Err(error) => {
                space.cancel(
                    pn.0,
                    &mut frames.drain(start..),
                );
                return Err(error);
            }
        };
        let final_size = if tail_size == 0 {
            size.max(required)
        } else {
            size
        };
        if final_size > size {
            buffer[size - tag..final_size - tag].fill(0);
            meta.record(&Frame::Padding(PaddingFrame));
            limits.take(
                epoch,
                if flight {
                    final_size - size
                } else {
                    final_size
                },
                final_size - size,
            );
        }
        let generation = match keys.seal(
            pn,
            pn_offset,
            &mut buffer[..final_size],
            epoch != Epoch::Data,
        ) {
            Ok(generation) => generation,
            Err(error) => {
                space.cancel(
                    pn.0,
                    &mut frames.drain(start..),
                );
                return Err(error);
            }
        };
        meta.pktlen = final_size;
        let own_frames = meta.nframes;
        space.on_sealed(
            pn.0,
            generation,
            final_size,
            meta,
            &mut frames.drain(start..),
        );
        packets[epoch] = Some(meta);
        limits.probe_quota[epoch] = 0;
        Ok((final_size + tail_size, own_frames + tail_frames, meta.in_flight || tail_flight))
    }

    pub fn snapshot(&self) -> Self {
        let mut spaces = IndexDeque::with_capacity(self.0.len());
        spaces.reset_offset(self.0.offset());
        for space in self.0.iter() {
            spaces.push_back(space.clone()).expect("epoch index");
        }
        Self(spaces)
    }

    /// Obtain a concrete handle when starting a receiver; phases retain only this queue.
    pub fn get<T: Encapsulate>(&self, epoch: Epoch) -> Option<Arc<T>> {
        let space: Arc<dyn Any + Send + Sync> = self.0.get(epoch as u64)?.clone();
        space.downcast().ok()
    }
}
