//! Space-wide packet numbers and recovery descriptors. Packet numbers are never returned.
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use qbase::{
    error::{Error, ErrorKind, QuicError},
    frame::{AckFrame, GuaranteedFrame},
    packet::{PacketContent, PacketNumber, assemble::Metadata},
    util::IndexDeque,
    varint::VARINT_MAX,
};
use tokio::time::Instant;

const MAX_RECORDS: usize = 8192;
const MAX_SKIPPED_PNS: usize = 256;
// Includes empty slots pinned behind an earlier retained packet.
const MAX_FRAMES: usize = MAX_RECORDS * 4;

pub struct SentPacket {
    pub size: usize,
    pub content: PacketContent,
    pub in_flight: bool,
    pub ack: Option<u64>,
    generation: Option<u64>,
    frame_range: Range<u64>,
    state: SentPacketState,
}

/// Pending -> Flighting -> Retransmitted -> Retired.
/// Pending can fail or become Acked, as can Flighting and Retransmitted.
/// Terminal records and their indexes are removed together by PN.
enum SentPacketState {
    Pending,
    Flighting {
        retrans_at: Instant,
        expire_after: Instant,
    },
    /// Frame owners have been notified once to retransmit under a new PN.
    Retransmitted {
        expire_after: Instant,
    },
    Failed,
    Acked,
    Retired,
}

#[derive(Default)]
pub struct SentJournal {
    packets: BTreeMap<u64, SentPacket>,
    frames: IndexDeque<Option<GuaranteedFrame>, { u64::MAX }>,
    deadlines: BTreeSet<(Instant, u64)>,
    next_pn: u64,
    largest_acked: u64,
    skipped_pns: BTreeSet<u64>,
}

impl SentJournal {
    pub fn frames(&self, pn: u64) -> impl Iterator<Item = &GuaranteedFrame> {
        self.packets[&pn]
            .frame_range
            .clone()
            .map(|index| self.frames[index].as_ref().unwrap())
    }

    pub fn packet(&self, pn: u64) -> Option<&SentPacket> {
        self.packets.get(&pn)
    }

    /// Fix the retention deadline at successful submission; loss never restarts it.
    pub fn on_sent(
        &mut self,
        pn: u64,
        in_flight: bool,
        retransmit_after: Duration,
        retention: Duration,
    ) {
        let sent_at = Instant::now();
        // An early ACK retains metadata until the socket result is processed.
        let Some(record) = self.packets.get_mut(&pn) else {
            return;
        };
        if matches!(record.state, SentPacketState::Acked) {
            self.packets.remove(&pn);
            return;
        }
        if !matches!(record.state, SentPacketState::Pending) {
            return;
        }
        if in_flight {
            let retrans_at = sent_at + retransmit_after;
            record.state = SentPacketState::Flighting {
                retrans_at,
                expire_after: sent_at + retention,
            };
            self.deadlines.insert((retrans_at, pn));
        } else {
            let record = self.remove_packet(pn, SentPacketState::Retired).unwrap();
            self.take_frames(record.frame_range, drop);
        }
    }

    fn take_frames(&mut self, range: Range<u64>, mut on_frame: impl FnMut(GuaranteedFrame)) {
        for index in range {
            on_frame(self.frames[index].take().unwrap());
        }
        self.reclaim();
    }

    fn resend(&mut self, pn: u64, mut on_frame: impl FnMut(&GuaranteedFrame)) {
        if let Some(record) = self.packets.get_mut(&pn)
            && let SentPacketState::Flighting {
                retrans_at,
                expire_after,
            } = record.state
        {
            self.deadlines.remove(&(retrans_at, pn));
            record.state = SentPacketState::Retransmitted { expire_after };
            self.deadlines.insert((expire_after, pn));
            for index in record.frame_range.clone() {
                on_frame(self.frames[index].as_ref().unwrap());
            }
        }
    }

    /// Remove a terminal packet and its current deadline together.
    /// The caller consumes or drops its frame slots before reclaiming the prefix.
    fn remove_packet(&mut self, pn: u64, state: SentPacketState) -> Option<SentPacket> {
        let mut record = self.packets.remove(&pn)?;
        let deadline = match record.state {
            SentPacketState::Flighting { retrans_at, .. } => Some(retrans_at),
            SentPacketState::Retransmitted { expire_after } => Some(expire_after),
            _ => None,
        };
        if let Some(deadline) = deadline {
            self.deadlines.remove(&(deadline, pn));
        }
        record.state = state;
        Some(record)
    }

    fn on_tick(&mut self, now: Instant, mut on_frame: impl FnMut(&GuaranteedFrame)) {
        while let Some(&(deadline, pn)) = self.deadlines.first() {
            if deadline > now {
                break;
            }
            match self.packets[&pn].state {
                SentPacketState::Flighting { .. } => {
                    self.resend(pn, &mut on_frame);
                }
                SentPacketState::Retransmitted { .. } => {
                    let record = self.remove_packet(pn, SentPacketState::Retired).unwrap();
                    self.take_frames(record.frame_range, drop);
                }
                _ => unreachable!("only flighting and retransmitted packets have deadlines"),
            }
        }
    }

    fn reclaim(&mut self) {
        while matches!(self.frames.front(), Some((_, None))) {
            self.frames.pop_front();
        }
    }
}

/// Shared sending journal for one packet-number space, across all path senders.
/// PN allocation and batch recording hold the lock only for their own operation;
/// Assembly and encryption run without a journal guard. Space locks the journal
/// internally when recording the successfully submitted batch.
#[derive(Clone, Default)]
pub struct ArcSentJournal(Arc<Mutex<SentJournal>>);

impl ArcSentJournal {
    pub fn lock_guard(&self) -> MutexGuard<'_, SentJournal> {
        self.0.lock().unwrap()
    }

    /// Abandon a sealed but unsubmitted packet and return its reliable data.
    pub fn cancel(&self, pn: u64, on_frame: impl FnMut(GuaranteedFrame)) {
        let mut records = self.0.lock().unwrap();
        if records
            .packets
            .get(&pn)
            .is_some_and(|packet| matches!(packet.state, SentPacketState::Acked))
        {
            records.packets.remove(&pn);
            return;
        }
        if let Some(record) = records.remove_packet(pn, SentPacketState::Failed) {
            records.skipped_pns.insert(pn);
            if records.skipped_pns.len() > MAX_SKIPPED_PNS {
                records.skipped_pns.pop_first();
            }
            records.take_frames(record.frame_range, on_frame);
        }
    }

    pub fn has_capacity(&self) -> bool {
        let records = self.0.lock().unwrap();
        records.packets.len() < MAX_RECORDS && records.frames.len() < MAX_FRAMES
    }

    /// Reserve a unique packet number before constructing a packet.
    pub fn next_pn(&self) -> Result<(u64, PacketNumber), Error> {
        let mut records = self.lock_guard();
        let pn = records.next_pn;
        if pn > VARINT_MAX {
            return Err(QuicError::with_default_fty(
                ErrorKind::AeadLimitReached,
                "packet numbers exhausted",
            )
            .into());
        }
        records.next_pn += 1;
        let start = records.frames.largest();
        records.packets.insert(
            pn,
            SentPacket {
                size: 0,
                content: PacketContent::default(),
                in_flight: false,
                ack: None,
                generation: None,
                frame_range: start..start,
                state: SentPacketState::Pending,
            },
        );
        Ok((pn, PacketNumber::encode(pn, records.largest_acked)))
    }

    /// Retain recovery descriptors and the properties accumulated during encoding.
    pub fn on_sealed(
        &self,
        pn: u64,
        generation: Option<u64>,
        pktlen: usize,
        meta: Metadata,
        frames: impl IntoIterator<Item = GuaranteedFrame>,
    ) {
        let mut records = self.lock_guard();
        assert!(
            records.packets.get(&pn).is_some_and(
                |p| matches!(p.state, SentPacketState::Pending) && p.frame_range.is_empty()
            ),
            "packet number must be reserved once"
        );
        let start = records.frames.largest();
        for frame in frames {
            records.frames.push_back(Some(frame)).unwrap();
        }
        let frame_range = start..records.frames.largest();
        records.packets.insert(
            pn,
            SentPacket {
                size: pktlen,
                content: meta.content,
                in_flight: meta.in_flight,
                ack: meta.ack,
                generation,
                frame_range,
                state: SentPacketState::Pending,
            },
        );
    }

    /// Fix the retention deadline at successful submission; loss never restarts it.
    pub fn on_sent(
        &self,
        pn: u64,
        in_flight: bool,
        retransmit_after: Duration,
        retention: Duration,
    ) {
        self.lock_guard()
            .on_sent(pn, in_flight, retransmit_after, retention);
    }

    /// Report loss directly to frame owners while retaining the original for late ACKs.
    /// Like acknowledge, callbacks must not call back into CC or this journal.
    pub fn resend(
        &self,
        pns: &mut dyn Iterator<Item = u64>,
        mut on_frame: impl FnMut(&GuaranteedFrame),
    ) {
        let mut records = self.0.lock().unwrap();
        for pn in pns {
            records.resend(pn, &mut on_frame);
        }
    }

    /// Process due deadlines and immediately notify frame owners of loss.
    /// This does not depend on a Path or its sending task remaining alive.
    /// Callbacks must not call back into CC or this journal.
    pub fn on_tick(&self, now: Instant, on_frame: impl FnMut(&GuaranteedFrame)) {
        self.0.lock().unwrap().on_tick(now, on_frame);
    }

    /// The receive path locks its CC before entering the journal, matching send order.
    /// Remove acknowledged records, notify frame owners, then reclaim the queue prefix.
    /// Return the highest newly acknowledged key generation, if any.
    /// The callback must not call back into CC or this journal.
    pub fn on_acked(
        &self,
        ack: &AckFrame,
        mut on_frame: impl FnMut(&GuaranteedFrame),
    ) -> Result<Option<u64>, Error> {
        let mut records = self.0.lock().unwrap();
        // qbase's decoder reads ACK fields; validate range arithmetic before its
        // iterators or CC can see an authenticated but malformed ACK.
        let invalid = || QuicError::with_default_fty(ErrorKind::FrameEncoding, "invalid ACK range");
        let mut start = ack
            .largest()
            .checked_sub(ack.first_range())
            .ok_or_else(invalid)?;
        let mut ranges = Vec::with_capacity(ack.ranges().len() + 1);
        ranges.push(start..=ack.largest());
        for (gap, range) in ack.ranges() {
            let end = start
                .checked_sub(gap.into_u64())
                .and_then(|pn| pn.checked_sub(2))
                .ok_or_else(invalid)?;
            start = end.checked_sub(range.into_u64()).ok_or_else(invalid)?;
            ranges.push(start..=end);
        }
        if ack.largest() >= records.next_pn
            || ranges
                .iter()
                .any(|range| records.skipped_pns.range(range.clone()).next().is_some())
        {
            return Err(QuicError::with_default_fty(
                ErrorKind::ProtocolViolation,
                "ACK acknowledges an unsent packet",
            )
            .into());
        }
        records.largest_acked = records.largest_acked.max(ack.largest());
        let mut acknowledged = None;
        // ACK ranges arrive from high to low; keep notifications in ascending PN order.
        for range in ranges.into_iter().rev() {
            let mut start = *range.start();
            while start <= *range.end() {
                let Some((&pn, _)) = records.packets.range(start..=*range.end()).next() else {
                    break;
                };
                start = pn + 1;
                let pending = matches!(
                    records.packets[&pn].state,
                    SentPacketState::Pending | SentPacketState::Acked
                );
                let mut record = records.remove_packet(pn, SentPacketState::Acked).unwrap();
                for index in record.frame_range.clone() {
                    on_frame(&records.frames[index].take().unwrap());
                }
                acknowledged = acknowledged.max(record.generation.take());
                if pending {
                    record.frame_range = 0..0;
                    records.packets.insert(pn, record);
                }
            }
        }
        records.reclaim();
        Ok(acknowledged)
    }
}

#[cfg(test)]
mod tests {
    use super::{ArcSentJournal, ErrorKind, PacketNumber, VARINT_MAX};

    // The u62 boundary cannot be reached by a practical sequence of public allocations.
    #[test]
    fn packet_number_exhaustion_never_wraps() {
        let records = ArcSentJournal::default();
        {
            let mut journal = records.lock_guard();
            journal.next_pn = VARINT_MAX;
            journal.largest_acked = VARINT_MAX - 1;
        }
        assert_eq!(
            records.next_pn().unwrap(),
            (VARINT_MAX, PacketNumber::U16(VARINT_MAX as u16))
        );
        for _ in 0..2 {
            assert_eq!(
                records.next_pn().unwrap_err().kind(),
                ErrorKind::AeadLimitReached
            );
            assert_eq!(records.lock_guard().next_pn, VARINT_MAX + 1);
        }
    }
}
