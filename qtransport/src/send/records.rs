//! Space-wide packet numbers and recovery descriptors. Packet numbers are never returned.
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use qbase::{
    error::{ErrorKind, QuicError},
    frame::AckFrame,
    net::tx::Signals,
    packet::PacketNumber,
    util::IndexDeque,
    varint::VARINT_MAX,
};
use tokio::time::Instant;

use super::write::PacketError;
use crate::{Error, GuaranteedFrame};

const MAX_RECORDS: usize = 8192;
const MAX_SKIPPED_PNS: usize = 256;
// Includes empty slots pinned behind an earlier retained packet.
const MAX_FRAMES: usize = MAX_RECORDS * 4;

struct SentPacket {
    generation: Option<u64>,
    frame_range: Range<u64>,
    state: SentPacketState,
}

/// Pending -> Flighting -> Retransmitted -> Retired.
/// Pending can fail; Flighting and Retransmitted can become Acked.
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
pub(crate) struct SendJournal {
    packets: BTreeMap<u64, SentPacket>,
    frames: IndexDeque<Option<GuaranteedFrame>, { u64::MAX }>,
    deadlines: BTreeSet<(Instant, u64)>,
    next_pn: u64,
    largest_acked: u64,
    skipped_pns: BTreeSet<u64>,
}

impl SendJournal {
    /// Fix the retention deadline at successful submission; loss never restarts it.
    pub fn mark_sent(
        &mut self,
        pn: u64,
        in_flight: bool,
        retransmit_after: Duration,
        retention: Duration,
    ) {
        let sent_at = Instant::now();
        let record = self
            .packets
            .get_mut(&pn)
            .expect("pending packet has a record");
        if in_flight {
            let retrans_at = sent_at + retransmit_after;
            record.state = SentPacketState::Flighting {
                retrans_at,
                expire_after: sent_at + retention,
            };
            self.deadlines.insert((retrans_at, pn));
        }
        if !in_flight {
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

    fn retransmit(&mut self, pn: u64, mut on_frame: impl FnMut(&GuaranteedFrame)) {
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
                    self.retransmit(pn, &mut on_frame);
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
/// Assembly and encryption run without a journal guard; submission holds the journals
/// until the accepted prefix and its CC records are committed.
#[derive(Clone)]
pub struct ArcSendJournal(
    Arc<Mutex<SendJournal>>,
    Arc<dyn Fn(&GuaranteedFrame) + Send + Sync>,
);

impl Default for ArcSendJournal {
    fn default() -> Self {
        Self::new(|_| {})
    }
}

impl ArcSendJournal {
    pub(crate) fn lock_guard(&self) -> MutexGuard<'_, SendJournal> {
        self.0.lock().unwrap()
    }

    pub fn new(recover: impl Fn(&GuaranteedFrame) + Send + Sync + 'static) -> Self {
        Self(
            Arc::new(Mutex::new(SendJournal::default())),
            Arc::new(recover),
        )
    }

    pub(crate) fn recover(&self, frame: &GuaranteedFrame) {
        (self.1)(frame);
    }

    /// Abandon a sealed but unsubmitted packet and return its reliable data.
    pub(crate) fn cancel(&self, pn: u64) {
        let mut records = self.0.lock().unwrap();
        if let Some(record) = records.remove_packet(pn, SentPacketState::Failed) {
            records.skipped_pns.insert(pn);
            if records.skipped_pns.len() > MAX_SKIPPED_PNS {
                records.skipped_pns.pop_first();
            }
            records.take_frames(record.frame_range, |frame| self.recover(&frame));
        }
    }

    #[cfg(test)]
    pub(crate) fn starting_at(pn: u64) -> Self {
        Self(
            Arc::new(Mutex::new(SendJournal {
                next_pn: pn,
                ..Default::default()
            })),
            Arc::new(|_| {}),
        )
    }

    pub fn has_capacity(&self) -> bool {
        let records = self.0.lock().unwrap();
        records.packets.len() < MAX_RECORDS && records.frames.len() < MAX_FRAMES
    }
    /// Allocate and encode a PN and retain its descriptors in one operation.
    /// The caller fixes the sealing generation while this operation runs.
    pub(crate) fn record_pending(
        &self,
        generation: impl Into<Option<u64>>,
        frames: &mut Vec<GuaranteedFrame>,
    ) -> Result<(u64, PacketNumber), PacketError> {
        let mut records = self.0.lock().unwrap();
        if records.packets.len() >= MAX_RECORDS || records.frames.len() + frames.len() > MAX_FRAMES
        {
            return Err(PacketError::Blocked(Signals::TRANSPORT));
        }
        let pn = records.next_pn;
        if pn > VARINT_MAX {
            return Err(Error::from(QuicError::with_default_fty(
                ErrorKind::AeadLimitReached,
                "packet numbers exhausted",
            ))
            .into());
        }
        let encoded = PacketNumber::encode(pn, records.largest_acked);
        records.next_pn += 1;
        let start = records.frames.largest();
        for frame in frames.drain(..) {
            records.frames.push_back(Some(frame)).unwrap();
        }
        let frame_range = start..records.frames.largest();
        records.packets.insert(
            pn,
            SentPacket {
                generation: generation.into(),
                frame_range,
                state: SentPacketState::Pending,
            },
        );
        Ok((pn, encoded))
    }
    /// Fix the retention deadline at successful submission; loss never restarts it.
    pub fn mark_sent(
        &self,
        pn: u64,
        in_flight: bool,
        retransmit_after: Duration,
        retention: Duration,
    ) {
        self.lock_guard()
            .mark_sent(pn, in_flight, retransmit_after, retention);
    }

    /// Failed or abandoned submission: return its frames before reclaiming the record.
    /// Called by the Sender that still owns this pending packet.
    pub fn cancel_pending(&self, pn: u64, frames: &mut Vec<GuaranteedFrame>) {
        let mut records = self.0.lock().unwrap();
        if let Some(record) = records.remove_packet(pn, SentPacketState::Failed) {
            records.skipped_pns.insert(pn);
            if records.skipped_pns.len() > MAX_SKIPPED_PNS {
                records.skipped_pns.pop_first();
            }
            records.take_frames(record.frame_range, |frame| frames.push(frame));
        }
    }
    /// Report loss directly to frame owners while retaining the original for late ACKs.
    /// Like acknowledge, callbacks must not call back into CC or this journal.
    pub(crate) fn mark_lost(
        &self,
        pns: &mut dyn Iterator<Item = u64>,
        mut on_frame: impl FnMut(&GuaranteedFrame),
    ) {
        let mut records = self.0.lock().unwrap();
        for pn in pns {
            records.retransmit(pn, &mut on_frame);
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
    /// The callback must not call back into CC or this journal.
    pub fn acknowledge(
        &self,
        ack: &AckFrame,
        mut on_frame: impl FnMut(&GuaranteedFrame),
    ) -> Result<Vec<u64>, Error> {
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
            || ranges.iter().any(|range| {
                records.skipped_pns.range(range.clone()).next().is_some()
                    || records
                        .packets
                        .range(range.clone())
                        .any(|(_, record)| matches!(record.state, SentPacketState::Pending))
            })
        {
            return Err(QuicError::with_default_fty(
                ErrorKind::ProtocolViolation,
                "ACK acknowledges an unsent packet",
            )
            .into());
        }
        records.largest_acked = records.largest_acked.max(ack.largest());
        let mut acknowledged = Vec::new();
        // ACK ranges arrive from high to low; keep notifications in ascending PN order.
        for range in ranges.into_iter().rev() {
            while let Some((&pn, _)) = records.packets.range(range.clone()).next() {
                let record = records.remove_packet(pn, SentPacketState::Acked).unwrap();
                for index in record.frame_range {
                    on_frame(&records.frames[index].take().unwrap());
                }
                if let Some(generation) = record.generation {
                    acknowledged.push(generation);
                }
            }
        }
        records.reclaim();
        Ok(acknowledged)
    }
}

#[cfg(test)]
mod tests {
    use qbase::frame::ReliableFrame;

    use super::*;
    use crate::GuaranteedFrame as Frame;
    fn ack(pn: u64) -> AckFrame {
        AckFrame::new(
            pn.try_into().unwrap(),
            0u32.into(),
            0u32.into(),
            vec![],
            None,
        )
    }

    fn frame(value: u32) -> GuaranteedFrame {
        Frame::Reliable(ReliableFrame::MaxData(qbase::frame::MaxDataFrame::new(
            value.into(),
        )))
    }

    fn acknowledged_values(records: &ArcSendJournal, pn: u64) -> Vec<u64> {
        let mut values = Vec::new();
        records
            .acknowledge(&ack(pn), |frame| match frame {
                GuaranteedFrame::Reliable(qbase::frame::ReliableFrame::MaxData(frame)) => {
                    values.push(frame.max_data());
                }
                _ => panic!("unexpected recovery frame"),
            })
            .unwrap();
        values
    }

    #[test]
    fn pending_reliable_records_reuse_scratch_allocation() {
        let records = ArcSendJournal::default();
        let mut scratch = vec![frame(10)];
        let allocation = scratch.as_ptr();
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 0);
        assert!(scratch.is_empty());
        assert_eq!(scratch.as_ptr(), allocation);
        records.mark_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
        records.mark_lost(&mut [0].into_iter(), |frame| scratch.push(frame.clone()));
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
        );
        assert_eq!(acknowledged_values(&records, 0), [10]);
    }

    #[test]
    fn recovery_keeps_data_headers_and_moves_tokens_without_copying() {
        use qbase::frame::{CryptoFrame, NewTokenFrame, StreamFrame};
        let records = ArcSendJournal::default();
        let crypto = CryptoFrame::new(10u32.into(), 20u32.into());
        let stream = StreamFrame::new(
            qbase::sid::StreamId::new(qbase::role::Role::Client, qbase::sid::Dir::Uni, 0),
            30,
            40,
        );
        let token = NewTokenFrame::new(vec![5; 20]);
        let allocation = token.token().as_ptr();
        // Keep an earlier packet live so cancellation cannot drain the queue prefix.
        assert_eq!(records.record_pending(0, &mut vec![frame(0)]).unwrap().0, 0);
        let mut scratch = vec![
            Frame::Crypto(crypto),
            Frame::Stream(stream),
            Frame::Reliable(ReliableFrame::NewToken(token)),
        ];
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 1);
        assert!(scratch.is_empty());
        records.cancel_pending(1, &mut scratch);
        assert!(matches!(scratch.as_slice(),
            [Frame::Crypto(c), Frame::Stream(s), Frame::Reliable(ReliableFrame::NewToken(t))]
            if *c == crypto && *s == stream && t.token().as_ptr() == allocation));
        scratch.clear();
        records.cancel_pending(0, &mut scratch);
        assert!(records.0.lock().unwrap().frames.is_empty());
    }

    #[tokio::test]
    async fn reverse_submission_and_ack_order_preserve_frame_ranges() {
        let records = ArcSendJournal::default();
        let mut scratch = Vec::with_capacity(4);
        let allocation = scratch.as_ptr();
        scratch.extend([frame(110), frame(111)]);
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 0);
        assert!(scratch.is_empty());
        assert_eq!(scratch.as_ptr(), allocation);
        scratch.push(frame(100));
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 1);
        {
            let journal = records.0.lock().unwrap();
            assert_eq!(journal.packets[&0].frame_range, 0..2);
            assert_eq!(journal.packets[&1].frame_range, 2..3);
        }
        records.mark_sent(1, true, Duration::from_secs(1), Duration::from_secs(3));
        records.mark_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
        assert_eq!(acknowledged_values(&records, 1), [100]);
        // The processed slots remain pinned by PN0 until the prefix can be removed.
        assert_eq!(records.0.lock().unwrap().frames.len(), 3);
        assert_eq!(acknowledged_values(&records, 0), [110, 111]);
        assert!(records.0.lock().unwrap().frames.is_empty());
        assert!(acknowledged_values(&records, 0).is_empty());
        scratch.push(frame(120));
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 2);
        records.cancel_pending(2, &mut scratch);
        assert_eq!(scratch.as_ptr(), allocation);
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 120)
        );
        assert!(records.0.lock().unwrap().frames.is_empty());
        assert!(records.acknowledge(&ack(2), |_| {}).is_err());
    }

    #[test]
    fn batch_ack_reclaims_prefix_without_moving_pending_frame_indices() {
        let records = ArcSendJournal::default();
        let mut scratch = Vec::new();
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 0); // Empty ranges do not pin frames.
        scratch.push(frame(10));
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 1);
        scratch.extend([frame(20), frame(21)]);
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 2);
        scratch.push(frame(30));
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 3);
        records.mark_sent(1, true, Duration::from_secs(1), Duration::from_secs(3));
        records.mark_sent(2, true, Duration::from_secs(1), Duration::from_secs(3));
        let ack = AckFrame::new(2u32.into(), 0u32.into(), 1u32.into(), vec![], None);
        let mut values = Vec::new();
        records
            .acknowledge(&ack, |frame| match frame {
                GuaranteedFrame::Reliable(qbase::frame::ReliableFrame::MaxData(frame)) => {
                    values.push(frame.max_data());
                }
                _ => panic!("unexpected recovery frame"),
            })
            .unwrap();
        assert_eq!(values, [10, 20, 21]);
        {
            let journal = records.0.lock().unwrap();
            assert_eq!(journal.frames.offset(), 3);
            assert_eq!(journal.frames.len(), 1);
            assert_eq!(journal.packets[&3].frame_range, 3..4);
        }
        records
            .acknowledge(&ack, |_| panic!("duplicate ACK delivered a frame"))
            .unwrap();
        records.cancel_pending(3, &mut scratch);
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(frame))] if frame.max_data() == 30)
        );
        assert!(records.0.lock().unwrap().frames.is_empty());
    }

    #[tokio::test]
    async fn concurrent_batches_keep_each_packets_frames_together() {
        let records = &ArcSendJournal::default();
        std::thread::scope(|scope| {
            for worker in 0..4 {
                scope.spawn(move || {
                    let mut scratch = Vec::new();
                    for i in 0..100 {
                        let value = worker * 100 + i;
                        scratch.extend([frame(value), frame(value + 1000)]);
                        records.record_pending(0, &mut scratch).unwrap();
                        assert!(scratch.is_empty());
                    }
                });
            }
        });
        let mut values = BTreeSet::new();
        let mut scratch = Vec::new();
        for pn in (0..400).rev() {
            records.cancel_pending(pn, &mut scratch);
            let [
                Frame::Reliable(ReliableFrame::MaxData(a)),
                Frame::Reliable(ReliableFrame::MaxData(b)),
            ] = scratch.as_slice()
            else {
                panic!()
            };
            assert_eq!(b.max_data(), a.max_data() + 1000);
            assert!(values.insert(a.max_data()));
            scratch.clear();
        }
        let journal = records.0.lock().unwrap();
        assert!(journal.packets.is_empty());
        assert!(journal.frames.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_slots_are_reclaimed_only_when_the_live_prefix_finishes() {
        let records = ArcSendJournal::default();
        let mut scratch = Vec::new();
        let now = Instant::now();
        for pn in 0..5 {
            scratch.push(frame(pn as u32));
            assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, pn);
        }
        records.mark_sent(1, true, Duration::from_secs(1), Duration::from_secs(3));
        records.mark_sent(3, true, Duration::from_secs(1), Duration::from_secs(3));
        assert_eq!(acknowledged_values(&records, 1), [1]);
        records.cancel_pending(2, &mut scratch);
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 2)
        );
        scratch.clear();
        records.mark_lost(&mut [3].into_iter(), |frame| scratch.push(frame.clone()));
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 3)
        );
        scratch.clear();
        assert!(records.0.lock().unwrap().frames[3].is_some());
        records.on_tick(now + Duration::from_secs(3), |frame| {
            scratch.push(frame.clone())
        });
        assert!(scratch.is_empty());
        {
            let journal = records.0.lock().unwrap();
            assert_eq!(journal.frames.offset(), 0);
            assert_eq!(journal.frames.len(), 5);
            assert!((1..4).all(|index| journal.frames[index].is_none()));
        }
        records.cancel_pending(0, &mut scratch);
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 0)
        );
        scratch.clear();
        {
            let journal = records.0.lock().unwrap();
            assert_eq!(journal.frames.offset(), 4);
            assert_eq!(journal.frames.len(), 1);
            assert_eq!(journal.packets[&4].frame_range, 4..5);
        }
        records.cancel_pending(4, &mut scratch);
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 4)
        );
        assert!(records.0.lock().unwrap().frames.is_empty());
    }

    #[tokio::test]
    async fn pinned_empty_slots_are_bounded_and_failed_append_preserves_frames() {
        let records = ArcSendJournal::default();
        let mut scratch = vec![frame(0)];
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 0);
        scratch.resize(MAX_FRAMES - 1, frame(1));
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 1);
        records.mark_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
        records.mark_sent(1, true, Duration::from_secs(1), Duration::from_secs(3));
        assert_eq!(acknowledged_values(&records, 1).len(), MAX_FRAMES - 1);
        assert!(!records.has_capacity());
        scratch.push(frame(2));
        assert!(records.record_pending(0, &mut scratch).is_err());
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 2)
        );
        assert_eq!(acknowledged_values(&records, 0), [0]);
        assert!(records.has_capacity());
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 2);
        assert!(scratch.is_empty());
        records.cancel_pending(2, &mut scratch);
        assert!(records.0.lock().unwrap().frames.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn loss_retains_frames_for_late_ack_and_expiration_reclaims_storage() {
        let records = ArcSendJournal::default();
        let mut scratch = vec![frame(10)];
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 0);
        records.mark_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
        records.mark_lost(&mut [0].into_iter(), |frame| scratch.push(frame.clone()));
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
        );
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 1);
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        assert!(scratch.is_empty());
        records.mark_sent(1, true, Duration::from_secs(1), Duration::from_secs(3));
        // The new PN can itself be lost; the retained original must not requeue again.
        records.mark_lost(&mut [0, 1].into_iter(), |frame| scratch.push(frame.clone()));
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
        );
        scratch.clear();
        assert_eq!(acknowledged_values(&records, 0), [10]);
        assert_eq!(acknowledged_values(&records, 1), [10]);
        assert!(records.0.lock().unwrap().frames.is_empty());

        scratch.push(frame(20));
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 2);
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        assert!(scratch.is_empty(), "unsent packets have no loss feedback");
        records.mark_sent(2, true, Duration::from_secs(1), Duration::from_secs(3));
        records.mark_lost(&mut [2].into_iter(), |frame| scratch.push(frame.clone()));
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        scratch.clear();
        tokio::time::advance(Duration::from_secs(4)).await;
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        assert!(scratch.is_empty());
        assert!(records.0.lock().unwrap().frames.is_empty());
        assert!(acknowledged_values(&records, 2).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_loss_never_requeues_retained_packets_or_extends_retention() {
        let records = ArcSendJournal::default();
        let mut scratch = vec![frame(10)];
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 0);
        records.mark_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
        scratch.push(frame(20));
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 1);
        records.mark_sent(1, true, Duration::from_secs(1), Duration::from_secs(3));
        records.mark_lost(&mut [0, 1, 0, 1].into_iter(), |frame| {
            scratch.push(frame.clone())
        });
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(a)), Frame::Reliable(ReliableFrame::MaxData(b))]
            if a.max_data() == 10 && b.max_data() == 20)
        );
        scratch.clear();

        tokio::time::advance(Duration::from_secs(2)).await;
        records.mark_lost(&mut [0, 1].into_iter(), |frame| scratch.push(frame.clone()));
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        assert!(
            scratch.is_empty(),
            "retained packets must not be requeued twice"
        );
        assert_eq!(acknowledged_values(&records, 0), [10]);
        assert!(acknowledged_values(&records, 0).is_empty());
        assert!(records.0.lock().unwrap().packets.contains_key(&1));

        tokio::time::advance(Duration::from_secs(1)).await;
        records.mark_lost(&mut [1].into_iter(), |frame| scratch.push(frame.clone()));
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        assert!(
            scratch.is_empty(),
            "expiration must not requeue the old packet"
        );
        let journal = records.0.lock().unwrap();
        assert!(
            journal.packets.is_empty(),
            "repeat loss must not extend retention"
        );
        assert!(journal.frames.is_empty());
    }

    #[test]
    fn late_ack_after_immediate_loss_notification_reclaims_original() {
        let records = ArcSendJournal::default();
        let mut scratch = vec![frame(10)];
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 0);
        records.mark_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
        records.mark_lost(&mut [0].into_iter(), |frame| scratch.push(frame.clone()));
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
        );
        scratch.clear();
        assert_eq!(acknowledged_values(&records, 0), [10]);
        records.mark_lost(&mut [0].into_iter(), |frame| scratch.push(frame.clone()));
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        assert!(scratch.is_empty());
        assert!(acknowledged_values(&records, 0).is_empty());
        assert!(records.0.lock().unwrap().frames.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn retention_starts_at_submission_and_is_not_reset_by_loss() {
        let records = ArcSendJournal::default();
        let mut scratch = vec![frame(10)];
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 0);
        // Time spent waiting for the socket is not part of the sent packet's retention.
        tokio::time::advance(Duration::from_secs(5)).await;
        records.mark_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
        tokio::time::advance(Duration::from_secs(1)).await;
        records.mark_lost(&mut [0].into_iter(), |frame| scratch.push(frame.clone()));

        tokio::time::advance(Duration::from_secs(1)).await;
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
        );
        assert!(records.0.lock().unwrap().packets.contains_key(&0));
        scratch.clear();
        tokio::time::advance(Duration::from_secs(1)).await;
        records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
        assert!(scratch.is_empty());
        let journal = records.0.lock().unwrap();
        assert!(journal.packets.is_empty());
        assert!(journal.frames.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn loss_notification_delivers_data_even_after_retention_deadline() {
        for delayed_loss in [false, true] {
            let records = ArcSendJournal::default();
            let mut scratch = vec![frame(10)];
            assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 0);
            records.mark_sent(0, true, Duration::from_secs(1), Duration::from_secs(3));
            if delayed_loss {
                tokio::time::advance(Duration::from_secs(4)).await;
            }
            records.mark_lost(&mut [0].into_iter(), |frame| scratch.push(frame.clone()));
            if !delayed_loss {
                tokio::time::advance(Duration::from_secs(4)).await;
            }
            records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
            assert!(
                matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
            );
            scratch.clear();
            records.on_tick(Instant::now(), |frame| scratch.push(frame.clone()));
            assert!(scratch.is_empty());
            let journal = records.0.lock().unwrap();
            assert!(journal.packets.is_empty());
            assert!(journal.frames.is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timer_and_loss_feedback_schedule_each_packet_once() {
        let records = ArcSendJournal::default();
        let mut scratch = Vec::new();
        let now = Instant::now();
        for pn in 0..3 {
            scratch.push(frame(pn as u32));
            assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, pn);
            records.mark_sent(pn, true, Duration::from_secs(1), Duration::from_secs(3));
        }
        scratch.push(frame(3));
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 3);
        assert_eq!(acknowledged_values(&records, 1), [1]);
        records.mark_lost(&mut [0].into_iter(), |frame| scratch.push(frame.clone()));
        records.on_tick(now + Duration::from_millis(999), |frame| {
            scratch.push(frame.clone())
        });
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 0)
        );
        scratch.clear();

        records.on_tick(now + Duration::from_secs(1), |frame| {
            scratch.push(frame.clone())
        });
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 2)
        );
        scratch.clear();
        records.mark_lost(&mut [0, 2].into_iter(), |frame| scratch.push(frame.clone()));
        records.on_tick(now + Duration::from_secs(1), |frame| {
            scratch.push(frame.clone())
        });
        assert!(scratch.is_empty());
        assert_eq!(acknowledged_values(&records, 0), [0]);
        records.on_tick(now + Duration::from_secs(3), |frame| {
            scratch.push(frame.clone())
        });
        assert!(scratch.is_empty());
        assert!(acknowledged_values(&records, 2).is_empty());
        // A never-submitted packet has no recovery deadline.
        assert!(records.0.lock().unwrap().packets.contains_key(&3));
        records.cancel_pending(3, &mut scratch);
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 3)
        );
        scratch.clear();

        scratch.push(frame(4));
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 4);
        records.mark_sent(4, true, Duration::from_secs(1), Duration::from_secs(3));
        // Even a late tick must deliver the data before retiring its original record.
        records.on_tick(now + Duration::from_secs(4), |frame| {
            scratch.push(frame.clone())
        });
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 4)
        );
        let journal = records.0.lock().unwrap();
        assert!(journal.packets.is_empty());
        assert!(journal.frames.is_empty());
    }

    #[tokio::test]
    async fn shared_handles_distinguish_cancelled_pending_and_sent_packets() {
        let first = ArcSendJournal::default();
        let second = first.clone();
        let mut frames = vec![frame(10)];
        let cancelled = first.record_pending(0, &mut frames).unwrap().0;
        let sent = second.record_pending(0, &mut frames).unwrap().0;
        let pending = first.record_pending(0, &mut frames).unwrap().0;
        assert_eq!((cancelled, sent, pending), (0, 1, 2));
        second.cancel_pending(cancelled, &mut frames);
        assert!(
            matches!(frames.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
        );
        frames.clear();
        first.mark_sent(sent, false, Duration::ZERO, Duration::ZERO);
        assert!(second.acknowledge(&ack(sent), |_| {}).unwrap().is_empty());
        assert!(second.acknowledge(&ack(cancelled), |_| {}).is_err());
        assert!(first.acknowledge(&ack(pending), |_| {}).is_err());
        second.mark_sent(pending, false, Duration::ZERO, Duration::ZERO);
        assert!(first.acknowledge(&ack(pending), |_| {}).unwrap().is_empty());
        let spanning_gap = AckFrame::new(2u32.into(), 0u32.into(), 2u32.into(), vec![], None);
        assert!(first.acknowledge(&spanning_gap, |_| {}).is_err());
        assert!(first.0.lock().unwrap().packets.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn deadlines_order_by_time_and_keep_packets_with_equal_times() {
        let records = ArcSendJournal::default();
        let now = Instant::now();
        let mut scratch = Vec::new();
        for (pn, retransmit, expire) in [(0, 3, 8), (1, 1, 5), (2, 1, 5), (3, 2, 6)] {
            scratch.push(frame(pn as u32));
            assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, pn);
            records.mark_sent(
                pn,
                true,
                Duration::from_secs(retransmit),
                Duration::from_secs(expire),
            );
        }
        records.on_tick(now + Duration::from_millis(999), |frame| {
            scratch.push(frame.clone())
        });
        assert!(scratch.is_empty());
        records.on_tick(now + Duration::from_secs(1), |frame| {
            scratch.push(frame.clone())
        });
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(a)), Frame::Reliable(ReliableFrame::MaxData(b))]
            if a.max_data() == 1 && b.max_data() == 2)
        );
        scratch.clear();
        assert_eq!(acknowledged_values(&records, 1), [1]);
        // ACK removes a future retransmission; CC loss notifies immediately.
        assert_eq!(acknowledged_values(&records, 0), [0]);
        records.mark_lost(&mut [3, 3].into_iter(), |frame| scratch.push(frame.clone()));
        {
            let journal = records.0.lock().unwrap();
            assert_eq!(
                journal.deadlines,
                BTreeSet::from([
                    (now + Duration::from_secs(5), 2),
                    (now + Duration::from_secs(6), 3),
                ])
            );
        }
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 3)
        );
        scratch.clear();
        assert_eq!(acknowledged_values(&records, 3), [3]);
        records.on_tick(now + Duration::from_secs(5), |frame| {
            scratch.push(frame.clone())
        });
        assert!(scratch.is_empty());
        let journal = records.0.lock().unwrap();
        assert!(journal.packets.is_empty());
        assert!(journal.frames.is_empty());
        assert!(journal.deadlines.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn equal_retransmission_and_retirement_deadlines_deliver_data_once() {
        let records = ArcSendJournal::default();
        let now = Instant::now();
        let mut scratch = vec![frame(10)];
        assert_eq!(records.record_pending(0, &mut scratch).unwrap().0, 0);
        records.mark_sent(0, true, Duration::ZERO, Duration::ZERO);
        records.on_tick(now, |frame| scratch.push(frame.clone()));
        assert!(
            matches!(scratch.as_slice(), [Frame::Reliable(ReliableFrame::MaxData(f))] if f.max_data() == 10)
        );
        scratch.clear();
        records.on_tick(now, |frame| scratch.push(frame.clone()));
        assert!(scratch.is_empty());
        let journal = records.0.lock().unwrap();
        assert!(journal.packets.is_empty());
        assert!(journal.frames.is_empty());
        assert!(journal.deadlines.is_empty());
    }

    #[test]
    fn skipped_numbers_are_explicit_bounded_and_allow_reordered_submission() {
        let journal = ArcSendJournal::default();
        let mut frames = Vec::new();
        for _ in 0..3 {
            journal.record_pending(0, &mut frames).unwrap();
        }
        journal.mark_sent(2, false, Duration::ZERO, Duration::ZERO);
        assert!(journal.0.lock().unwrap().skipped_pns.is_empty());
        assert!(journal.acknowledge(&ack(0), |_| {}).is_err());
        journal.mark_sent(0, false, Duration::ZERO, Duration::ZERO);
        journal.acknowledge(&ack(0), |_| {}).unwrap();
        journal.cancel_pending(1, &mut frames);
        assert!(journal.acknowledge(&ack(1), |_| {}).is_err());
        for _ in 0..MAX_SKIPPED_PNS {
            let (pn, _) = journal.record_pending(0, &mut frames).unwrap();
            journal.cancel_pending(pn, &mut frames);
        }
        let inner = journal.0.lock().unwrap();
        assert_eq!(inner.skipped_pns.len(), MAX_SKIPPED_PNS);
        assert_eq!(inner.skipped_pns.first(), Some(&3));
        drop(inner);
        // Old history is deliberately forgotten; retained skipped PNs are still rejected.
        journal.acknowledge(&ack(1), |_| {}).unwrap();
        assert!(journal.acknowledge(&ack(3), |_| {}).is_err());
        assert!(
            journal
                .acknowledge(&ack(3 + MAX_SKIPPED_PNS as u64), |_| {})
                .is_err()
        );
    }

    #[test]
    fn regression_invalid_ack_ranges_return_an_error_without_underflow() {
        let records = ArcSendJournal::default();
        let malformed = AckFrame::new(0u32.into(), 0u32.into(), 1u32.into(), vec![], None);
        assert!(records.acknowledge(&malformed, |_| {}).is_err());
    }

    #[test]
    fn pn_encoding_tracks_valid_ack_even_after_recovery_records_are_removed() {
        let records = ArcSendJournal::default();
        assert_eq!(
            records.record_pending(0, &mut Vec::new()).unwrap(),
            (0, PacketNumber::U16(0))
        );
        records.mark_sent(0, false, Duration::ZERO, Duration::ZERO);
        records.0.lock().unwrap().next_pn = 1 << 15;
        let (pn, encoded) = records.record_pending(0, &mut Vec::new()).unwrap();
        assert_eq!(encoded, PacketNumber::U24(pn as u32));
        records.mark_sent(pn, false, Duration::ZERO, Duration::ZERO);
        assert!(records.0.lock().unwrap().packets.is_empty());

        assert!(records.acknowledge(&ack(pn + 1), |_| {}).is_err());
        assert_eq!(records.0.lock().unwrap().largest_acked, 0);
        records.acknowledge(&ack(pn), |_| {}).unwrap();
        records.acknowledge(&ack(0), |_| {}).unwrap();
        records.acknowledge(&ack(pn), |_| {}).unwrap();
        assert_eq!(
            records.record_pending(0, &mut Vec::new()).unwrap(),
            (pn + 1, PacketNumber::U16((pn + 1) as u16))
        );
    }

    #[test]
    fn pn_encoding_selects_two_three_and_four_bytes_from_the_ack_gap() {
        let records = ArcSendJournal::default();
        let largest = 1 << 40;
        records.0.lock().unwrap().largest_acked = largest;
        for (gap, size) in [(32767, 2), (32768, 3), (8388607, 3), (8388608, 4)] {
            records.0.lock().unwrap().next_pn = largest + gap;
            let (pn, encoded) = records.record_pending(0, &mut Vec::new()).unwrap();
            assert_eq!(pn, largest + gap);
            assert_eq!(encoded.size(), size);
            assert_eq!(encoded.decode(pn), pn);
        }
    }

    #[test]
    fn concurrent_packet_allocation_is_unique_and_exhaustion_never_wraps() {
        let records = ArcSendJournal::default();
        let numbers = std::thread::scope(|scope| {
            (0..4)
                .map(|_| {
                    let records = records.clone();
                    scope.spawn(move || {
                        (0..1000)
                            .map(|_| records.record_pending(0, &mut Vec::new()).unwrap().0)
                            .collect::<Vec<_>>()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .flat_map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        let unique = numbers
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), 4000);
        assert_eq!(records.record_pending(0, &mut Vec::new()).unwrap().0, 4000);
        {
            let mut journal = records.0.lock().unwrap();
            journal.next_pn = VARINT_MAX;
            journal.largest_acked = VARINT_MAX - 1;
        }
        assert_eq!(
            records.record_pending(0, &mut Vec::new()).unwrap().0,
            VARINT_MAX
        );
        assert!(records.record_pending(0, &mut Vec::new()).is_err());
        assert!(records.record_pending(0, &mut Vec::new()).is_err());
    }
}
