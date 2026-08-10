use std::{
    ops::Range,
    sync::{Arc, RwLock},
};

use bytes::BufMut;
use qbase::{
    frame::AckFrame,
    net::tx::Signals,
    packet::{InvalidPacketNumber, Package, PacketContent, PacketNumber, PacketWriter},
    varint::{VARINT_MAX, VarInt},
};
use tokio::time::{Duration, Instant};

// A range is 16 bytes on 64-bit targets. This bound is deliberately wider than the number of
// ranges that normally fit in one ACK packet so multipath reordering does not immediately retire
// slow-path packets, while still providing a connection-local memory limit.
const MAX_TRACKED_ACK_RANGES: usize = 256;

/// Received packet numbers represented as sorted, disjoint, half-open ranges.
///
/// The range set is intentionally independent from ACK delivery. An ACK can be lost, arrive on a
/// different path, or never be elicited by the peer; none of those events may make memory safety
/// depend on peer cooperation.
#[derive(Debug, Clone, Default)]
struct ReceivedPacketRanges {
    ranges: Vec<Range<u64>>,
    // Packet numbers below this boundary are never accepted again. It advances only when the hard
    // range bound is reached and the oldest range is evicted.
    retired_before: u64,
    largest_received: Option<(u64, Instant)>,
}

impl ReceivedPacketRanges {
    fn contains(&self, pn: u64) -> bool {
        let index = self.ranges.partition_point(|range| range.end <= pn);
        self.ranges
            .get(index)
            .is_some_and(|range| range.start <= pn && pn < range.end)
    }

    fn insert(&mut self, pn: u64, received_at: Instant) -> bool {
        if pn < self.retired_before || self.contains(pn) {
            return false;
        }

        let index = self.ranges.partition_point(|range| range.end < pn);
        let inserted_end = pn + 1;
        if index < self.ranges.len() && self.ranges[index].end == pn {
            self.ranges[index].end = inserted_end;
            if index + 1 < self.ranges.len()
                && self.ranges[index + 1].start <= self.ranges[index].end
            {
                let next_end = self.ranges[index + 1].end;
                self.ranges[index].end = self.ranges[index].end.max(next_end);
                self.ranges.remove(index + 1);
            }
        } else if index < self.ranges.len() && self.ranges[index].start == inserted_end {
            self.ranges[index].start = pn;
        } else {
            self.ranges.insert(index, pn..inserted_end);
        }

        if self
            .largest_received
            .is_none_or(|(largest, _)| pn > largest)
        {
            self.largest_received = Some((pn, received_at));
        }

        if self.ranges.len() > MAX_TRACKED_ACK_RANGES {
            let evicted = self.ranges.remove(0);
            self.retired_before = self.retired_before.max(evicted.end);
        }
        true
    }

    fn largest(&self) -> Option<(u64, Instant)> {
        self.largest_received
    }

    fn range_containing(&self, pn: u64) -> Option<usize> {
        let index = self.ranges.partition_point(|range| range.end <= pn);
        self.ranges
            .get(index)
            .filter(|range| range.start <= pn && pn < range.end)
            .map(|_| index)
    }
}

/// 记录已经收到的 packet，并生成 ACK frame。
///
/// 接收状态按 ACK range 保存，而不是为每个 PN 保存一个状态。ACK frame 的构造是只读操作；
/// ACK 调度和发送后的状态更新由各路径的拥塞控制器负责。
#[derive(Debug, Default)]
struct RcvdJournal {
    packets: ReceivedPacketRanges,
}

impl RcvdJournal {
    fn with_capacity(capacity: usize, _max_ack_delay: Option<Duration>) -> Self {
        Self {
            packets: ReceivedPacketRanges {
                ranges: Vec::with_capacity(capacity.min(MAX_TRACKED_ACK_RANGES)),
                ..Default::default()
            },
        }
    }

    fn decode_pn(&self, pkt_number: PacketNumber) -> Result<u64, InvalidPacketNumber> {
        let expected_pn = self
            .packets
            .largest()
            .map_or(0, |(largest, _)| largest.saturating_add(1));
        let pn = pkt_number.decode(expected_pn);
        if pn < self.packets.retired_before {
            return Err(InvalidPacketNumber::TooOld);
        }
        if self.packets.contains(pn) {
            return Err(InvalidPacketNumber::Duplicate);
        }
        Ok(pn)
    }

    fn on_rcvd_pn(&mut self, pn: u64, _is_ack_eliciting: bool, _pto: Duration) {
        let now = Instant::now();
        self.packets.insert(pn, now);
    }

    fn gen_ack_frame_util(
        &self,
        largest: u64,
        rcvd_time: Instant,
        mut capacity: usize,
    ) -> Result<AckFrame, Signals> {
        let (range_start, previous_ranges) = match self.packets.range_containing(largest) {
            Some(range_index) => (
                self.packets.ranges[range_index].start,
                &self.packets.ranges[..range_index],
            ),
            // A path-local ACK trigger is independent of the bounded shared journal. If its range
            // has since been retired, the trigger still proves that this packet was received, so a
            // singleton ACK is valid and lets that path finish its pending ACK cycle.
            None if largest < self.packets.retired_before => (largest, &[][..]),
            None => return Err(Signals::TRANSPORT),
        };
        let largest = VarInt::from_u64(largest).map_err(|_| Signals::TRANSPORT)?;
        let delay: u64 = rcvd_time
            .elapsed()
            .as_micros()
            .try_into()
            .unwrap_or(VARINT_MAX)
            .min(VARINT_MAX);
        let delay = VarInt::from_u64(delay).map_err(|_| Signals::TRANSPORT)?;
        let first_range =
            VarInt::from_u64(largest.into_u64() - range_start).map_err(|_| Signals::TRANSPORT)?;

        // Frame type + Largest Acknowledged + ACK Delay + ACK Range Count + First ACK Range.
        let min_len =
            1 + largest.encoding_size() + delay.encoding_size() + 1 + first_range.encoding_size();
        if capacity < min_len {
            return Err(Signals::CONGESTION);
        }
        capacity -= min_len;

        fn range_count_size_increment(range_count: usize) -> usize {
            match range_count {
                len if len == (1 << 6) - 1 => 1,
                len if len == (1 << 14) - 1 => 2,
                len if len == (1 << 30) - 1 => 4,
                _ => 0,
            }
        }

        let mut ranges = Vec::new();
        let mut current_start = range_start;
        for previous in previous_ranges.iter().rev() {
            let gap = current_start
                .checked_sub(previous.end + 1)
                .ok_or(Signals::TRANSPORT)?;
            let gap = VarInt::from_u64(gap).map_err(|_| Signals::TRANSPORT)?;
            let ack = VarInt::from_u64(previous.end - previous.start - 1)
                .map_err(|_| Signals::TRANSPORT)?;
            let size = range_count_size_increment(ranges.len())
                + gap.encoding_size()
                + ack.encoding_size();
            if capacity < size {
                break;
            }
            capacity -= size;
            ranges.push((gap, ack));
            current_start = previous.start;
        }

        Ok(AckFrame::new(largest, delay, first_range, ranges, None))
    }
}

/// Records for received packets, decodes packet numbers and generates ACK frames.
#[derive(Debug, Clone, Default)]
pub struct ArcRcvdJournal {
    inner: Arc<RwLock<RcvdJournal>>,
}

impl ArcRcvdJournal {
    pub fn with_capacity(capacity: usize, max_ack_delay: Option<Duration>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(RcvdJournal::with_capacity(
                capacity,
                max_ack_delay,
            ))),
        }
    }

    pub fn decode_pn(&self, encoded_pn: PacketNumber) -> Result<u64, InvalidPacketNumber> {
        self.inner.read().unwrap().decode_pn(encoded_pn)
    }

    pub fn on_rcvd_pn(&self, pn: u64, is_ack_eliciting: bool, pto: Duration) {
        self.inner
            .write()
            .unwrap()
            .on_rcvd_pn(pn, is_ack_eliciting, pto);
    }

    pub fn gen_ack_frame_util(
        &self,
        largest: u64,
        rcvd_time: Instant,
        capacity: usize,
    ) -> Result<AckFrame, Signals> {
        self.inner
            .read()
            .unwrap()
            .gen_ack_frame_util(largest, rcvd_time, capacity)
    }

    pub fn ack_package<'r>(&'r self, need_ack: Option<(u64, Instant)>) -> AckPackege<'r> {
        AckPackege {
            journal: self,
            need_ack,
        }
    }
}

pub struct AckPackege<'r> {
    journal: &'r ArcRcvdJournal,
    need_ack: Option<(u64, Instant)>,
}

impl AckPackege<'_> {
    fn gen_ack_frame(&self, capacity: usize) -> Result<AckFrame, Signals> {
        let (largest, rcvd_time) = self.need_ack.ok_or(Signals::TRANSPORT)?;
        self.journal
            .gen_ack_frame_util(largest, rcvd_time, capacity)
    }
}

impl<'r, Target> Package<Target> for AckPackege<'r>
where
    Target: AsRef<PacketWriter<'r>> + ?Sized,
    AckFrame: Package<Target>,
{
    fn dump(&mut self, target: &mut Target) -> Result<PacketContent, Signals> {
        // Packet numbers and ACK ranges are connection/epoch scoped, but ACK scheduling is
        // path-local. Start at this path's trigger so a high PN received on another path cannot
        // consume this ACK cycle while leaving the trigger outside a capacity-limited frame.
        self.gen_ack_frame(target.as_ref().remaining_mut())?
            .dump(target)?;
        Ok(PacketContent::NonAckEliciting)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contiguous_packets_merge_into_one_range() {
        let records = ArcRcvdJournal::with_capacity(16, None);
        for pn in [10, 12, 11] {
            records.on_rcvd_pn(pn, true, Duration::ZERO);
        }
        let journal = records.inner.read().unwrap();
        assert_eq!(journal.packets.ranges, vec![10..13]);
        assert_eq!(journal.packets.ranges.len(), 1);
    }

    #[test]
    fn large_packet_number_gap_does_not_allocate_empty_states() {
        let records = ArcRcvdJournal::with_capacity(16, None);
        records.on_rcvd_pn(10, true, Duration::ZERO);
        records.on_rcvd_pn(10_000_000, true, Duration::ZERO);
        let journal = records.inner.read().unwrap();
        assert_eq!(journal.packets.ranges, vec![10..11, 10_000_000..10_000_001]);
    }

    #[test]
    fn range_bound_evicts_oldest_and_retires_it() {
        let records = ArcRcvdJournal::with_capacity(MAX_TRACKED_ACK_RANGES, None);
        for pn in (0..=MAX_TRACKED_ACK_RANGES as u64 * 2).step_by(2) {
            records.on_rcvd_pn(pn, true, Duration::ZERO);
        }
        let journal = records.inner.read().unwrap();
        assert_eq!(journal.packets.ranges.len(), MAX_TRACKED_ACK_RANGES);
        assert!(journal.packets.retired_before > 0);
        drop(journal);
        assert_eq!(
            records.decode_pn(PacketNumber::encode(0, 0)),
            Err(InvalidPacketNumber::TooOld)
        );
    }

    #[test]
    fn ack_ranges_preserve_holes_and_encode_exactly() {
        let records = ArcRcvdJournal::with_capacity(16, None);
        for pn in [100, 101, 104, 105, 110] {
            records.on_rcvd_pn(pn, true, Duration::ZERO);
        }
        let ack = records
            .gen_ack_frame_util(110, Instant::now(), 1200)
            .unwrap();
        assert_eq!(ack.largest(), 110);
        assert_eq!(ack.first_range(), 0);
        assert_eq!(
            ack.ranges(),
            &vec![
                (VarInt::from_u64(3).unwrap(), VarInt::from_u64(1).unwrap()),
                (VarInt::from_u64(1).unwrap(), VarInt::from_u64(1).unwrap()),
            ]
        );
        assert!(ack.iter().any(|range| range == (100..=101)));
        assert!(ack.iter().any(|range| range == (104..=105)));
    }

    #[test]
    fn ack_generation_is_read_only() {
        let records = ArcRcvdJournal::with_capacity(16, None);
        records.on_rcvd_pn(1, true, Duration::ZERO);
        let before = records.inner.read().unwrap().clone_for_test();
        assert!(records.gen_ack_frame_util(1, Instant::now(), 1200).is_ok());
        assert_eq!(records.inner.read().unwrap().clone_for_test(), before);
    }

    #[test]
    fn high_packet_number_does_not_retire_slow_path_range() {
        let records = ArcRcvdJournal::with_capacity(16, None);
        records.on_rcvd_pn(100, true, Duration::ZERO);
        records.on_rcvd_pn(10_000, true, Duration::ZERO);
        assert_eq!(
            records.inner.read().unwrap().packets.ranges,
            vec![100..101, 10_000..10_001]
        );
    }

    #[test]
    fn path_local_trigger_selects_ack_largest_in_shared_journal() {
        let records = ArcRcvdJournal::with_capacity(16, None);
        records.on_rcvd_pn(100, true, Duration::ZERO);
        records.on_rcvd_pn(10_000, true, Duration::ZERO);

        let ack = records
            .ack_package(Some((100, Instant::now())))
            .gen_ack_frame(1200)
            .unwrap();

        assert_eq!(ack.largest(), 100);
        assert!(ack.iter().any(|range| range.contains(&100)));
        assert!(!ack.iter().any(|range| range.contains(&10_000)));
    }

    #[test]
    fn retired_path_trigger_can_still_generate_singleton_ack() {
        let records = ArcRcvdJournal::with_capacity(MAX_TRACKED_ACK_RANGES, None);
        records.on_rcvd_pn(0, true, Duration::ZERO);
        for pn in (2..=MAX_TRACKED_ACK_RANGES as u64 * 2).step_by(2) {
            records.on_rcvd_pn(pn, true, Duration::ZERO);
        }
        assert!(!records.inner.read().unwrap().packets.contains(0));

        let ack = records
            .ack_package(Some((0, Instant::now())))
            .gen_ack_frame(1200)
            .unwrap();

        assert_eq!(ack.largest(), 0);
        assert_eq!(ack.first_range(), 0);
        assert_eq!(ack.ranges(), &[]);
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct JournalSnapshot {
        ranges: Vec<Range<u64>>,
        retired_before: u64,
    }

    impl RcvdJournal {
        fn clone_for_test(&self) -> JournalSnapshot {
            JournalSnapshot {
                ranges: self.packets.ranges.clone(),
                retired_before: self.packets.retired_before,
            }
        }
    }
}
