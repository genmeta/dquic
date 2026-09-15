//! Space-wide packet numbers and recovery descriptors. Packet numbers are never returned.
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use qbase::{
    error::ErrorKind,
    frame::{AckFrame, Frame},
    varint::VARINT_MAX,
};
use qrecovery::journal::ArcRcvdJournal;
use tokio::time::Instant;

use crate::{Error, path::Path};

const MAX_RECORDS: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SentState {
    Pending,
    Sent,
}

struct SentPacket {
    path: Weak<Path>,
    status: SentState,
    generation: u64,
    frames: Vec<Frame<()>>,
    loss_pending: bool,
    expires: Option<Instant>,
    retention: Duration,
}

pub struct SentPackets {
    packets: Mutex<BTreeMap<u64, SentPacket>>,
    journal: ArcRcvdJournal,
    next_pn: AtomicU64,
    largest_submitted: AtomicU64,
}
impl Default for SentPackets {
    fn default() -> Self {
        Self {
            packets: Mutex::new(BTreeMap::new()),
            journal: ArcRcvdJournal::with_capacity(0, None),
            next_pn: 0.into(),
            largest_submitted: u64::MAX.into(),
        }
    }
}

impl SentPackets {
    pub fn next_pn(&self) -> Result<u64, Error> {
        let mut pn = self.next_pn.load(Ordering::Acquire);
        loop {
            if pn > VARINT_MAX {
                return Err(crate::error(
                    ErrorKind::AeadLimitReached,
                    "packet numbers exhausted",
                ));
            }
            match self.next_pn.compare_exchange_weak(
                pn,
                pn + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(pn),
                Err(next) => pn = next,
            }
        }
    }
    pub fn has_capacity(&self) -> bool {
        self.packets.lock().unwrap().len() < MAX_RECORDS
    }
    pub fn pending(
        &self,
        pn: u64,
        path: &Arc<Path>,
        generation: u64,
        frames: &[Frame<()>],
    ) -> bool {
        let mut packets = self.packets.lock().unwrap();
        if packets.len() >= MAX_RECORDS {
            return false;
        }
        assert!(!packets.contains_key(&pn), "packet number reserved twice");
        packets.insert(
            pn,
            SentPacket {
                path: Arc::downgrade(path),
                status: SentState::Pending,
                generation,
                frames: frames.to_vec(),
                loss_pending: false,
                expires: None,
                retention: Duration::from_secs(3),
            },
        );
        true
    }
    /// Caller holds the connection's submission boundary through actual I/O and on_sent.
    pub fn can_submit(&self, pn: u64) -> bool {
        let largest = self.largest_submitted.load(Ordering::Acquire);
        largest == u64::MAX || pn > largest
    }
    pub fn on_sent(&self, pn: u64, in_flight: bool, retention: Duration) {
        let mut packets = self.packets.lock().unwrap();
        let record = packets.get_mut(&pn).expect("pending packet has a record");
        record.status = SentState::Sent;
        record.retention = retention;
        self.largest_submitted.store(pn, Ordering::Release);
        self.journal.on_rcvd_pn(pn, false, Duration::ZERO);
        if !in_flight {
            packets.remove(&pn);
        }
    }
    pub fn abort(&self, pn: u64) -> Vec<Frame<()>> {
        let mut packets = self.packets.lock().unwrap();
        if packets
            .get(&pn)
            .is_some_and(|record| record.status == SentState::Pending)
        {
            return packets.remove(&pn).unwrap().frames;
        }
        Vec::new()
    }
    pub(crate) fn mark_lost(&self, pns: &mut dyn Iterator<Item = u64>) {
        let mut packets = self.packets.lock().unwrap();
        for pn in pns {
            if let Some(record) = packets.get_mut(&pn) {
                record.loss_pending = true;
            }
        }
    }
    pub fn take_lost(&self) -> Vec<Frame<()>> {
        let mut packets = self.packets.lock().unwrap();
        let mut frames = Vec::new();
        let now = Instant::now();
        packets.retain(|_, record| {
            if record.loss_pending && record.status == SentState::Sent {
                record.loss_pending = false;
                frames.extend(record.frames.iter().cloned());
                record.expires.get_or_insert(now + record.retention);
            }
            record.expires.is_none_or(|expires| now < expires)
        });
        frames
    }

    /// Serialized with submission by the caller; ACK cannot race CC's on_pkt_sent.
    #[allow(clippy::type_complexity)]
    pub fn acknowledge(
        &self,
        ack: &AckFrame,
    ) -> Result<Vec<(Arc<Path>, Vec<(u64, u64, Vec<Frame<()>>)>)>, Error> {
        let largest = self.largest_submitted.load(Ordering::Acquire);
        // qbase's decoder reads ACK fields; validate range arithmetic before its
        // iterators or CC can see an authenticated but malformed ACK.
        let invalid = || crate::error(ErrorKind::FrameEncoding, "invalid ACK range");
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
        if largest == u64::MAX
            || ack.largest() > largest
            || ranges
                .iter()
                .any(|range| !self.journal.covers_range(range.clone()))
        {
            return Err(crate::error(
                ErrorKind::ProtocolViolation,
                "ACK acknowledges an unsent packet",
            ));
        }
        let mut packets = self.packets.lock().unwrap();
        let numbers = packets
            .keys()
            .copied()
            .filter(|pn| ranges.iter().any(|r| r.contains(pn)))
            .collect::<Vec<_>>();
        let mut paths: BTreeMap<usize, (Arc<Path>, Vec<_>)> = BTreeMap::new();
        for pn in numbers {
            let record = packets.remove(&pn).unwrap();
            if let Some(path) = record.path.upgrade() {
                paths
                    .entry(Arc::as_ptr(&path) as usize)
                    .or_insert_with(|| (path, Vec::new()))
                    .1
                    .push((pn, record.generation, record.frames));
            }
        }
        Ok(paths.into_values().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn regression_invalid_ack_ranges_return_an_error_without_underflow() {
        let records = SentPackets::default();
        let malformed = AckFrame::new(0u32.into(), 0u32.into(), 1u32.into(), vec![], None);
        assert!(records.acknowledge(&malformed).is_err());
    }

    #[test]
    fn concurrent_packet_allocation_is_unique_and_exhaustion_never_wraps() {
        let records = Arc::new(SentPackets::default());
        let numbers = std::thread::scope(|scope| {
            (0..4)
                .map(|_| {
                    let records = &records;
                    scope.spawn(move || {
                        (0..1000)
                            .map(|_| records.next_pn().unwrap())
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
        assert_eq!(records.next_pn().unwrap(), 4000);
        records.next_pn.store(VARINT_MAX, Ordering::Release);
        assert_eq!(records.next_pn().unwrap(), VARINT_MAX);
        assert!(records.next_pn().is_err());
        assert!(records.next_pn().is_err());
    }
}
