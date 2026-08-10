use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use qbase::{
    error::{ErrorKind, QuicError},
    frame::{AckFrame, GetFrameType},
    packet::PacketNumber,
    varint::VARINT_MAX,
};
use tokio::time::Instant;

/// State for a sent packet that contains frames requiring ACK/loss feedback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SentPktState {
    Flighting {
        nframes: usize,
        sent_time: Instant,
        expire_time: Instant,
        retran_time: Instant,
    },
    Retransmitted {
        nframes: usize,
        sent_time: Instant,
        expire_time: Instant,
    },
    Acked {
        nframes: usize,
        sent_time: Instant,
        expire_time: Instant,
    },
}

impl SentPktState {
    fn new(nframes: usize, sent_time: Instant, retran_time: Instant, expire_time: Instant) -> Self {
        Self::Flighting {
            nframes,
            sent_time,
            retran_time,
            expire_time,
        }
    }

    fn nframes(&self) -> usize {
        match self {
            Self::Flighting { nframes, .. }
            | Self::Retransmitted { nframes, .. }
            | Self::Acked { nframes, .. } => *nframes,
        }
    }

    fn be_acked(&mut self) -> usize {
        match *self {
            Self::Flighting {
                nframes,
                sent_time,
                expire_time,
                ..
            }
            | Self::Retransmitted {
                nframes,
                sent_time,
                expire_time,
            } => {
                *self = Self::Acked {
                    nframes,
                    sent_time,
                    expire_time,
                };
                nframes
            }
            Self::Acked { .. } => 0,
        }
    }

    fn maybe_lost(&mut self) -> usize {
        match *self {
            Self::Flighting {
                nframes,
                sent_time,
                expire_time,
                ..
            } => {
                *self = Self::Retransmitted {
                    nframes,
                    sent_time,
                    expire_time,
                };
                nframes
            }
            Self::Retransmitted { nframes, .. } => nframes,
            Self::Acked { .. } => 0,
        }
    }

    fn should_retransmit_after(&mut self, now: Instant) -> bool {
        match *self {
            Self::Flighting {
                nframes,
                sent_time,
                retran_time,
                expire_time,
            } if retran_time < now => {
                *self = Self::Retransmitted {
                    nframes,
                    sent_time,
                    expire_time,
                };
                true
            }
            _ => false,
        }
    }

    fn should_remain_after(&self, pn: u64, now: Instant) -> bool {
        match self {
            Self::Flighting { .. } => true,
            Self::Retransmitted { expire_time, .. } => {
                if *expire_time > now {
                    true
                } else {
                    tracing::trace!(target: "dquic", "retransmitted packet {pn} expired without ACK");
                    false
                }
            }
            Self::Acked { .. } => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SentPacketRecord {
    packet_number: u64,
    state: SentPktState,
}

/// Reliable-frame feedback journal for sent packets.
///
/// Packet numbers are allocated by `next_pn`, while `sent_packets` only stores packets containing
/// reliable frames. Pure ACK/PING/PADDING packets consume packet numbers but allocate no journal
/// record, so a long-lived earlier packet cannot pin a dense tail of `Skipped` entries.
#[derive(Debug, Default)]
struct SentJournal<T> {
    queue: VecDeque<T>,
    sent_packets: VecDeque<SentPacketRecord>,
    next_pn: u64,
    largest_acked_pktno: u64,
}

impl<T: Clone> SentJournal<T> {
    fn record_index_and_offset(&self, pn: u64) -> Option<(usize, usize)> {
        let mut offset = 0;
        for (index, record) in self.sent_packets.iter().enumerate() {
            if record.packet_number == pn {
                return Some((index, offset));
            }
            if record.packet_number > pn {
                break;
            }
            offset += record.state.nframes();
        }
        None
    }

    fn on_packet_acked(&mut self, pn: u64) -> impl Iterator<Item = T> + '_ {
        let (offset, len) = self
            .record_index_and_offset(pn)
            .map(|(index, offset)| {
                let len = self.sent_packets[index].state.be_acked();
                (offset, len)
            })
            .unwrap_or_default();
        self.queue.range(offset..offset + len).cloned()
    }

    fn may_loss_packet(&mut self, pn: u64) -> impl Iterator<Item = T> + '_ {
        let (offset, len) = self
            .record_index_and_offset(pn)
            .map(|(index, offset)| {
                let len = self.sent_packets[index].state.maybe_lost();
                (offset, len)
            })
            .unwrap_or_default();
        self.queue.range(offset..offset + len).cloned()
    }

    fn fast_retransmit(&mut self) -> std::vec::IntoIter<T> {
        self.resize();
        let now = Instant::now();
        let largest_acked = self.largest_acked_pktno;
        let mut offset = 0;
        let mut frames = Vec::new();
        for record in self
            .sent_packets
            .iter_mut()
            .take_while(|record| record.packet_number < largest_acked)
        {
            let end = offset + record.state.nframes();
            if record.state.should_retransmit_after(now) {
                frames.extend(self.queue.range(offset..end).cloned());
            }
            offset = end;
        }
        frames.into_iter()
    }
}

impl<T> SentJournal<T> {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity * 4),
            sent_packets: VecDeque::with_capacity(capacity),
            next_pn: 0,
            largest_acked_pktno: 0,
        }
    }

    fn resize(&mut self) {
        let now = Instant::now();
        let (records, frames) = self
            .sent_packets
            .iter()
            .take_while(|record| !record.state.should_remain_after(record.packet_number, now))
            .fold((0usize, 0usize), |(records, frames), record| {
                (records + 1, frames + record.state.nframes())
            });
        self.sent_packets.drain(..records);
        self.queue.drain(..frames);
    }
}

/// Records sent packets and the reliable frames they contain.
#[derive(Debug, Default)]
pub struct ArcSentJournal<T>(Arc<Mutex<SentJournal<T>>>);

impl<T> Clone for ArcSentJournal<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> ArcSentJournal<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(SentJournal::with_capacity(capacity))))
    }

    pub fn rotate(&self) -> SentRotateGuard<'_, T> {
        SentRotateGuard {
            inner: self.0.lock().unwrap(),
        }
    }

    pub fn new_packet(&self) -> NewPacketGuard<'_, T> {
        let inner = self.0.lock().unwrap();
        assert!(inner.next_pn <= VARINT_MAX, "packet number exhausted");
        let packet_number = inner.next_pn;
        let origin_len = inner.queue.len();
        NewPacketGuard {
            trivial: false,
            committed: false,
            packet_number,
            origin_len,
            inner,
        }
    }
}

/// Handles peer ACK/loss feedback for retained reliable packets.
pub struct SentRotateGuard<'a, T> {
    inner: MutexGuard<'a, SentJournal<T>>,
}

impl<T: Clone> SentRotateGuard<'_, T> {
    pub fn update_largest(&mut self, ack_frame: &AckFrame) -> Result<(), QuicError> {
        if ack_frame.largest() >= self.inner.next_pn {
            return Err(QuicError::new(
                ErrorKind::ProtocolViolation,
                ack_frame.frame_type().into(),
                "ACK frame largest PN is not smaller than the next PN to send",
            ));
        }
        self.inner.largest_acked_pktno = self.inner.largest_acked_pktno.max(ack_frame.largest());
        Ok(())
    }

    pub fn on_packet_acked(&mut self, pn: u64) -> impl Iterator<Item = T> + '_ {
        self.inner.on_packet_acked(pn)
    }

    pub fn may_loss_packet(&mut self, pn: u64) -> impl Iterator<Item = T> + '_ {
        self.inner.may_loss_packet(pn)
    }

    pub fn fast_retransmit(&mut self) -> impl Iterator<Item = T> + '_ {
        self.inner.fast_retransmit()
    }
}

impl<T> Drop for SentRotateGuard<'_, T> {
    fn drop(&mut self) {
        self.inner.resize();
    }
}

/// Reserves a packet number and records frames while a packet is assembled.
///
/// Dropping this guard before either build method rolls back tentative frames and leaves the packet
/// number available for reuse. A successful build consumes the PN but stores a record only when the
/// packet contains reliable frames.
#[derive(Debug)]
pub struct NewPacketGuard<'a, T> {
    trivial: bool,
    committed: bool,
    packet_number: u64,
    origin_len: usize,
    inner: MutexGuard<'a, SentJournal<T>>,
}

impl<T> NewPacketGuard<'_, T> {
    pub fn pn(&self) -> (u64, PacketNumber) {
        let encoded_pn = PacketNumber::encode(self.packet_number, self.inner.largest_acked_pktno);
        (self.packet_number, encoded_pn)
    }

    pub fn record_trivial(&mut self) {
        self.trivial = true;
    }

    pub fn record_frame(&mut self, frame: T) {
        self.inner.queue.push_back(frame);
    }

    fn commit(&mut self) {
        debug_assert_eq!(self.inner.next_pn, self.packet_number);
        self.inner.next_pn = self
            .inner
            .next_pn
            .checked_add(1)
            .expect("packet number never overflows u64");
        self.committed = true;
    }

    pub fn build_with_time(mut self, retran_timeout: Duration, expire_timeout: Duration) {
        let nframes = self.inner.queue.len() - self.origin_len;
        assert!(self.trivial || nframes > 0, "cannot commit an empty packet");
        if nframes > 0 {
            let sent_time = Instant::now();
            self.inner.sent_packets.push_back(SentPacketRecord {
                packet_number: self.packet_number,
                state: SentPktState::new(
                    nframes,
                    sent_time,
                    sent_time + retran_timeout,
                    sent_time + expire_timeout,
                ),
            });
        }
        self.commit();
    }

    pub fn build_trivial(mut self) {
        assert_eq!(self.inner.queue.len(), self.origin_len);
        assert!(self.trivial);
        self.commit();
    }
}

impl<T> Drop for NewPacketGuard<'_, T> {
    fn drop(&mut self) {
        if !self.committed {
            self.inner.queue.truncate(self.origin_len);
        }
    }
}

#[cfg(test)]
mod tests {
    use qbase::{frame::AckFrame, varint::VarInt};

    use super::*;

    fn ack_packet(pn: u64) -> AckFrame {
        AckFrame::new(
            VarInt::from_u64(pn).unwrap(),
            0_u32.into(),
            0_u32.into(),
            vec![],
            None,
        )
    }

    #[test]
    fn trivial_packets_only_advance_next_packet_number() {
        let journal = ArcSentJournal::<u64>::with_capacity(1);
        for expected in 0..100_000 {
            let mut packet = journal.new_packet();
            assert_eq!(packet.pn().0, expected);
            packet.record_trivial();
            packet.build_trivial();
        }
        let inner = journal.0.lock().unwrap();
        assert_eq!(inner.next_pn, 100_000);
        assert!(inner.sent_packets.is_empty());
        assert!(inner.queue.is_empty());
    }

    #[test]
    fn dropped_packet_rolls_back_frames_and_packet_number() {
        let journal = ArcSentJournal::<u64>::with_capacity(1);
        {
            let mut packet = journal.new_packet();
            assert_eq!(packet.pn().0, 0);
            packet.record_frame(7);
        }
        let packet = journal.new_packet();
        assert_eq!(packet.pn().0, 0);
        drop(packet);
        let inner = journal.0.lock().unwrap();
        assert_eq!(inner.next_pn, 0);
        assert!(inner.sent_packets.is_empty());
        assert!(inner.queue.is_empty());
    }

    #[test]
    fn sparse_reliable_packets_keep_exact_packet_numbers() {
        let journal = ArcSentJournal::<u64>::with_capacity(4);
        for pn in 0..6 {
            let mut packet = journal.new_packet();
            if pn == 1 || pn == 5 {
                packet.record_frame(pn);
                packet.build_with_time(Duration::from_secs(1), Duration::from_secs(2));
            } else {
                packet.record_trivial();
                packet.build_trivial();
            }
        }

        let mut rotate = journal.rotate();
        rotate.update_largest(&ack_packet(5)).unwrap();
        assert_eq!(rotate.on_packet_acked(5).collect::<Vec<_>>(), vec![5]);
        assert!(rotate.on_packet_acked(4).next().is_none());
    }

    #[test]
    fn ack_for_unsent_packet_is_rejected() {
        let journal = ArcSentJournal::<u64>::with_capacity(1);
        let mut packet = journal.new_packet();
        packet.record_trivial();
        packet.build_trivial();
        assert!(journal.rotate().update_largest(&ack_packet(1)).is_err());
        assert!(journal.rotate().update_largest(&ack_packet(0)).is_ok());
    }
}
