use std::{
    collections::VecDeque,
    ops::DerefMut,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use derive_more::{Deref, DerefMut};
use qbase::{
    error::{ErrorKind, QuicError},
    frame::{AckFrame, GetFrameType},
    packet::PacketNumber,
    util::IndexDeque,
    varint::VARINT_MAX,
};
use tokio::time::Instant;

/// 记录发送的数据包的状态，包括
/// - Flighting: 数据包正在传输中
/// - Acked: 数据包已经被确认
/// - Lost: 数据包丢失
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SentPktState {
    Skipped,
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
    #[allow(dead_code)]
    fn skipped() -> Self {
        Self::Skipped
    }

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
            SentPktState::Skipped => 0,
            SentPktState::Flighting { nframes, .. } => *nframes,
            SentPktState::Retransmitted { nframes, .. } => *nframes,
            SentPktState::Acked { nframes, .. } => *nframes,
        }
    }

    fn be_acked(&mut self) -> usize {
        match *self {
            SentPktState::Skipped => 0,
            SentPktState::Flighting {
                nframes,
                sent_time,
                expire_time,
                ..
            } => {
                *self = SentPktState::Acked {
                    nframes,
                    sent_time,
                    expire_time,
                };
                nframes
            }
            SentPktState::Retransmitted {
                nframes,
                sent_time,
                expire_time,
                ..
            } => {
                *self = SentPktState::Acked {
                    nframes,
                    sent_time,
                    expire_time,
                };
                nframes
            }
            SentPktState::Acked { .. } => 0,
        }
    }

    fn maybe_lost(&mut self) -> usize {
        match *self {
            SentPktState::Flighting {
                nframes,
                sent_time,
                expire_time,
                ..
            } => {
                *self = SentPktState::Retransmitted {
                    nframes,
                    sent_time,
                    expire_time,
                };
                nframes
            }
            Self::Retransmitted { nframes, .. } => nframes,
            _ => 0,
        }
    }

    fn should_retransmit_after(&mut self, now: &Instant) -> bool {
        match *self {
            SentPktState::Flighting {
                sent_time,
                retran_time,
                expire_time,
                ..
            } if retran_time < *now => {
                *self = SentPktState::Retransmitted {
                    nframes: self.nframes(),
                    sent_time,
                    expire_time,
                };
                true
            }
            _ => false,
        }
    }

    fn should_remain_after(&self, pn: u64, now: &Instant) -> bool {
        match self {
            SentPktState::Skipped => false,
            SentPktState::Flighting { .. } => true,
            SentPktState::Retransmitted { expire_time, .. } => {
                if expire_time > now {
                    true
                } else {
                    tracing::trace!(target: "dquic", "retransmitted packet {pn} is expired without ack");
                    false
                }
            }
            SentPktState::Acked { .. } => false,
        }
    }
}

/// 记录已经发送的帧，尽最大努力省略内存分配。
/// queue记录着所有发送过的帧，records记录着顺序发送的数据包包含几个帧，以及这些数据包的状态。
/// 发送数据包的时候，往其中写入数据包的帧，
/// 接收到确认的时候，更新数据包的状态，被确认就什么都不做；丢失的数据包，得重新发送
#[derive(Debug, Default, Deref, DerefMut)]
struct SentJournal<T> {
    #[deref]
    #[deref_mut]
    queue: VecDeque<T>,
    // 记录着每个包的内容，其实是一个数字，该数字对应着queue中的record数量
    sent_packets: IndexDeque<SentPktState, VARINT_MAX>,
    largest_acked_pktno: u64,
}

impl<T: Clone> SentJournal<T> {
    fn on_packet_acked(&mut self, pn: u64) -> impl Iterator<Item = T> + '_ {
        let mut len = 0;
        let offset = self
            .sent_packets
            .enumerate()
            .take_while(|(pkt_idx, _)| *pkt_idx < pn)
            .map(|(_, s)| s.nframes())
            .sum::<usize>();
        if let Some(s) = self.sent_packets.get_mut(pn) {
            len = s.be_acked();
        }
        self.queue
            .range_mut(offset..offset + len)
            .map(|f| f.clone())
    }

    fn may_loss_packet(&mut self, pn: u64) -> impl Iterator<Item = T> + '_ {
        let mut len = 0;
        let offset = self
            .sent_packets
            .enumerate()
            // TODO(optimize): 调用者是一种遍历，每次都从头take_while，可以优化
            .take_while(|(pkt_idx, _)| *pkt_idx < pn)
            .map(|(_, s)| s.nframes())
            .sum::<usize>();
        if let Some(s) = self.sent_packets.get_mut(pn) {
            len = s.maybe_lost();
        }
        self.queue
            .range_mut(offset..offset + len)
            .map(|f| f.clone())
    }

    fn fast_retransmit(&mut self) -> impl Iterator<Item = T> + '_ {
        self.resize();

        let now = tokio::time::Instant::now();
        self.sent_packets
            .enumerate_mut()
            .take_while(|(pn, _)| *pn < self.largest_acked_pktno)
            .scan(0, move |sum, (_, s)| {
                let start = *sum;
                *sum += s.nframes();
                Some((s.should_retransmit_after(&now), start..*sum))
            })
            .filter(|(should_retran, _)| *should_retran)
            .flat_map(|(_, r)| self.queue.range(r))
            .cloned()
    }
}

impl<T> SentJournal<T> {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity * 4),
            sent_packets: IndexDeque::with_capacity(capacity),
            largest_acked_pktno: 0,
        }
    }

    fn resize(&mut self) {
        let now = Instant::now();
        let (n, f) = self
            .sent_packets
            .enumerate()
            .take_while(|(pn, s)| !s.should_remain_after(*pn, &now))
            .fold((0usize, 0usize), |(n, f), (_, s)| (n + 1, f + s.nframes()));
        self.sent_packets.advance(n);
        _ = self.queue.drain(..f);
    }
}

/// Records for sent packets and frames in them.
///
/// [`DataStreams`] need to be aware of frame acknowledgment or possible loss, and so does [`CryptoStream`].
/// This structure records some frames (type T) in each packet sent, and feeds back the frames in
/// these packets to [`DataStreams`] and [`CryptoStream`] when the packet is acknowledged or may be
/// lost.
///
/// The interfaces are on the [`NewPacketGuard`] structure and the [`SentRotateGuard`] structure, read their
/// documentation for more. This structure only provide the methods to create them.
///
/// If multiple tasks are recording at the same time, the recording will become confusing, so the
/// [`NewPacketGuard`] and the [`SentRotateGuard`] are designed to be `Guard`, which means that they hold a
/// [`MutexGuard`].
///
///
/// [`DataStreams`]: crate::streams::DataStreams
/// [`CryptoStream`]: crate::crypto::CryptoStream
#[derive(Debug, Default)]
pub struct ArcSentJournal<T>(Arc<Mutex<SentJournal<T>>>);

impl<T> Clone for ArcSentJournal<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> ArcSentJournal<T> {
    /// Create a new empty records with the given `capatity`.
    ///
    /// The number of records can exceed the `capacity` specified at creation time, but the internel
    /// implementation strvies to avoid reallocation.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(SentJournal::with_capacity(capacity))))
    }

    /// Return a [`SentRotateGuard`] to resolve the ack frame from peer.
    pub fn rotate(&self) -> SentRotateGuard<'_, T> {
        SentRotateGuard {
            inner: self.0.lock().unwrap(),
        }
    }

    /// Return a [`NewPacketGuard`] to get the next pn and record frames in the packet.
    pub fn new_packet(&self) -> NewPacketGuard<'_, T> {
        let inner = self.0.lock().unwrap();
        let origin_len = inner.queue.len();
        NewPacketGuard {
            trivial: false,
            origin_len,
            inner,
        }
    }
}

/// Handle the peer's ack frame and feed back the frames in the acknowledged or possibly lost packets to other components.
pub struct SentRotateGuard<'a, T> {
    inner: MutexGuard<'a, SentJournal<T>>,
}

impl<T: Clone> SentRotateGuard<'_, T> {
    /// Handle the [`Largest Acknowledged`] field of the ack frame from peer.
    ///
    /// [`Largest Acknowleged`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
    pub fn update_largest(&mut self, ack_frame: &AckFrame) -> Result<(), QuicError> {
        if ack_frame.largest() > self.inner.sent_packets.largest() {
            return Err(QuicError::new(
                ErrorKind::ProtocolViolation,
                ack_frame.frame_type().into(),
                "ack frame largest pn is larger than the largest pn sent",
            ));
        }
        if ack_frame.largest() > self.inner.largest_acked_pktno {
            self.inner.largest_acked_pktno = ack_frame.largest();
        }
        Ok(())
    }

    /// Called when the packet sent is acked by peer, return the frames in that packet.
    pub fn on_packet_acked(&mut self, pn: u64) -> impl Iterator<Item = T> + '_ {
        self.inner.on_packet_acked(pn)
    }

    /// Called when the packet sent may lost, reutrn the frames in that packet.
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

/// Provide the [encoded] packet number to assemble a packet, and record the frames in packet which
/// will be send.
///
/// One [`NewPacketGuard`] correspond to a packet.
///
/// Even if the next packet number is obtained, the packet may not be sent out. If the packet is not
/// sent out, the packet number will not be consumed.
///
/// Call [`NewPacketGuard::record_trivial`] or [`NewPacketGuard::record_frame`] means that the packet will be
/// correspond to this [`NewPacketGuard`] will be sent, and the packet number will be consumed when the
/// [`NewPacketGuard`] dropped.
///
/// [encoded]: https://www.rfc-editor.org/rfc/rfc9000.html#name-sample-packet-number-encodi
#[derive(Debug)]
pub struct NewPacketGuard<'a, T> {
    trivial: bool,
    origin_len: usize,
    inner: MutexGuard<'a, SentJournal<T>>,
}

impl<T> NewPacketGuard<'_, T> {
    /// Provide a packet number and its [encoded] form to assemble a packet.
    ///
    /// Call this method multipes on the same [`NewPacketGuard`] will result the same pn.
    ///
    /// [encoded]: https://www.rfc-editor.org/rfc/rfc9000.html#name-sample-packet-number-encodi
    pub fn pn(&self) -> (u64, PacketNumber) {
        let pn = self.inner.sent_packets.largest();
        let encoded_pn = PacketNumber::encode(pn, self.inner.largest_acked_pktno);
        (pn, encoded_pn)
    }

    /// Records trivial frames that do not need retransmission, such as Padding, Ping, and Ack.
    /// However, this packet does occupy a packet number. Even if no other reliable frames are sent,
    /// it still needs to be recorded, with the number of reliable frames in this packet being 0.
    pub fn record_trivial(&mut self) {
        self.trivial = true;
    }

    /// Records a frame in the packet being sent.
    ///
    /// Once this method or [`NewPacketGuard::record_trivial`] called, the packet number will be consumed.
    ///
    /// When the packet is acked, or may loss, the frames in packet will been fed back to the
    /// components which sent them.
    pub fn record_frame(&mut self, frame: T) {
        self.inner.deref_mut().push_back(frame);
    }

    pub fn build_with_time(mut self, retran_timeout: Duration, expire_timeout: Duration) {
        let nframes = self.inner.queue.len() - self.origin_len;
        let sent_time = tokio::time::Instant::now();
        if self.trivial && nframes == 0 {
            self.inner
                .sent_packets
                .push_back(SentPktState::Skipped)
                .expect("packet number never overflow");
        } else if nframes > 0 {
            self.inner
                .sent_packets
                .push_back(SentPktState::new(
                    nframes,
                    sent_time,
                    sent_time + retran_timeout,
                    sent_time + expire_timeout,
                ))
                .expect("packet number never overflow");
        }
    }

    pub fn build_trivial(mut self) {
        assert_eq!(self.inner.queue.len(), self.origin_len);
        assert!(self.trivial);
        self.inner
            .sent_packets
            .push_back(SentPktState::Skipped)
            .expect("packet number never overflow");
    }
}
