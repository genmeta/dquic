use std::{
    cmp::Ordering,
    collections::VecDeque,
    fmt::{Debug, Display},
    ops::Range,
    task::Poll,
};

use bytes::Bytes;

/// To indicate the state of a data segment, it is colored.
#[derive(Default, PartialEq, Eq, Clone, Copy, Debug)]
enum Color {
    #[default]
    Pending,
    Flighting,
    Recved,
    Lost,
}

impl Color {
    fn prefix(&self) -> u64 {
        match self {
            Self::Pending => 0,
            Self::Flighting => 0b01 << 62,
            Self::Lost => 0b10 << 62,
            Self::Recved => 0b11 << 62,
        }
    }
}

#[derive(PartialEq, PartialOrd, Eq, Clone, Copy)]
struct State(u64);

impl State {
    #[allow(dead_code)]
    const PREFIX: u64 = 0b11 << 62;
    const SUFFIX: u64 = u64::MAX >> 2;

    fn encode(pos: u64, color: Color) -> Self {
        Self(color.prefix() | pos)
    }

    fn offset(&self) -> u64 {
        self.0 & Self::SUFFIX
    }

    fn color(&self) -> Color {
        match self.0 >> 62 {
            0b00 => Color::Pending,
            0b01 => Color::Flighting,
            0b10 => Color::Lost,
            0b11 => Color::Recved,
            _ => unreachable!("impossible"),
        }
    }

    fn set_color(&mut self, value: Color) {
        self.0 = (self.0 & Self::SUFFIX) | value.prefix();
    }

    fn decode(&self) -> (u64, Color) {
        (self.offset(), self.color())
    }
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}: {:?}]", self.offset(), self.color())
    }
}

impl Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}: {:?}]", self.offset(), self.color())
    }
}

/**
 * Self.0 意思是区间状态信息，它由一段VecDeque表示；
 * VecDeque中的每个元素是State，其中低62位是offset，代高2位是颜色，代表着到下一个State::offset的区间颜色。
 * Self.1代表着结尾位置，不包括Self.1; VecDeque中最后一个元素代表的状态区间，是最后一个State::offset到Self.1的区间。
 * 之所以采用这种数据结构，是考虑到CPU缓存行有64字节，可一次处理8段数据，足够很多小流传输了，很高效。
 * 即便是大流，其中相同状态的合并起来，各种不同状态的区间也不会很多，相比于链表、跳表、线段树等结构依然很高效。
 */
#[derive(Default, Debug)]
struct BufMap(VecDeque<State>, u64);

impl BufMap {
    fn size(&self) -> u64 {
        self.1
    }

    // 追加写数据
    fn extend_to(&mut self, pos: u64) -> u64 {
        debug_assert!(pos < (1 << 62), "pos({pos}) overflow",);
        debug_assert!(pos >= self.size(), "pos({pos}) less than {}", self.size());

        if pos > self.size() {
            let back = self.0.back();
            match back {
                Some(s) if s.color() == Color::Pending => {}
                _ => self.0.push_back(State::encode(self.size(), Color::Pending)),
            };
            self.1 = pos;
        }
        self.size()
    }

    fn sent(&self) -> u64 {
        match self.0.back() {
            Some(s) if s.color() == Color::Pending => s.offset(),
            _ => self.size(),
        }
    }

    // 挑选Lost/Pending的数据发送。越靠前的数据，越高优先级发送；
    // 丢包重传的数据，相比于Pending数据更靠前，因此具有更高的优先级。
    fn pick<P>(
        &mut self,
        predicate: P,
        flow_limit: usize,
        send_window_size: u64,
    ) -> Result<(Range<u64>, bool), Poll<()>>
    where
        P: Fn(u64) -> Option<usize>,
    {
        let mut availability = Poll::Pending;
        // 先找到第一个能发送的区间，并将该区间染成Flight，返回原State
        self.0
            .iter_mut()
            .enumerate()
            .find(|(.., state)| {
                if state.offset() >= send_window_size {
                    // 如果offset已经超过了发送窗口大小，说明该区间不能被发送
                    availability = Poll::Ready(());
                    return false;
                }
                // 选择Pending的区间（如果流控允许），或者选择Lost的区间
                match state.color() {
                    Color::Pending if flow_limit != 0 => return true,
                    Color::Pending => availability = Poll::Ready(()),
                    Color::Lost => return true,
                    _ => {}
                }
                false
            })
            .and_then(|(idx, state)| {
                // 如果区间的offset不符合predicate，就不发送这一段
                // 其实选择到的第一段数据数据的offset已经是最小的了，如果最小的offset都不能发送，那么后面片段肯定也不能发送
                let Some(available) = predicate(state.offset()) else {
                    availability = Poll::Ready(());
                    return None;
                };

                let allowance = if state.color() == Color::Lost {
                    // 重传不受流量控制限制
                    available
                } else {
                    available.min(flow_limit)
                };
                Some((idx, allowance, state))
            })
            .map(|(index, allowance, state)| {
                let origin_state = *state; // 此处能归还self.0的可变借用
                state.set_color(Color::Flighting);
                (index, origin_state, allowance)
            })
            .map(|(index, origin_state, allowance)| {
                // 找到了一个合适的区间来发送，但检查区间长度是否足够，过长的话，还要拆区间一分为二
                let (start, color) = origin_state.decode();
                let mut end = self
                    .0
                    .get(index + 1)
                    .map(|s| s.offset())
                    .unwrap_or(self.size())
                    .min(send_window_size);

                let mut i = self.same_before(index, Color::Flighting);
                if start + (allowance as u64) < end {
                    end = start + allowance as u64;
                    if i < index {
                        // 一分为二，如果本来有合并删除的区间，直接旧state回收复用
                        *self.0.get_mut(i + 1).unwrap() = State::encode(end, color);
                    } else {
                        self.0.insert(i + 1, State::encode(end, color));
                    }
                    i += 1;
                } else {
                    // TODO: 这里有个优化，如果紧跟着下一个是Lost或者Pending，可以连起来
                    self.merge_after(index, Color::Flighting);
                }
                // i仍然小于index，说明有需要删除直到index的state，意味着前向合并请求，一次drain即可
                if i < index {
                    self.0.drain(i + 1..=index);
                }
                (start..end, color == Color::Pending)
            })
            .ok_or(availability)
    }

    // 收到了ack确认，确认的数据不需再发送，对于头部连续确认的数据，就可以删掉。
    // 寻找到ack区间所在的位置，将这些区间都染成Recved，然后检查前后是否有需要合并的区间，合并之。
    // ack区间，不能ack到Pending的数据，因为Pending的数据尚未发送过，当然无法被ack。
    fn ack_rcvd(&mut self, range: &Range<u64>) {
        let pos = self.0.binary_search_by(|s| s.offset().cmp(&range.start));
        let (mut drain_start, need_insert_at_start, mut drain_end, mut pre_color) = match pos {
            Ok(idx) => {
                let s = self.0.get_mut(idx).unwrap();
                let pre_color = s.color();
                debug_assert!(
                    pre_color != Color::Pending,
                    "Recved Range({:?}) covered Pending part from {}",
                    range,
                    s.offset()
                );
                s.set_color(Color::Recved);
                (
                    self.same_before(idx, Color::Recved) + 1,
                    false,
                    idx + 1,
                    pre_color,
                )
            }
            Err(idx) => {
                if idx == 0 {
                    (0, false, 0, Color::Recved)
                } else {
                    let s = self.0.get(idx - 1).unwrap();
                    let pre_color = s.color();
                    debug_assert!(
                        pre_color != Color::Pending,
                        "Recved Range({:?}) covered Pending part from {}",
                        range,
                        s.offset()
                    );
                    (idx, pre_color != Color::Recved, idx, pre_color)
                }
            }
        };

        let mut need_insert_at_end = false;
        loop {
            let entry = self.0.get(drain_end);
            match entry {
                Some(s) => match s.offset().cmp(&range.end) {
                    Ordering::Less => {
                        debug_assert!(
                            s.color() != Color::Pending,
                            "Recved Range({:?}) covered Pending parts from {}",
                            range,
                            s.offset()
                        );
                        drain_end += 1;
                        pre_color = s.color();
                    }
                    Ordering::Equal => {
                        // TODO: nightly版本, overflowing_sub 改为unchecked_sub更好
                        drain_end = self
                            .same_after(drain_end.overflowing_sub(1).0, Color::Recved)
                            .overflowing_add(1)
                            .0;
                        break;
                    }
                    Ordering::Greater => {
                        need_insert_at_end = pre_color != Color::Recved;
                        break;
                    }
                },
                None => {
                    debug_assert!(
                        range.end <= self.size(),
                        "Recved Range({:?}) over {}",
                        range,
                        self.size()
                    );
                    need_insert_at_end = range.end < self.size() && pre_color != Color::Recved;
                    break;
                }
            }
        }

        if need_insert_at_start {
            if drain_start < drain_end {
                *self.0.get_mut(drain_start).unwrap() = State::encode(range.start, Color::Recved);
            } else {
                self.0
                    .insert(drain_start, State::encode(range.start, Color::Recved));
            }
            drain_start += 1;
        }
        if need_insert_at_end {
            if drain_start < drain_end {
                *self.0.get_mut(drain_start).unwrap() = State::encode(range.end, pre_color);
            } else {
                self.0
                    .insert(drain_start, State::encode(range.end, pre_color));
            }
            drain_start += 1;
        }
        if drain_start < drain_end {
            self.0.drain(drain_start..drain_end);
        }
    }

    // 寻找第一个不是Recved的位置，意味着之前的数据都已经被确认接收，
    // 发送缓冲区可以移动到该位置，以让发送缓冲区腾出更多空间
    fn shift(&mut self) -> u64 {
        loop {
            let entry = self.0.front();
            match entry {
                Some(s) if s.color() == Color::Recved => _ = self.0.pop_front(),
                Some(s) => return s.offset(),
                None => return self.size(),
            }
        }
    }

    // 判定某部分数据丢失，但不一定真的丢失，判定可能有误；丢失的数据需要优先重传。
    // 寻找到丢失区间覆盖的范围，其中若遇到Recved的区间，则忽略；只有Flighting/Lost的才可以丢失。
    // 然后检查Lost区间前后是否有需要合并的区间，合并之。
    // 同样地，Lost区间不能覆盖Pending的数据，因为Pending的数据尚未发送过，无法丢失。
    fn may_loss(&mut self, range: &Range<u64>) {
        let pos = self.0.binary_search_by(|s| s.offset().cmp(&range.start));
        let (mut drain_start, need_insert_at_start, mut drain_end, mut pre_color) = match pos {
            Ok(idx) => {
                let s = self.0.get_mut(idx).unwrap();
                debug_assert!(
                    s.color() != Color::Pending,
                    "Lost Range({:?}) covered Pending parts from {}",
                    range,
                    s.offset()
                );
                if s.color() == Color::Recved {
                    // 如果是Recved，那就不需要在前面插入了，直接往后探索
                    self.may_lost_from(idx + 1, range.end);
                    return;
                }

                let pre_color = s.color();
                let mut drain_start = idx;
                if pre_color == Color::Flighting {
                    s.set_color(Color::Lost);
                    // 只有变化了，才会向前寻找同为Lost，寻求合并
                    // 如果已经是Lost了，那前面的肯定是无法合并的非Lost状态
                    drain_start = self.same_before(idx, Color::Lost) + 1;
                } else {
                    // 如果是lost，那这一段状态不需要改变，继续探索下一段需不需要改变
                    // 如果下一段还是Lost，那下一段可以删掉，往后合并Lost
                    drain_start += 1;
                }
                // 肯定不需要在前面插入了，从drain_start开始往后探索，pre_color是当前状态
                (drain_start, false, idx + 1, pre_color)
            }
            Err(idx) => {
                if idx == 0 {
                    // 之前的数据都是recved，前面不再需要插入
                    // 表示从0往后，要尝试变为Lost，就完事儿了
                    self.may_lost_from(idx, range.end);
                    return;
                } else {
                    let s = self.0.get(idx - 1).unwrap();
                    let pre_color = s.color();
                    debug_assert!(
                        pre_color != Color::Pending,
                        "Lost Range({:?}) covered Pending parts from {}",
                        range,
                        s.offset()
                    );
                    if pre_color == Color::Recved {
                        // 另有安排，直接调用，lost_from(idx, range.end);
                        self.may_lost_from(idx, range.end);
                        return;
                    }
                    (idx, pre_color == Color::Flighting, idx, pre_color)
                }
            }
        };

        let mut need_insert_at_end = false;
        loop {
            // 从drain_end位置的entry开始遍历，看其是否存在，存在看其是否仍在Lost的range区间里
            let entry = self.0.get(drain_end);
            match entry {
                Some(s) => match s.offset().cmp(&range.end) {
                    Ordering::Less => {
                        // 以s.offset开头的区间，仍在Lost的range区间里
                        debug_assert!(
                            s.color() != Color::Pending,
                            "Lost Range({:?}) covered Pending parts from {}",
                            range,
                            s.offset()
                        );
                        if s.color() == Color::Recved {
                            // s是recved，那就s的下一段到range.end都是丢失的，相当于独立的may_lost区间处理
                            // 接下来只需处理drain_end之前的操作即可
                            self.may_lost_from(drain_end + 1, range.end);
                            break;
                        } else {
                            // s是Lost/Flighting，那就将s染成Lost，继续往后探索
                            drain_end += 1;
                            pre_color = s.color();
                        }
                    }
                    Ordering::Equal => {
                        // s之前的是Lost，从上一个检查后续连续lost状态的有多少个
                        drain_end = self
                            .same_after(drain_end.overflowing_sub(1).0, Color::Lost)
                            .overflowing_add(1)
                            .0;
                        break;
                    }
                    Ordering::Greater => {
                        // s的offset大于range.end，说明s之后的区间都不在Lost的范围内
                        // s的前一个是Flighting，它要一分为二，前部分为Lost，后部分为Flighting
                        need_insert_at_end = pre_color == Color::Flighting;
                        break;
                    }
                },
                None => {
                    // 找不到，说明到最后一段了
                    debug_assert!(
                        range.end <= self.size(),
                        "Lost Range({:?}) over {}",
                        range,
                        self.size()
                    );
                    // 如果上一段的color是Flighting，它要一分为二，到range.end的部分为Lost，后续部分为Flighting
                    need_insert_at_end = range.end < self.size() && pre_color == Color::Flighting;
                    break;
                }
            };
        }

        if need_insert_at_start {
            if drain_start < drain_end {
                *self.0.get_mut(drain_start).unwrap() = State::encode(range.start, Color::Lost);
            } else {
                self.0
                    .insert(drain_start, State::encode(range.start, Color::Lost));
            }
            drain_start += 1;
        }
        if need_insert_at_end {
            if drain_start < drain_end {
                *self.0.get_mut(drain_start).unwrap() = State::encode(range.end, pre_color);
            } else {
                self.0
                    .insert(drain_start, State::encode(range.end, pre_color));
            }
            drain_start += 1;
        }
        if drain_start < drain_end {
            self.0.drain(drain_start..drain_end);
        }
    }

    fn resend_flighting(&mut self) {
        for state in self.0.iter_mut() {
            if state.color() == Color::Flighting {
                state.set_color(Color::Lost);
            }
        }
    }
}

impl BufMap {
    fn same_before(&self, mut index: usize, color: Color) -> usize {
        loop {
            let pre = index.overflowing_sub(1).0;
            match self.0.get(pre) {
                Some(s) if s.color() == color => index = pre,
                _ => break,
            }
        }
        index
    }

    fn same_after(&self, mut index: usize, color: Color) -> usize {
        loop {
            let next = index.overflowing_add(1).0;
            match self.0.get(next) {
                Some(s) if s.color() == color => index = next,
                _ => break,
            }
        }
        index
    }

    fn merge_after(&mut self, index: usize, color: Color) {
        let same_after = self.same_after(index, color);
        if index < same_after {
            self.0.drain(index + 1..=same_after);
        }
    }

    // lost的辅助函数，将idx_start位置的变为Lost，然后向后继续判定丢失
    fn may_lost_from(&mut self, mut idx_start: usize, end: u64) {
        let mut idx = idx_start;
        let mut pre_color = Color::Recved;
        let mut need_insert_at_end = false;
        loop {
            let entry = self.0.get_mut(idx);
            match entry {
                Some(s) => match s.offset().cmp(&end) {
                    Ordering::Less => {
                        debug_assert!(
                            s.color() != Color::Pending,
                            "Lost Range.end({end}) covered Pending parts from {}",
                            s.offset()
                        );
                        pre_color = s.color();
                        if s.color() == Color::Recved {
                            // 另有安排，直接调用，lost_from(idx, range.end);
                            self.may_lost_from(idx + 1, end);
                            break;
                        } else {
                            s.set_color(Color::Lost);
                            idx += 1;
                        }
                    }
                    Ordering::Equal => {
                        idx = self
                            .same_after(idx.overflowing_sub(1).0, Color::Lost)
                            .overflowing_add(1)
                            .0;
                        break;
                    }
                    Ordering::Greater => {
                        need_insert_at_end = pre_color == Color::Flighting;
                        break;
                    }
                },
                None => {
                    debug_assert!(
                        end <= self.size(),
                        "Lost Range.end({end}) over {}",
                        self.size()
                    );
                    need_insert_at_end = end < self.size() && pre_color == Color::Flighting;
                    break;
                }
            }
        }
        if need_insert_at_end {
            if idx_start + 1 < idx {
                *self.0.get_mut(idx_start + 1).unwrap() = State::encode(end, pre_color);
            } else {
                self.0.insert(idx_start + 1, State::encode(end, pre_color));
            }
            idx_start += 1;
        }
        if idx_start + 1 < idx {
            self.0.drain(idx_start + 1..idx);
        }
    }
}

/// Data to be reliably sent to the peer will first be cached in [`SendBuf`].
///
/// SendBuf will record the status of data that has been or has not been sent.
///
/// The transport layer needs to notify that the data it has sent is confirmed([`on_data_acked`]) or lost
/// ([`may_loss_data`]), to uopate the state of [`SendBuf`].
///
/// The transport layer can [`pick_up`] a piece of data that needs to be sent. The data may be new data,
/// or old data that has been sent but has not been acknowledged.
///
/// The data picked up may not continuous, the [`receive buffer`] will assemble the data into continuous before
/// passing them to the application layer.
///
/// [`pick_up`]: SendBuf::pick_up
/// [`on_data_acked`]: SendBuf::on_data_acked
/// [`may_loss_data`]: SendBuf::may_loss_data
/// [`receive buffer`]: crate::recv::RecvBuf
#[derive(Default, Debug)]
pub struct SendBuf {
    offset: u64,
    // 写入数据的队列，与接收队列不同的是，每一段数据都是前后连续的
    data: VecDeque<Bytes>,
    // 对BufMap::size的限制
    max_data: u64,
    state: BufMap,
}

impl SendBuf {
    /// Create a new [`SendBuf`] with the given size.
    pub fn with_capacity(capacity: u64) -> Self {
        Self {
            offset: 0,
            data: VecDeque::new(),
            max_data: capacity,
            state: BufMap::default(),
        }
    }

    /// Write data to the [`SendBuf`].
    ///
    /// When [`SendBuf`] has buffered [`Self::max_data`] amount of data,
    /// no more data should be written.
    pub fn write(&mut self, data: Bytes) {
        // debug_assert!(self.remaining_mut() > 0, "Sendbuf buffers excess data");
        if !data.is_empty() {
            self.state
                .extend_to((self.written() + data.len() as u64).min(self.max_data));
            self.data.push_back(data);
        }
    }

    /// The maximum amount of data that can be sent in the [`SendBuf`].
    ///
    /// For [`DataStreams`], this is the flow control of the stream.
    ///
    /// For [`CryptoStream`], there should be no restrictions.
    ///
    /// [`DataStreams`]: crate::streams::DataStreams
    /// [`CryptoStream`]: crate::crypto::CryptoStream
    pub fn max_data(&self) -> u64 {
        self.max_data
    }

    /// Forget all state of data that has been sent.
    ///
    /// This is usually called when the zero rtt is rejected by server.
    ///
    /// All data sent should be resent as fresh data,
    /// and for the subsequent correction of max_data, max_data is also reset to 0.
    pub fn forget_sent_state(&mut self) {
        self.state = BufMap::default();
        self.max_data = 0;
    }

    /// Extend the [`Self::max_data`] limit.
    pub fn extend(&mut self, max_data: u64) {
        debug_assert!(max_data >= self.max_data, "Cannot reduce sndbuf size");
        self.max_data = max_data;
        self.state.extend_to(self.written().min(self.max_data));
    }

    /// Return whether the [`SendBuf`] is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Return the total length of data that has been cumulatively written to the send buffer in the past.
    ///
    /// Note that data the returned size may be larger than [`Self::max_data`].
    pub fn written(&self) -> u64 {
        self.offset + self.data.iter().map(|data| data.len() as u64).sum::<u64>()
    }

    /// Return the number of bytes that have been sent.
    pub fn sent(&self) -> u64 {
        self.state.sent()
    }

    /// Return the number of bytes that can be written without exceeding the [`Self::max_data`] limit.
    ///
    /// To prevent [`SendBuf`] from buffering excessive data, data should not be written when this method returns 0.
    pub fn remaining_mut(&self) -> u64 {
        self.max_data().saturating_sub(self.written())
    }

    /// Return whether there is remaining space to write data without exceeding the [`Self::max_data`] limit.
    ///
    /// When this method returns false, data should not be written.
    pub fn has_remaining_mut(&self) -> bool {
        self.max_data() > self.written()
    }

    // 无需close：不在写入即可，具体到某个状态，才有close
    // 无需reset：状态转化间，需要reset，而Sender上下文直接释放即可
    // 无需clean：Sender上下文直接释放即可，
}

type Data<'s> = (Range<u64>, bool, Vec<Bytes>);

impl SendBuf {
    /// Pick up data that can be sent.
    ///
    /// The selected data is subject to `predicate`, which accepts the starting position of the
    /// data segment, returns whether the segment could be sent and the maximum amount of bytes could
    /// take.
    ///
    /// If the data picked up is new (never sent before), how much data can be sent is also subject
    /// to `flow_limit`.
    ///
    /// ### Returns
    /// `None` if there is no data picked up.
    ///
    /// Otherwise, return a tuple:
    /// * `Range<u64>`: the range of data picked up (start inclusive, end exclusive).
    /// * `bool`: whether the data is new(not retransmitted).
    /// * `(&[u8], &[u8])`: the data picked up, duo to the internal buffer is a ring buffer, the data
    ///   picked up is in two parts, the begin of the second slice are the end of the first slice
    pub fn pick_up<P>(&mut self, predicate: P, flow_limit: usize) -> Result<Data<'_>, Poll<()>>
    where
        P: Fn(u64) -> Option<usize>,
    {
        self.state
            .pick(predicate, flow_limit, self.max_data())
            .map(|(range, is_fresh)| {
                let iter = self
                    .data
                    .iter()
                    .scan(self.offset, |offset, data| {
                        let current_range = *offset..*offset + data.len() as u64;
                        *offset += data.len() as u64;
                        Some((current_range, data))
                    })
                    .filter(move |(slice, ..)| slice.end > range.start && slice.start < range.end)
                    .map(move |(slice, data)| {
                        if slice.start >= range.start && slice.end <= range.end {
                            data.clone()
                        } else {
                            data.slice(
                                (range.start.saturating_sub(slice.start)) as usize
                                    ..(range.end.min(slice.end) - slice.start) as usize,
                            )
                        }
                    });

                (range, is_fresh, iter.collect())
            })
    }

    /// Called when the `range` of data sent is acknowledged by the peer.
    ///
    /// The `range` is the range of data that has been acknowledged.
    // 通过传输层接收到的对方的ack帧，确认某些包已经被接收到，这些包携带的数据即被确认。
    // ack只能确认Flighting/Lost状态的区间；如果确认的是Lost区间，意味着之前的判定丢包是错误的。
    pub fn on_data_acked(&mut self, range: &Range<u64>) {
        self.state.ack_rcvd(range);
        // 对于头部连续确认接收到的，还要前进，以免浪费空间
        let min_unrecved_pos = self.state.shift();
        if self.offset < min_unrecved_pos {
            let mut drain_len = (min_unrecved_pos - self.offset) as usize;
            self.offset = min_unrecved_pos;

            while !self.data.is_empty() && drain_len > 0 {
                match drain_len {
                    n if n >= self.data[0].len() => {
                        drain_len -= self.data[0].len();
                        self.data.pop_front().unwrap();
                    }
                    n => {
                        self.data[0] = self.data[0].slice(n..);
                        break;
                    }
                }
            }
        }
    }

    /// Called when the `range` of data sent may be lost.
    ///
    /// The `range` is the range of data that may be lost.
    // 通过传输层收到的ack帧，判定有些数据包丢失，因为它之后的数据包都被确认了，
    // 或者距离发送该段数据之后相当长一段时间都没收到它的确认。
    pub fn may_loss_data(&mut self, range: &Range<u64>) {
        self.state.may_loss(range);
    }

    pub fn resend_flighting(&mut self) {
        self.state.resend_flighting()
    }

    /// Return whether all data currently written has been received(acknowledged) by the peer.
    pub fn is_all_rcvd(&self) -> bool {
        self.data.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use super::{BufMap, Color, State};

    #[test]
    fn test_state() {
        let state = State::encode(100, Color::Pending);
        assert_eq!(state.offset(), 100);
        assert_eq!(state.color(), Color::Pending);

        let mut state = State::encode(100, Color::Pending);
        state.set_color(Color::Flighting);
        assert_eq!(state.color(), Color::Flighting);

        let state = State::encode(100, Color::Pending);
        assert_eq!(state.decode(), (100, Color::Pending));

        // test Dispaly
        assert_eq!(format!("{state}"), "[100: Pending]");
        assert_eq!(format!("{state:?}"), "[100: Pending]");
    }

    #[test]
    fn test_bufmap_empty() {
        let buf_map = BufMap::default();
        assert!(buf_map.0.is_empty());
    }

    #[test]
    fn test_bufmap_extend_to() {
        let mut buf_map = BufMap::default();
        buf_map.extend_to(100);
        assert_eq!(buf_map.0, vec![State::encode(0, Color::Pending)]);
        assert_eq!(buf_map.1, 100);

        buf_map.0.get_mut(0).unwrap().set_color(Color::Flighting);
        buf_map.extend_to(200);
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Flighting),
                State::encode(100, Color::Pending)
            ]
        );
        assert_eq!(buf_map.1, 200);
    }

    #[test]
    fn test_bufmap_pick() {
        let mut buf_map = BufMap::default();
        let range = buf_map.pick(|_| Some(20), usize::MAX, u64::MAX);
        assert_eq!(range, Err(Poll::Pending));
        assert!(buf_map.0.is_empty());

        buf_map.extend_to(200);
        let (range, is_fresh) = buf_map.pick(|_| Some(20), usize::MAX, u64::MAX).unwrap();
        assert_eq!(range, 0..20);
        assert!(is_fresh);
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Flighting),
                State::encode(20, Color::Pending)
            ]
        );

        let (range, is_fresh) = buf_map.pick(|_| Some(20), usize::MAX, u64::MAX).unwrap();
        assert_eq!(range, 20..40);
        assert!(is_fresh);
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Flighting),
                State::encode(40, Color::Pending)
            ]
        );

        buf_map.0.insert(2, State::encode(50, Color::Lost));
        buf_map.0.insert(3, State::encode(120, Color::Pending));
        let (range, is_fresh) = buf_map.pick(|_| Some(20), usize::MAX, u64::MAX).unwrap();
        assert_eq!(range, 40..50);
        assert!(is_fresh);
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Flighting),
                State::encode(50, Color::Lost),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.0.get_mut(0).unwrap().set_color(Color::Recved);
        let (range, is_fresh) = buf_map.pick(|_| Some(20), usize::MAX, u64::MAX).unwrap();
        assert_eq!(range, 50..70);
        assert!(!is_fresh);
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(50, Color::Flighting),
                State::encode(70, Color::Lost),
                State::encode(120, Color::Pending)
            ]
        );

        let (range, is_fresh) = buf_map.pick(|_| Some(130), usize::MAX, u64::MAX).unwrap();
        assert_eq!(range, 70..120);
        assert!(!is_fresh);
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(50, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        let (range, is_fresh) = buf_map.pick(|_| Some(130), usize::MAX, u64::MAX).unwrap();
        assert_eq!(range, 120..200);
        assert!(is_fresh);
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(50, Color::Flighting),
            ]
        );

        let result = buf_map.pick(|_| Some(130), usize::MAX, u64::MAX);
        assert!(result.is_err());
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(50, Color::Flighting),
            ]
        );
    }

    #[test]
    fn test_bufmap_sent() {
        let mut buf_map = BufMap::default();
        buf_map.extend_to(200);
        assert_eq!(buf_map.sent(), 0);

        assert!(buf_map.pick(|_| Some(120), usize::MAX, u64::MAX).is_ok());
        assert_eq!(buf_map.sent(), 120);

        assert!(buf_map.pick(|_| Some(80), usize::MAX, u64::MAX).is_ok());
        assert_eq!(buf_map.sent(), 200);
    }

    #[test]
    fn test_bufmap_recved() {
        let mut buf_map = BufMap::default();
        buf_map.extend_to(200);
        assert!(buf_map.pick(|_| Some(120), usize::MAX, u64::MAX).is_ok());
        buf_map.ack_rcvd(&(0..20));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(20, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.ack_rcvd(&(30..50));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(20, Color::Flighting),
                State::encode(30, Color::Recved),
                State::encode(50, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.ack_rcvd(&(25..55));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(20, Color::Flighting),
                State::encode(25, Color::Recved),
                State::encode(55, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.ack_rcvd(&(20..25));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(55, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.0.pop_front();
        buf_map.ack_rcvd(&(20..55));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(55, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.ack_rcvd(&(30..70));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(70, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        buf_map.ack_rcvd(&(100..119));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(70, Color::Flighting),
                State::encode(100, Color::Recved),
                State::encode(119, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );

        assert!(buf_map.pick(|_| Some(130), usize::MAX, u64::MAX).is_ok());
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(70, Color::Flighting),
                State::encode(100, Color::Recved),
                State::encode(119, Color::Flighting),
            ]
        );

        buf_map.ack_rcvd(&(119..150));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(70, Color::Flighting),
                State::encode(100, Color::Recved),
                State::encode(150, Color::Flighting),
            ]
        );
        buf_map.ack_rcvd(&(150..200));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(70, Color::Flighting),
                State::encode(100, Color::Recved),
            ]
        );
    }

    #[test]
    #[should_panic]
    fn test_bufmap_invalid_recved() {
        let mut buf_map = BufMap::default();
        buf_map.extend_to(200);
        assert!(buf_map.pick(|_| Some(120), usize::MAX, u64::MAX).is_ok());
        buf_map.ack_rcvd(&(20..40));
        buf_map.0.insert(2, State::encode(30, Color::Pending));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Flighting),
                State::encode(20, Color::Recved),
                // Alerting: 30..40 is Pending, never been sent, but they will be Recved
                State::encode(30, Color::Pending),
                State::encode(40, Color::Flighting),
                State::encode(120, Color::Pending)
            ]
        );
        buf_map.ack_rcvd(&(0..50));
    }

    #[test]
    #[should_panic]
    fn test_bufmap_recved_overflow() {
        let mut buf_map = BufMap::default();
        buf_map.extend_to(200);
        assert!(buf_map.pick(|_| Some(120), usize::MAX, u64::MAX).is_ok());
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );
        buf_map.ack_rcvd(&(110..121));
    }

    #[test]
    #[should_panic]
    fn test_bufmap_recved_over_end() {
        let mut buf_map = BufMap::default();
        buf_map.extend_to(200);
        assert!(buf_map.pick(|_| Some(200), usize::MAX, u64::MAX).is_ok());
        assert_eq!(buf_map.0, vec![State::encode(0, Color::Flighting)]);
        buf_map.ack_rcvd(&(0..201));
    }

    #[test]
    fn test_bufmap_lost() {
        let mut buf_map = BufMap::default();
        buf_map.extend_to(200);
        assert!(buf_map.pick(|_| Some(120), usize::MAX, u64::MAX).is_ok());
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(0..20));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Lost),
                State::encode(20, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(30..50));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Lost),
                State::encode(20, Color::Flighting),
                State::encode(30, Color::Lost),
                State::encode(50, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.ack_rcvd(&(0..10));
        buf_map.ack_rcvd(&(70..100));
        buf_map.0.pop_front();
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(20, Color::Flighting),
                State::encode(30, Color::Lost),
                State::encode(50, Color::Flighting),
                State::encode(70, Color::Recved),
                State::encode(100, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(15..25));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(25, Color::Flighting),
                State::encode(30, Color::Lost),
                State::encode(50, Color::Flighting),
                State::encode(70, Color::Recved),
                State::encode(100, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(10..20));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(25, Color::Flighting),
                State::encode(30, Color::Lost),
                State::encode(50, Color::Flighting),
                State::encode(70, Color::Recved),
                State::encode(100, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(60..110));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(25, Color::Flighting),
                State::encode(30, Color::Lost),
                State::encode(50, Color::Flighting),
                State::encode(60, Color::Lost),
                State::encode(70, Color::Recved),
                State::encode(100, Color::Lost),
                State::encode(110, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.ack_rcvd(&(20..55));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(20, Color::Recved),
                State::encode(55, Color::Flighting),
                State::encode(60, Color::Lost),
                State::encode(70, Color::Recved),
                State::encode(100, Color::Lost),
                State::encode(110, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(40..80));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(20, Color::Recved),
                State::encode(55, Color::Lost),
                State::encode(70, Color::Recved),
                State::encode(100, Color::Lost),
                State::encode(110, Color::Flighting),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.ack_rcvd(&(20..120));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(20, Color::Recved),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(50..80));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(20, Color::Recved),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(2..10));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(20, Color::Recved),
                State::encode(120, Color::Pending),
            ]
        );

        buf_map.may_loss(&(30..50));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(10, Color::Lost),
                State::encode(20, Color::Recved),
                State::encode(120, Color::Pending),
            ]
        );
    }

    #[test]
    fn test_bufmap_ack_and_lost_all() {
        let mut buf_map = BufMap::default();
        buf_map.extend_to(46);
        assert!(buf_map.pick(|_| Some(46), usize::MAX, u64::MAX).is_ok());
        assert_eq!(buf_map.0, vec![State::encode(0, Color::Flighting)]);

        buf_map.ack_rcvd(&(0..2));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(2, Color::Flighting)
            ]
        );

        buf_map.may_loss(&(0..46));
        assert_eq!(
            buf_map.0,
            vec![
                State::encode(0, Color::Recved),
                State::encode(2, Color::Lost)
            ]
        )
    }

    #[test]
    fn test_bufmap_ack_and_lost_all2() {
        let mut buf_map = BufMap(vec![State::encode(2, Color::Flighting)].into(), 46);

        buf_map.may_loss(&(0..46));
        assert_eq!(buf_map.0, vec![State::encode(2, Color::Lost)])
    }
}
