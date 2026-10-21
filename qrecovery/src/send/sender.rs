use std::{
    ops::Range,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use qbase::{
    error::Error,
    frame::{ResetStreamError, ResetStreamFrame, StreamFrame, io::SendFrame},
    metric::ArcConnectionMetrics,
    net::tx::ArcSendWakers,
    sid::StreamId,
    varint::{VARINT_MAX, VarInt},
};
use qevent::{
    RawInfo,
    quic::transport::{
        DataMovedAdditionalInfo, GranularStreamStates, StreamDataLocation, StreamDataMoved,
        StreamSide, StreamStateUpdated,
    },
};

use super::sndbuf::SendBuf;
use crate::streams::error::StreamError;

fn log_reset_event(sid: StreamId, from_state: GranularStreamStates) {
    qevent::event!(StreamStateUpdated {
        stream_id: sid.id(),
        stream_type: sid.dir(),
        old: from_state,
        new: GranularStreamStates::ResetSent,
        stream_side: StreamSide::Sending
    });
}

/// The "Ready" state represents a newly created stream that is able to accept data from the application.
/// Stream data might be buffered in this state in preparation for sending.
/// An implementation might choose to defer allocating a stream ID to a stream until it sends the first
/// STREAM frame and enters this state, which can allow for better stream prioritization.
#[derive(Debug)]
pub struct ReadySender<TX> {
    stream_id: StreamId,
    sndbuf: SendBuf,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    broker: TX,
    tx_wakers: ArcSendWakers,
    writable_waker: Option<Waker>,
    metrics: ArcConnectionMetrics,
}

impl<TX> ReadySender<TX> {
    pub(super) fn new(
        stream_id: StreamId,
        buf_size: u64,
        broker: TX,
        metrics: ArcConnectionMetrics,
    ) -> ReadySender<TX> {
        ReadySender {
            stream_id,
            sndbuf: SendBuf::with_capacity(buf_size, Arc::default()),
            flush_waker: None,
            shutdown_waker: None,
            broker,
            tx_wakers: ArcSendWakers::default(),
            writable_waker: None,
            metrics,
        }
    }

    pub(super) fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    // /// 非阻塞写，如果没有多余的发送缓冲区，将返回WouldBlock错误。
    // /// 但什么时候可写，是没通知的，只能不断去尝试写，直到写入成功。
    // /// 仅供展示学习
    // #[allow(dead_code)]
    // fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    //     if self.sndbuf.has_remaining_mut() {
    //         self.tx_wakers.wake_all();
    //         self.sndbuf.write(Bytes::copy_from_slice(buf));
    //         Ok(buf.len())
    //     } else {
    //         Err(io::ErrorKind::WouldBlock.into())
    //     }
    // }

    pub(crate) fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        if self.shutdown_waker.is_some() {
            return Poll::Ready(Err(StreamError::Finished));
        }

        if !self.sndbuf.has_remaining_mut() {
            self.writable_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        Poll::Ready(Ok(()))
    }

    pub(crate) fn write(&mut self, data: Bytes) -> Result<(), StreamError> {
        if self.shutdown_waker.is_some() {
            return Err(StreamError::Finished);
        }

        let data_len = data.len() as u64;

        qevent::event!(StreamDataMoved {
            stream_id: self.stream_id,
            offset: self.sndbuf.written(),
            length: data_len,
            from: StreamDataLocation::Application,
            to: StreamDataLocation::Transport,
            raw: data.clone()
        });

        // Update metrics when application writes data
        self.metrics.add_pending(data_len);

        self.tx_wakers.wake_all();
        self.sndbuf.write(data);
        Ok(())
    }

    pub(super) fn update_window(&mut self, max_stream_data: u64) {
        if max_stream_data > self.sndbuf.max_data() {
            if self.sndbuf.written() > self.sndbuf.max_data() {
                self.tx_wakers.wake_all();
            }
            self.sndbuf.extend(max_stream_data);
            if self.sndbuf.has_remaining_mut()
                && let Some(waker) = self.writable_waker.take()
            {
                waker.wake();
            }
        }
    }

    pub(super) fn revise_max_stream_data(&mut self, zero_rtt_rejected: bool, max_stream_data: u64) {
        if zero_rtt_rejected {
            self.sndbuf.forget_sent_state();
        }
        self.update_window(max_stream_data);
    }

    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.sndbuf.is_all_rcvd() {
            Poll::Ready(())
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        // 就算当前没有流量窗口，也可以单独发送一个空StreamFrame，携带fin bit
        self.tx_wakers.wake_all();
        self.shutdown_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub(super) fn wake_all(&mut self) {
        self.tx_wakers.wake_all();
        if let Some(waker) = self.writable_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.flush_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.shutdown_waker.take() {
            waker.wake();
        }
    }

    pub(super) fn be_stopped(&mut self) -> u64 {
        self.wake_all();
        // ReadyState: no data is sent
        debug_assert_eq!(self.sndbuf.sent(), 0);
        self.sndbuf.sent()
    }
}

/// 状态升级，ReaderSender => SendingSender
impl<TX: Clone> ReadySender<TX> {
    pub(super) fn upgrade(&mut self) -> SendingSender<TX> {
        qevent::event!(StreamStateUpdated {
            stream_id: self.stream_id,
            stream_type: self.stream_id.dir(),
            old: GranularStreamStates::Ready,
            new: GranularStreamStates::Send,
            stream_side: StreamSide::Sending
        });
        SendingSender {
            stream_id: self.stream_id,
            sndbuf: std::mem::take(&mut self.sndbuf),
            flush_waker: self.flush_waker.take(),
            shutdown_waker: self.shutdown_waker.take(),
            broker: self.broker.clone(),
            tx_wakers: self.tx_wakers.clone(),
            writable_waker: self.writable_waker.take(),
            metrics: self.metrics.clone(),
        }
    }
}

impl<TX> ReadySender<TX>
where
    TX: SendFrame<ResetStreamFrame>,
{
    /// 应用层使用，取消发送流
    pub(super) fn cancel(&mut self, err_code: u64) -> ResetStreamError {
        let final_size = self.sndbuf.sent();
        let reset_stream_err = ResetStreamError::new(
            VarInt::from_u64(err_code).expect("app error code must not exceed 2^62"),
            VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
        );
        tracing::debug!(
            target: "dquic",
            "{} is canceled by app layer, with error code {err_code}",
            self.stream_id
        );
        self.broker
            .send_frame([reset_stream_err.combine(self.stream_id)]);
        log_reset_event(self.stream_id, GranularStreamStates::Ready);
        reset_stream_err
    }
}

#[derive(Debug)]
pub struct SendingSender<TX> {
    stream_id: StreamId,
    sndbuf: SendBuf,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    broker: TX,
    tx_wakers: ArcSendWakers,
    writable_waker: Option<Waker>,
    metrics: ArcConnectionMetrics,
}

pub type StreamData<'s> = (Range<u64>, bool, Vec<Bytes>, bool);

impl<TX> SendingSender<TX> {
    pub(super) fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub(super) fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        if self.shutdown_waker.is_some() {
            return Poll::Ready(Err(StreamError::Finished));
        }

        if !self.sndbuf.has_remaining_mut() {
            self.writable_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        Poll::Ready(Ok(()))
    }

    pub(super) fn write(&mut self, data: Bytes) -> Result<(), StreamError> {
        if self.shutdown_waker.is_some() {
            return Err(StreamError::Finished);
        }

        let data_len = data.len() as u64;

        qevent::event!(StreamDataMoved {
            stream_id: self.stream_id,
            offset: self.sndbuf.written(),
            length: data_len,
            from: StreamDataLocation::Application,
            to: StreamDataLocation::Transport,
            raw: data.clone()
        });

        // Update metrics when application writes data
        self.metrics.add_pending(data_len);

        self.tx_wakers.wake_all();
        self.sndbuf.write(data);
        Ok(())
    }

    /// 传输层使用
    pub(super) fn update_window(&mut self, max_stream_data: u64) {
        if max_stream_data > self.sndbuf.max_data() {
            if self.sndbuf.written() > self.sndbuf.max_data() {
                self.tx_wakers.wake_all();
            }
            self.sndbuf.extend(max_stream_data);
            if self.sndbuf.has_remaining_mut()
                && let Some(waker) = self.writable_waker.take()
            {
                waker.wake();
            }
        }
    }

    pub(super) fn pick_up<P>(
        &'_ mut self,
        predicate: P,
        flow_limit: usize,
    ) -> Result<StreamData<'_>, Poll<()>>
    where
        P: Fn(u64) -> Option<usize>,
    {
        let total_size = self.total_size();
        let sent = self.sndbuf.sent();
        self.sndbuf
            .pick_up(&predicate, flow_limit)
            .map(|(range, is_fresh, data)| {
                (range.clone(), is_fresh, data, Some(range.end) == total_size)
            })
            .or_else(|availability| {
                if total_size == Some(sent) {
                    predicate(sent).ok_or(Poll::Ready(()))?;
                    Ok((sent..sent, false, Vec::new(), true))
                } else {
                    Err(availability)
                }
            })
            .map(|(range, is_fresh, data, is_eos)| {
                qevent::event!(StreamDataMoved {
                    stream_id: self.stream_id,
                    offset: range.start,
                    length: range.end - range.start,
                    from: StreamDataLocation::Transport,
                    to: StreamDataLocation::Network,
                    ?additional_info: is_eos.then_some(DataMovedAdditionalInfo::FinSet),
                    raw: RawInfo { data : data.as_slice() }
                });
                (range, is_fresh, data, is_eos)
            })
    }

    pub(super) fn on_data_acked(&mut self, frame: &StreamFrame) {
        self.sndbuf.on_data_acked(&frame.range());
        if self.sndbuf.is_all_rcvd()
            && let Some(waker) = self.flush_waker.take()
        {
            waker.wake();
        }
    }

    pub(super) fn may_loss_data(&mut self, frame: &StreamFrame) {
        self.tx_wakers.wake_all();
        self.sndbuf.may_loss_data(&frame.range())
    }

    pub(super) fn revise_max_stream_data(&mut self, zero_rtt_rejected: bool, max_stream_data: u64) {
        if zero_rtt_rejected {
            self.sndbuf.forget_sent_state();
        }
        self.update_window(max_stream_data);
    }

    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.sndbuf.is_all_rcvd() {
            Poll::Ready(())
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.tx_wakers.wake_all();
        self.shutdown_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub(super) fn total_size(&self) -> Option<u64> {
        if self.shutdown_waker.is_some() {
            Some(self.sndbuf.written())
        } else {
            None
        }
    }

    pub(super) fn wake_all(&mut self) {
        self.tx_wakers.wake_all();
        if let Some(waker) = self.writable_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.flush_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.shutdown_waker.take() {
            waker.wake();
        }
    }

    /// 传输层使用
    pub(super) fn be_stopped(&mut self) -> u64 {
        self.wake_all();
        // Actually, these remaining data is not acked and will not be acked
        self.sndbuf.sent()
    }
}

impl<TX: Clone> SendingSender<TX> {
    pub(super) fn upgrade(&mut self) -> DataSentSender<TX> {
        qevent::event!(StreamStateUpdated {
            stream_id: self.stream_id,
            stream_type: self.stream_id.dir(),
            old: GranularStreamStates::Send,
            new: GranularStreamStates::DataSent,
            stream_side: StreamSide::Sending
        });
        DataSentSender {
            stream_id: self.stream_id,
            sndbuf: std::mem::take(&mut self.sndbuf),
            flush_waker: self.flush_waker.take(),
            shutdown_waker: self.shutdown_waker.take(),
            broker: self.broker.clone(),
            tx_wakers: self.tx_wakers.clone(),
            fin_state: FinState::Sent,
        }
    }
}

impl<TX> SendingSender<TX>
where
    TX: SendFrame<ResetStreamFrame>,
{
    pub(super) fn cancel(&mut self, err_code: u64) -> ResetStreamError {
        let final_size = self.sndbuf.sent();
        let reset_stream_err = ResetStreamError::new(
            VarInt::from_u64(err_code).expect("app error code must not exceed 2^62"),
            VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
        );
        tracing::debug!(
            target: "dquic",
            "{} is canceled by app layer, with error code {err_code}",
            self.stream_id
        );
        self.broker
            .send_frame([reset_stream_err.combine(self.stream_id)]);
        log_reset_event(self.stream_id, GranularStreamStates::Send);
        reset_stream_err
    }
}

#[derive(Debug, PartialEq)]
enum FinState {
    Sent,
    Lost,
    Rcvd,
}

#[derive(Debug)]
pub struct DataSentSender<TX> {
    stream_id: StreamId,
    sndbuf: SendBuf,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    broker: TX,
    // retran/fin
    tx_wakers: ArcSendWakers,
    fin_state: FinState,
}

impl<TX> DataSentSender<TX> {
    pub(super) fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub(super) fn pick_up<P>(
        &'_ mut self,
        predicate: P,
        flow_limit: usize,
    ) -> Result<StreamData<'_>, Poll<()>>
    where
        P: Fn(u64) -> Option<usize>,
    {
        let total_size = self.sndbuf.written();
        self.sndbuf
            .pick_up(&predicate, flow_limit)
            .map(|(range, is_fresh, data)| (range.clone(), is_fresh, data, range.end == total_size))
            .or_else(|availability| {
                if self.fin_state == FinState::Lost {
                    predicate(total_size).ok_or(Poll::Ready(()))?;
                    self.fin_state = FinState::Sent;
                    Ok((total_size..total_size, false, vec![], true))
                } else {
                    Err(availability)
                }
            })
            .map(|(range, is_fresh, data, is_eos)| {
                qevent::event!(StreamDataMoved {
                    stream_id: self.stream_id,
                    offset: range.start,
                    length: range.end - range.start,
                    from: StreamDataLocation::Transport,
                    to: StreamDataLocation::Network,
                    ?additional_info: is_eos.then_some(DataMovedAdditionalInfo::FinSet),
                    raw: RawInfo { data : data.as_slice() }
                },);
                (range, is_fresh, data, is_eos)
            })
    }

    pub(super) fn on_data_acked(&mut self, frame: &StreamFrame) {
        self.sndbuf.on_data_acked(&frame.range());
        if frame.is_fin() {
            self.fin_state = FinState::Rcvd;
        }
        if self.is_all_rcvd() {
            if let Some(waker) = self.flush_waker.take() {
                waker.wake();
            }
            if let Some(waker) = self.shutdown_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn is_all_rcvd(&self) -> bool {
        self.sndbuf.is_all_rcvd() && self.fin_state == FinState::Rcvd
    }

    pub(super) fn may_loss_data(&mut self, frame: &StreamFrame) {
        self.tx_wakers.wake_all();
        if frame.is_fin() && self.fin_state != FinState::Rcvd {
            self.fin_state = FinState::Lost;
        }
        self.sndbuf.may_loss_data(&frame.range())
    }

    pub(super) fn revise_max_stream_data(&mut self, zero_rtt_rejected: bool, max_stream_data: u64) {
        if zero_rtt_rejected {
            self.sndbuf.forget_sent_state();
        }
        self.sndbuf.extend(max_stream_data);
    }

    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        debug_assert!(!self.is_all_rcvd());
        self.flush_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub(super) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        debug_assert!(!self.is_all_rcvd());
        self.tx_wakers.wake_all();
        self.shutdown_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub(super) fn wake_all(&mut self) {
        self.tx_wakers.wake_all();
        if let Some(waker) = self.flush_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.shutdown_waker.take() {
            waker.wake();
        }
    }

    pub(super) fn be_stopped(&mut self) -> u64 {
        self.wake_all();
        // Actually, these remaining data is not acked and will not be acked
        self.sndbuf.written()
    }
}

impl<TX> DataSentSender<TX>
where
    TX: SendFrame<ResetStreamFrame>,
{
    pub(super) fn cancel(&mut self, err_code: u64) -> ResetStreamError {
        let final_size = self.sndbuf.sent();
        let reset_stream_err = ResetStreamError::new(
            VarInt::from_u64(err_code).expect("app error code must not exceed 2^62"),
            VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
        );
        tracing::debug!(
            target: "dquic",
            "{} is canceled by app layer, with error code {err_code}",
            self.stream_id
        );
        self.broker
            .send_frame([reset_stream_err.combine(self.stream_id)]);
        log_reset_event(self.stream_id, GranularStreamStates::DataSent);
        reset_stream_err
    }
}

#[derive(Debug)]
pub(super) enum Sender<TX> {
    Ready(ReadySender<TX>),
    Sending(SendingSender<TX>),
    DataSent(DataSentSender<TX>),
    DataRcvd,
    ResetSent(ResetStreamError),
    ResetRcvd(ResetStreamError),
}

impl<TX> Sender<TX> {
    pub(super) fn fresh_bytes(&self) -> usize {
        let buffer = match self {
            Self::Ready(s) => &s.sndbuf,
            Self::Sending(s) => &s.sndbuf,
            Self::DataSent(s) => &s.sndbuf,
            _ => return 0,
        };
        buffer
            .written()
            .min(buffer.max_data())
            .saturating_sub(buffer.sent()) as usize
    }
    pub(super) fn source(&self) -> Option<(StreamId, &ArcSendWakers)> {
        match self {
            Self::Ready(s) => Some((s.stream_id, &s.tx_wakers)),
            Self::Sending(s) => Some((s.stream_id, &s.tx_wakers)),
            Self::DataSent(s) => Some((s.stream_id, &s.tx_wakers)),
            _ => None,
        }
    }

    pub fn new(
        stream_id: StreamId,
        buf_size: u64,
        broker: TX,
        metrics: ArcConnectionMetrics,
    ) -> Self {
        Sender::Ready(ReadySender::new(stream_id, buf_size, broker, metrics))
    }
}

/// The internal state representations of [`Outgoing`] and [`Writer`].
///
/// For the application layer, this struct is represented as [`Writer`]. The application can use it to
/// write data to the stream, or reset the stream.
///
/// For the protocol layer, this struct is represented as [`Outgoing`]. The protocol layer uses it to
/// manage the status of the `Sender`, sends data(stream frame),reset frames and other frames to peer.
///
/// [`Outgoing`]: super::Outgoing
/// [`Writer`]: super::Writer
#[derive(Debug, Clone)]
pub struct ArcSender<TX>(Arc<Mutex<Result<Sender<TX>, Error>>>);

impl<TX> ArcSender<TX> {
    #[doc(hidden)]
    pub(crate) fn new(
        stream_id: StreamId,
        buf_size: u64,
        broker: TX,
        metrics: ArcConnectionMetrics,
    ) -> Self {
        ArcSender(Arc::new(Mutex::new(Ok(Sender::new(
            stream_id, buf_size, broker, metrics,
        )))))
    }
}

impl<TX> ArcSender<TX> {
    // update send window for opened stream.
    pub(crate) fn update_window(&self, max_stream_data: u64) {
        assert!(max_stream_data <= VARINT_MAX);
        match self.sender().as_mut() {
            Ok(Sender::Ready(s)) => s.update_window(max_stream_data),
            Ok(Sender::Sending(s)) => s.update_window(max_stream_data),
            _ => {}
        }
    }

    pub(super) fn sender(&self) -> MutexGuard<'_, Result<Sender<TX>, Error>> {
        self.0.lock().unwrap()
    }
}
