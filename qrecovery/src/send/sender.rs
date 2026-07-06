use std::{
    ops::Range,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use qbase::{
    error::Error,
    frame::{ResetStreamError, ResetStreamFrame, StreamFrame, io::SendFrame},
    net::tx::{ArcSendWakers, Signals},
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
    metrics: Option<qbase::metric::ArcConnectionMetrics>,
}

impl<TX> ReadySender<TX> {
    pub(super) fn new(
        stream_id: StreamId,
        buf_size: u64,
        broker: TX,
        tx_wakers: ArcSendWakers,
        metrics: Option<qbase::metric::ArcConnectionMetrics>,
    ) -> ReadySender<TX> {
        ReadySender {
            stream_id,
            sndbuf: SendBuf::with_capacity(buf_size),
            flush_waker: None,
            shutdown_waker: None,
            broker,
            tx_wakers,
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
    //         self.tx_wakers.wake_all_by(Signals::WRITTEN);
    //         self.sndbuf.write(Bytes::copy_from_slice(buf));
    //         Ok(buf.len())
    //     } else {
    //         Err(io::ErrorKind::WouldBlock.into())
    //     }
    // }

    pub(crate) fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        if self.shutdown_waker.is_some() {
            return Poll::Ready(Err(StreamError::EosSent));
        }

        if !self.sndbuf.has_remaining_mut() {
            self.writable_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        Poll::Ready(Ok(()))
    }

    pub(crate) fn write(&mut self, data: Bytes) -> Result<(), StreamError> {
        if self.shutdown_waker.is_some() {
            return Err(StreamError::EosSent);
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
        if let Some(metrics) = &self.metrics {
            metrics.new_pending(data_len);
        }

        self.tx_wakers.wake_all_by(Signals::WRITTEN);
        self.sndbuf.write(data);
        Ok(())
    }

    pub(super) fn update_window(&mut self, max_stream_data: u64) {
        if max_stream_data > self.sndbuf.max_data() {
            if self.sndbuf.written() > self.sndbuf.max_data() {
                self.tx_wakers.wake_all_by(Signals::WRITTEN);
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
        self.tx_wakers.wake_all_by(Signals::TRANSPORT);
        self.shutdown_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub(super) fn wake_all(&mut self) {
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
    metrics: Option<qbase::metric::ArcConnectionMetrics>,
}

pub type StreamData<'s> = (Range<u64>, bool, Vec<Bytes>, bool);

impl<TX> SendingSender<TX> {
    pub(super) fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub(super) fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        if self.shutdown_waker.is_some() {
            return Poll::Ready(Err(StreamError::EosSent));
        }

        if !self.sndbuf.has_remaining_mut() {
            self.writable_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        Poll::Ready(Ok(()))
    }

    pub(super) fn write(&mut self, data: Bytes) -> Result<(), StreamError> {
        if self.shutdown_waker.is_some() {
            return Err(StreamError::EosSent);
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
        if let Some(metrics) = &self.metrics {
            metrics.new_pending(data_len);
        }

        self.tx_wakers.wake_all_by(Signals::WRITTEN);
        self.sndbuf.write(data);
        Ok(())
    }

    /// 传输层使用
    pub(super) fn update_window(&mut self, max_stream_data: u64) {
        if max_stream_data > self.sndbuf.max_data() {
            if self.sndbuf.written() > self.sndbuf.max_data() {
                self.tx_wakers.wake_all_by(Signals::WRITTEN);
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
    ) -> Result<StreamData<'_>, Signals>
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
            .or_else(|signals| {
                if total_size == Some(sent) {
                    predicate(sent).ok_or(signals | Signals::CONGESTION)?;
                    Ok((sent..sent, false, Vec::new(), true))
                } else {
                    Err(signals)
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
        self.tx_wakers.wake_all_by(Signals::TRANSPORT);
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
        self.tx_wakers.wake_all_by(Signals::TRANSPORT);
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
    ) -> Result<StreamData<'_>, Signals>
    where
        P: Fn(u64) -> Option<usize>,
    {
        let total_size = self.sndbuf.written();
        self.sndbuf
            .pick_up(&predicate, flow_limit)
            .map(|(range, is_fresh, data)| (range.clone(), is_fresh, data, range.end == total_size))
            .or_else(|signals| {
                if self.fin_state == FinState::Lost {
                    self.fin_state = FinState::Sent;
                    Ok((total_size..total_size, false, vec![], true))
                } else {
                    Err(signals)
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
        self.tx_wakers.wake_all_by(Signals::TRANSPORT);
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
        self.tx_wakers.wake_all_by(Signals::TRANSPORT);
        self.shutdown_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub(super) fn wake_all(&mut self) {
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
    pub fn new(
        stream_id: StreamId,
        buf_size: u64,
        broker: TX,
        tx_wakers: ArcSendWakers,
        metrics: Option<qbase::metric::ArcConnectionMetrics>,
    ) -> Self {
        Sender::Ready(ReadySender::new(
            stream_id, buf_size, broker, tx_wakers, metrics,
        ))
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
        tx_wakers: ArcSendWakers,
        metrics: Option<qbase::metric::ArcConnectionMetrics>,
    ) -> Self {
        ArcSender(Arc::new(Mutex::new(Ok(Sender::new(
            stream_id, buf_size, broker, tx_wakers, metrics,
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

#[cfg(test)]
mod tests {
    use qbase::{role::Role, sid::Dir};

    use super::*;

    #[derive(Debug, Default, Clone)]
    struct MockBroker(Arc<Mutex<Vec<ResetStreamFrame>>>);

    impl SendFrame<ResetStreamFrame> for MockBroker {
        fn send_frame<I: IntoIterator<Item = ResetStreamFrame>>(&self, iter: I) {
            self.0.lock().unwrap().extend(iter);
        }
    }

    fn create_test_sender() -> ArcSender<MockBroker> {
        let stream_id = StreamId::new(Role::Client, Dir::Bi, 0);
        let buf_size = 1000;
        let broker = MockBroker::default();
        ArcSender::new(stream_id, buf_size, broker, Default::default(), None)
    }

    #[test]
    fn test_ready_sender_new() {
        let stream_id = StreamId::new(Role::Client, Dir::Bi, 0);
        let buf_size = 1000;
        let broker = MockBroker::default();
        let sender = ReadySender::new(stream_id, buf_size, broker, Default::default(), None);

        assert_eq!(sender.stream_id, stream_id);
        assert_eq!(sender.sndbuf.max_data(), buf_size);
        assert!(sender.flush_waker.is_none());
        assert!(sender.shutdown_waker.is_none());
        assert!(sender.writable_waker.is_none());
    }

    #[test]
    fn test_ready_sender_write() {
        let stream_id = StreamId::new(Role::Client, Dir::Bi, 0);
        let buf_size = 10;
        let broker = MockBroker::default();
        let mut sender = ReadySender::new(stream_id, buf_size, broker, Default::default(), None);

        let data = Bytes::from_static(b"hello");
        let result = sender.write(data);
        assert!(result.is_ok());

        // Test write when buffer is full
        let large_data = Bytes::from_static(include_bytes!("./sender.rs"));
        let result = sender.write(large_data);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ready_sender_poll_write() {
        let stream_id = StreamId::new(Role::Client, Dir::Bi, 0);
        let buf_size = 10;
        let broker = MockBroker::default();
        let mut sender = ReadySender::new(stream_id, buf_size, broker, Default::default(), None);

        let data = Bytes::from_static(b"test");

        assert!(matches!(sender.write(data.clone()), Ok(())));

        // Test poll_write when buffer is full
        sender.sndbuf.forget_sent_state();
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let result = sender.poll_ready(&mut cx);
        assert!(result.is_pending());
    }

    #[test]
    fn test_sender_state_transitions() {
        let stream_id = StreamId::new(Role::Client, Dir::Bi, 0);
        let buf_size = 1000;
        let broker = MockBroker::default();
        let mut ready = ReadySender::new(stream_id, buf_size, broker, Default::default(), None);

        // Test transition to SendingSender
        let mut sending = ready.upgrade();
        assert_eq!(sending.stream_id, stream_id);
        assert_eq!(sending.sndbuf.max_data(), buf_size);

        // Test transition to DataSentSender
        let data_sent = sending.upgrade();
        assert_eq!(data_sent.stream_id, stream_id);
        assert!(data_sent.fin_state == FinState::Sent);
    }

    #[test]
    fn test_arc_sender() {
        let sender = create_test_sender();

        // Test buffer size revision
        sender.update_window(2000);

        // Test sender lock access
        let guard = sender.sender();
        assert!(guard.is_ok());
    }

    #[test]
    fn test_data_sent_sender() {
        let stream_id = StreamId::new(Role::Client, Dir::Bi, 0);
        let buf_size = 1000;
        let broker = MockBroker::default();
        let mut sender = DataSentSender {
            stream_id,
            sndbuf: SendBuf::with_capacity(buf_size),
            flush_waker: None,
            shutdown_waker: None,
            broker,
            tx_wakers: Default::default(),
            fin_state: FinState::Sent,
        };

        // Test pick_up with empty buffer
        let predicate = |_| Some(100);
        let result = sender.pick_up(predicate, 1000);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_data_sent_sender_polling() {
        let stream_id = StreamId::new(Role::Client, Dir::Bi, 0);
        let buf_size = 1000;
        let broker = MockBroker::default();
        let mut sender = DataSentSender {
            stream_id,
            sndbuf: SendBuf::with_capacity(buf_size),
            flush_waker: None,
            shutdown_waker: None,
            broker,
            tx_wakers: Default::default(),
            fin_state: FinState::Sent,
        };

        let mut cx = Context::from_waker(futures::task::noop_waker_ref());

        // Test poll_flush when all data received
        let result = sender.poll_flush(&mut cx);
        assert!(result.is_pending());

        // Test poll_shutdown when all data received
        let _ = sender.poll_shutdown(&mut cx);
        assert!(sender.shutdown_waker.is_some());
    }
}
