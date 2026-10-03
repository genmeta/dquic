use std::{
    sync::atomic::{AtomicBool, Ordering::*},
    task::{Context, Poll, Waker, ready},
};

use bytes::BufMut;
use qbase::{
    error::{Error, ErrorKind, QuicError},
    frame::{
        Frame, FrameType, GetFrameType, ResetStreamFrame, StreamCtlFrame, StreamFrame,
        io::{ReceiveFrame, SendFrame},
    },
    metric::ArcConnectionMetrics,
    net::tx::{ArcSendWakers, UnregisterWaker},
    packet::ConstraintBuffer,
    param::{ArcParameters, ParameterId, core::Parameters},
    sid::{
        ControlStreamsConcurrency, Dir, StreamId, StreamIds,
        remote_sid::{AcceptSid, ExceedLimitError},
    },
    varint::VarInt,
};

use super::{
    Ext,
    io::{ArcInput, ArcOutput, IOState},
    listener::{AcceptBiStream, AcceptUniStream, ArcListener},
};
use crate::{
    recv::{ArcRecver, Incoming, Reader},
    send::{ArcSender, Outgoing, Writer},
};

/// Manage all streams in the connection, send and receive frames, handle frame loss, and acknowledge.
///
/// The struct dont truly send and receive frames, this struct provides interfaces to generate frames
/// will be sent to the peer, receive frames, handle frame loss, and acknowledge.
///
/// [`Outgoing`], [`Incoming`] , [`Writer`] and [`Reader`] dont truly send and receive frames, too.
///
/// # Send frames
///
/// ## Stream frame
///
/// When the application wants to send data to the peer, it will call [`write`] method on [`Writer`]
/// to write data to the [`SendBuf`].
///
/// Protocol layer will call [`Package::poll_dump`] to read data from the streams into stream frames and
/// write the frame into the quic packet.
///
/// ## Stream control frame
///
/// Be different from the stream frame, the stream control frame is much samller in size.
///
/// The struct has a generic type `T`, which must implement the [`SendFrame`] trait. The trait has
/// a method [`send_frame`], which will be called to send the stream control frame to the peer, see
/// [`SendFrame`] for more details.
///
/// # Receive frames, handle frame loss and acknowledge
///
/// Frames received, frames lost or acknowledgmented will be delivered to the corresponding method.
/// | method on [`DataStreams`]                                | corresponding method                               |
/// | -------------------------------------------------------- | -------------------------------------------------- |
/// | [`recv_data`]                                            | [`Incoming::recv_data`]                            |
/// | [`recv_stream_control`] ([`RESET_STREAM frame`])         | [`Incoming::recv_reset`]                           |
/// | [`recv_stream_control`] ([`STOP_SENDING frame`])         | [`Outgoing::be_stopped`]                           |
/// | [`recv_stream_control`] ([`MAX_STREAM_DATA frame`])      | [`Outgoing::update_window`]                        |
/// | [`recv_stream_control`] ([`STREAM_DATA_BLOCKED frame`])  | none(the frame will be ignored)                    |
/// | [`recv_stream_control`] ([`MAX_STREAMS frame`])          | [`ArcLocalStreamIds::recv_max_streams_frame`]      |
/// | [`recv_stream_control`] ([`STREAMS_BLOCKED frame`])      | [`ArcRemoteStreamIds::recv_streams_blocked_frame`] |
/// | [`on_data_acked`]                                        | [`Outgoing::on_data_acked`]                        |
/// | [`may_loss_data`]                                        | [`Outgoing::may_loss_data`]                        |
/// | [`on_reset_acked`]                                       | [`Outgoing::on_reset_acked`]                       |
///
/// # Create and accept streams
///
/// Stream frames and stream control frames have the function of creating flows. If a steam frame is
/// received but the corresponding stream has not been created, a stream will be created passively.
///
/// [`AcceptBiStream`] and [`AcceptUniStream`] are provided to the application layer to `accept` a
/// stream (obtain a passively created stream). These future will be resolved when a stream is created
/// by peer.
///
/// Alternatively, sending a stream frame or a stream control frame will create a stream actively.
/// [`OpenBiStream`] and [`OpenUniStream`] are provided to the application layer to `open` a stream.
/// These future will be resolved when the connection established.
///
/// [`write`]: tokio::io::AsyncWriteExt::write
/// [`SendBuf`]: crate::send::SendBuf
/// [`send_frame`]: SendFrame::send_frame
/// [`Package::poll_dump`]: qbase::packet::Package::poll_dump
/// [`recv_data`]: DataStreams::recv_data
/// [`recv_stream_control`]: DataStreams::recv_stream_control
/// [`on_data_acked`]: DataStreams::on_data_acked
/// [`may_loss_data`]: DataStreams::may_loss_data
/// [`on_reset_acked`]: DataStreams::on_reset_acked
/// [`RESET_STREAM frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frame
/// [`STOP_SENDING frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames
/// [`MAX_STREAM_DATA frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-max_stream_data-frame
/// [`MAX_STREAMS frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-max_streams-frame
/// [`STREAM_DATA_BLOCKED frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-stream_data_blocked-frame
/// [`STREAMS_BLOCKED frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-streams_blocked-frame
/// [`OpenBiStream`]: crate::streams::OpenBiStream
/// [`OpenUniStream`]: crate::streams::OpenUniStream
/// [`ArcLocalStreamIds::recv_max_streams_frame`]: qbase::sid::ArcLocalStreamIds::recv_max_streams_frame
/// [`ArcRemoteStreamIds::recv_streams_blocked_frame`]: qbase::sid::ArcRemoteStreamIds::recv_streams_blocked_frame
///
#[derive(Debug)]
pub struct DataStreams<TX> {
    // 该queue与space中的transmitter中的frame_queue共享，为了方便向transmitter中写入帧
    ctrl_frames: TX,

    parameters: ArcParameters,
    stream_ids: StreamIds<Ext<TX>, Ext<TX>>,
    // 所有流的待写端，要发送数据，就得向这些流索取
    output: ArcOutput<Ext<TX>>,
    // 所有流的待读端，收到了数据，交付给这些流
    input: ArcInput<Ext<TX>>,
    // 对方主动创建的流
    listener: ArcListener<Ext<TX>>,
    tls_fin: AtomicBool,
    tx_wakers: ArcSendWakers,

    metrics: Option<ArcConnectionMetrics>,
}

fn wrapper_error(fty: FrameType) -> impl FnOnce(ExceedLimitError) -> QuicError {
    move |e| QuicError::new(ErrorKind::StreamLimit, fty.into(), e.to_string())
}

impl<TX> DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    fn poll_dump_once<B: BufMut + ?Sized>(
        &self,
        output: &mut super::io::Output<Ext<TX>>,
        cx: &mut Context<'_>,
        buffer: &mut qbase::packet::ConstraintBuffer<'_, B>,
        frames: &mut Vec<qbase::frame::Frame>,
    ) -> Poll<Result<usize, Error>> {
        use core::ops::Bound::*;
        fn poll_streams<'s, TX: 's + Clone, B: BufMut + ?Sized>(
            streams: impl Iterator<Item = (StreamId, &'s (Outgoing<TX>, IOState), usize)>,
            cx: &mut Context<'_>,
            buffer: &mut qbase::packet::ConstraintBuffer<'_, B>,
            frames: &mut Vec<qbase::frame::Frame>,
        ) -> Result<(StreamId, usize, usize), Poll<Result<usize, Error>>> {
            let mut availability = Poll::Pending;
            for (sid, (outgoing, _), tokens) in streams {
                let start = frames.len();
                let credit = buffer.limits.flow_ctrl();
                match outgoing.poll_dump_with_tokens(cx, buffer, frames, tokens) {
                    Poll::Ready(Ok(n)) if n > 0 => {
                        let length = frames[start..]
                            .iter()
                            .filter_map(|f| match f {
                                qbase::frame::Frame::Stream(f, ()) => Some(f.len()),
                                _ => None,
                            })
                            .sum::<usize>();
                        return Ok((sid, tokens - length, credit - buffer.limits.flow_ctrl()));
                    }
                    Poll::Ready(Ok(_)) => availability = Poll::Ready(Ok(0)),
                    Poll::Ready(Err(error)) => return Err(Poll::Ready(Err(error))),
                    Poll::Pending => {}
                }
            }
            Err(availability)
        }
        let start = frames.len();
        // 不一定所有流都允许被发送，比如，0rtt被拒绝max_streams会倒缩，此时大于max_streams的流就不允许被发送
        let remote_role = self.stream_ids.remote.role();
        let max_streams_bidi = self.stream_ids.local.opened_streams(Dir::Bi);
        let max_streams_uni = self.stream_ids.local.opened_streams(Dir::Uni);
        let stream_allowed = |sid: &StreamId| {
            sid.role() == remote_role
                || sid.dir() == Dir::Bi && sid.id() < max_streams_bidi
                || sid.dir() == Dir::Uni && sid.id() < max_streams_uni
        };

        // 该tokens是令牌桶算法的token，为了多条Stream的公平性，给每个流定期地发放tokens，不累积
        // 各流轮流按令牌桶算法发放的tokens来整理数据去发送
        const DEFAULT_TOKENS: usize = 4096;
        let result = match &output.cursor {
            // Rotate after the exhausted stream, then wrap around.
            Some((sid, tokens)) if *tokens == 0 => poll_streams(
                (output.outgoings.range(..sid).rev())
                    .chain(output.outgoings.range(sid..).rev())
                    .map(|(sid, outgoing)| (*sid, outgoing, DEFAULT_TOKENS))
                    .filter(|(sid, ..)| stream_allowed(sid)),
                cx,
                buffer,
                frames,
            ),
            // [sid] + rev([..sid]) + rev([sid+1..])
            Some((sid, tokens)) => poll_streams(
                Option::into_iter(
                    output
                        .outgoings
                        .get(sid)
                        .map(|outgoing| (*sid, outgoing, *tokens)),
                )
                .chain(
                    (output.outgoings.range(..sid).rev())
                        .chain(output.outgoings.range((Excluded(sid), Unbounded)).rev())
                        .map(|(sid, outgoing)| (*sid, outgoing, DEFAULT_TOKENS)),
                )
                .filter(|(sid, ..)| stream_allowed(sid)),
                cx,
                buffer,
                frames,
            ),
            // rev([..])
            None => poll_streams(
                (output.outgoings.range(..).rev())
                    .map(|(sid, outgoing)| (*sid, outgoing, DEFAULT_TOKENS))
                    .filter(|(sid, ..)| stream_allowed(sid)),
                cx,
                buffer,
                frames,
            ),
        };
        let (sid, remain_tokens, fresh_bytes) = match result {
            Ok(result) => result,
            Err(result) => return result,
        };

        output.cursor = Some((sid, remain_tokens));

        if fresh_bytes > 0
            && let Some(metrics) = &self.metrics
        {
            metrics.on_data_sent(fresh_bytes as u64);
        }
        Poll::Ready(Ok(frames.len() - start))
    }

    /// Called when the stream frame acked.
    ///
    /// Actually calls the [`Outgoing::on_data_acked`] method of the corresponding stream.
    pub fn on_data_acked(&self, frame: StreamFrame) {
        if let Ok(set) = self.output.streams().as_mut() {
            let mut is_all_rcvd = false;
            if let Some((o, s)) = set.get(&frame.stream_id()) {
                is_all_rcvd = o.on_data_acked(&frame);

                // Update metrics when data is acknowledged
                let acked_len = frame.range().end - frame.range().start;
                if acked_len > 0
                    && let Some(metrics) = &self.metrics
                {
                    metrics.on_data_acked(acked_len);
                }

                if is_all_rcvd {
                    s.shutdown_send();
                    if s.is_terminated() {
                        self.stream_ids.remote.on_end_of_stream(frame.stream_id());
                    }
                }
            }

            if is_all_rcvd {
                set.remove(&frame.stream_id());
            }
        }
    }

    /// Called when the stream frame may lost.
    ///
    /// Actually calls the [`Outgoing::may_loss_data`] method of the corresponding stream.
    pub fn may_loss_data(&self, stream_frame: &StreamFrame) {
        if let Some((o, _s)) = self
            .output
            .streams()
            .as_mut()
            .ok()
            .and_then(|set| set.get(&stream_frame.stream_id()))
        {
            o.may_loss_data(stream_frame);
        }
    }

    /// Called when the stream reset frame acked.
    ///
    /// Actually calls the [`Outgoing::on_reset_acked`] method of the corresponding stream.
    pub fn on_reset_acked(&self, reset_frame: ResetStreamFrame) {
        if let Ok(set) = self.output.streams().as_mut()
            && let Some((o, s)) = set.remove(&reset_frame.stream_id())
        {
            o.on_reset_acked(reset_frame.stream_id());
            s.shutdown_send();
            if s.is_terminated() {
                self.stream_ids
                    .remote
                    .on_end_of_stream(reset_frame.stream_id());
            }
        }
        // 如果流是双向的，接收部分的流独立地管理结束。其实是上层应用决定接收的部分是否同时结束
    }

    /// Called when a stream frame which from peer is received by local.
    ///
    /// If the correspoding stream is not exist, `accept` the stream.
    ///
    /// Actually calls the [`Incoming::recv_data`] method of the corresponding stream.
    pub fn recv_data(
        &self,
        (stream_frame, body): (StreamFrame, bytes::Bytes),
    ) -> Result<usize, QuicError> {
        let sid = stream_frame.stream_id();
        // 对方必须是发送端，才能发送此帧
        if sid.role() != self.parameters.role() {
            // 对方的sid，看是否跳跃，把跳跃的流给创建好
            self.try_accept_sid(sid)
                .map_err(wrapper_error(stream_frame.frame_type()))?;
        } else {
            // 我方的sid，那必须是双向流才能收到对方的数据，否则就是错误
            if sid.dir() == Dir::Uni {
                return Err(QuicError::new(
                    ErrorKind::StreamState,
                    stream_frame.frame_type().into(),
                    format!("local {sid} cannot receive STREAM_FRAME"),
                ));
            }
        }

        if let Ok(set) = self.input.streams().as_mut()
            && let Some((incoming, s)) = set.get(&sid)
        {
            let (is_into_rcvd, fresh_data) = incoming.recv_data(stream_frame, body.clone())?;
            if is_into_rcvd {
                // 数据被接收完的，忽略后续的ResetStreamFrame
                s.shutdown_receive();
                if s.is_terminated() {
                    self.stream_ids.remote.on_end_of_stream(sid);
                }
                set.remove(&sid);
            }
            return Ok(fresh_data);
        }
        Ok(0)
    }

    /// Called when a stream control frame which from peer is received by local.
    ///
    /// If the correspoding stream is not exist, `accept` the stream first.
    ///
    /// Actually calls the corresponding method of the corresponding stream for the corresponding frame type.
    pub fn recv_stream_control(
        &self,
        stream_ctl_frame: StreamCtlFrame,
    ) -> Result<usize, QuicError> {
        let mut sync_fresh_data = 0;
        match stream_ctl_frame {
            StreamCtlFrame::ResetStream(reset) => {
                let sid = reset.stream_id();
                // 对方必须是发送端，才能发送此帧
                if sid.role() != self.parameters.role() {
                    self.try_accept_sid(sid)
                        .map_err(wrapper_error(reset.frame_type()))?;
                } else {
                    // 我方创建的流必须是双向流，对方才能发送ResetStream,否则就是错误
                    if sid.dir() == Dir::Uni {
                        return Err(QuicError::new(
                            ErrorKind::StreamState,
                            reset.frame_type().into(),
                            format!("local {sid} cannot receive RESET_STREAM frame"),
                        ));
                    }
                }
                if let Ok(set) = self.input.streams().as_mut()
                    && let Some((incoming, s)) = set.remove(&sid)
                {
                    sync_fresh_data = incoming.recv_reset(reset)?;
                    s.shutdown_receive();
                    if s.is_terminated() {
                        self.stream_ids.remote.on_end_of_stream(reset.stream_id());
                    }
                }
            }
            StreamCtlFrame::StopSending(stop_sending) => {
                let sid = stop_sending.stream_id();
                // 对方必须是接收端，才能发送此帧
                if sid.role() != self.parameters.role() {
                    // 对方创建的单向流，接收端是我方，不可能收到对方的StopSendingFrame
                    if sid.dir() == Dir::Uni {
                        return Err(QuicError::new(
                            ErrorKind::StreamState,
                            stop_sending.frame_type().into(),
                            format!("remote {sid} must not send STOP_SENDING_FRAME"),
                        ));
                    }
                    self.try_accept_sid(sid)
                        .map_err(wrapper_error(stop_sending.frame_type()))?;
                }

                if let Some(final_size) = self
                    .output
                    .streams()
                    .as_mut()
                    .ok()
                    .and_then(|set| set.get(&sid))
                    .and_then(|(outgoing, _s)| outgoing.be_stopped(stop_sending.app_err_code()))
                {
                    self.ctrl_frames.send_frame([StreamCtlFrame::ResetStream(
                        stop_sending.reset_stream(VarInt::from_u64(final_size).unwrap()),
                    )]);
                }
            }
            StreamCtlFrame::MaxStreamData(max_stream_data) => {
                let sid = max_stream_data.stream_id();
                // 对方必须是接收端，才能发送此帧
                if sid.role() != self.parameters.role() {
                    // 对方创建的单向流，接收端是我方，不可能收到对方的MaxStreamData
                    if sid.dir() == Dir::Uni {
                        return Err(QuicError::new(
                            ErrorKind::StreamState,
                            max_stream_data.frame_type().into(),
                            format!("remote {sid} must not send MAX_STREAM_DATA_FRAME"),
                        ));
                    }
                    self.try_accept_sid(sid)
                        .map_err(wrapper_error(max_stream_data.frame_type()))?;
                }
                if let Some((outgoing, _s)) = self
                    .output
                    .streams()
                    .as_ref()
                    .ok()
                    .and_then(|set| set.get(&sid))
                {
                    outgoing.update_window(max_stream_data.max_stream_data());
                }
            }
            StreamCtlFrame::StreamDataBlocked(stream_data_blocked) => {
                let sid = stream_data_blocked.stream_id();
                // 对方必须是发送端，才能发送此帧
                if sid.role() != self.parameters.role() {
                    self.try_accept_sid(sid)
                        .map_err(wrapper_error(stream_data_blocked.frame_type()))?;
                } else {
                    // 我方创建的，必须是双向流，对方才是发送端，才能发出StreamDataBlocked；否则就是错误
                    if sid.dir() == Dir::Uni {
                        return Err(QuicError::new(
                            ErrorKind::StreamState,
                            stream_data_blocked.frame_type().into(),
                            format!("local {sid} cannot receive STREAM_DATA_BLOCKED_FRAME"),
                        ));
                    }
                }
                // 仅仅起到通知作用?主动更新窗口的，此帧没多大用，或许要进一步放大缓冲区大小；被动更新窗口的，此帧有用
            }
            StreamCtlFrame::MaxStreams(max_streams) => {
                // 主要更新我方能创建的单双向流
                _ = self.stream_ids.local.recv_frame(max_streams);
            }
            StreamCtlFrame::StreamsBlocked(streams_blocked) => {
                // 在某些流并发策略中，收到此帧，可能会更新MaxStreams
                _ = self.stream_ids.remote.recv_frame(streams_blocked);
            }
        }
        Ok(sync_fresh_data)
    }

    /// Called when a connection error occured.
    ///
    /// After the method called, read on [`Reader`] or write on [`Writer`] will return an error,
    /// the resouces will be released.
    pub fn on_error(&self, error: &Error) {
        let mut output = match self.output.guard() {
            Ok(out) => out,
            Err(_) => return,
        };
        let mut input = match self.input.guard() {
            Ok(input) => input,
            Err(_) => return,
        };
        let mut listener = match self.listener.guard() {
            Ok(listener) => listener,
            Err(_) => return,
        };

        output.on_error(error);
        input.on_error(error);
        listener.on_error(error);
        self.stream_ids.on_error();
        self.tx_wakers.wake_all();
    }
}

impl<TX> DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    pub(super) fn new(
        parameters: ArcParameters,
        ctrl: Box<dyn ControlStreamsConcurrency>,
        ctrl_frames: TX,
        metrics: Option<qbase::metric::ArcConnectionMetrics>,
    ) -> Self {
        let tx_wakers = ArcSendWakers::default();
        Self {
            stream_ids: StreamIds::new(
                &parameters,
                Ext(ctrl_frames.clone()),
                ctrl,
                tx_wakers.clone(),
            ),
            parameters,
            output: ArcOutput::new(),
            input: ArcInput::default(),
            listener: ArcListener::new(),
            ctrl_frames,
            tls_fin: AtomicBool::new(false),
            tx_wakers,
            metrics,
        }
    }

    pub fn revise_params<Role>(&self, zero_rtt_rejected: bool, remote_params: &Parameters<Role>) {
        if let Ok(output) = self.output.guard() {
            // enter 1rtt state, old state must be 0rtt
            self.tls_fin.store(true, Release);

            let opened_bidi = self.stream_ids.local.opened_streams(Dir::Bi);
            let opened_uni = self.stream_ids.local.opened_streams(Dir::Uni);
            let opened_bidi_snd_wnd_size =
                remote_params.get::<u64>(ParameterId::InitialMaxStreamDataBidiRemote);
            let opened_uni_snd_wnd_size =
                remote_params.get::<u64>(ParameterId::InitialMaxStreamDataUni);
            output.revise_max_stream_data(
                zero_rtt_rejected,
                opened_bidi,
                opened_uni,
                opened_bidi_snd_wnd_size,
                opened_uni_snd_wnd_size,
            );
            let max_streams_bidi = remote_params.get::<u64>(ParameterId::InitialMaxStreamsBidi);
            let max_streams_uni = remote_params.get::<u64>(ParameterId::InitialMaxStreamsUni);
            self.stream_ids.local.revise_max_streams(
                zero_rtt_rejected,
                max_streams_bidi,
                max_streams_uni,
            );
        }
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn poll_open_bi_stream(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<(StreamId, (Reader<Ext<TX>>, Writer<Ext<TX>>))>, Error>> {
        let snd_buf_size = self
            .parameters
            .remote(ParameterId::InitialMaxStreamDataBidiRemote);
        self.poll_open_bi_with_limit(cx, snd_buf_size)
    }

    #[allow(clippy::type_complexity)]
    pub fn poll_open_bi_with_limit(
        &self,
        cx: &mut Context<'_>,
        snd_buf_size: u64,
    ) -> Poll<Result<Option<(StreamId, (Reader<Ext<TX>>, Writer<Ext<TX>>))>, Error>> {
        let mut output = self.output.guard()?;
        let mut input = self.input.guard()?;
        let Some(sid) = ready!(self.stream_ids.local.poll_alloc_sid(cx, Dir::Bi)) else {
            return Poll::Ready(Ok(None));
        };

        let arc_sender = self.create_sender(sid, snd_buf_size);
        let arc_recver = self.create_recver(
            sid,
            self.parameters
                .local(ParameterId::InitialMaxStreamDataBidiLocal),
        );
        let io_state = IOState::bidirection();
        output.insert(sid, Outgoing::new(arc_sender.clone()), io_state.clone());
        input.insert(sid, Incoming::new(arc_recver.clone()), io_state);
        self.tx_wakers.wake_all();
        Poll::Ready(Ok(Some((
            sid,
            (Reader::new(arc_recver), Writer::new(arc_sender)),
        ))))
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn poll_open_uni_stream(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<(StreamId, Writer<Ext<TX>>)>, Error>> {
        let snd_buf_size = self.parameters.remote(ParameterId::InitialMaxStreamDataUni);
        self.poll_open_uni_with_limit(cx, snd_buf_size)
    }

    #[allow(clippy::type_complexity)]
    pub fn poll_open_uni_with_limit(
        &self,
        cx: &mut Context<'_>,
        snd_buf_size: u64,
    ) -> Poll<Result<Option<(StreamId, Writer<Ext<TX>>)>, Error>> {
        let mut output = self.output.guard()?;
        let Some(sid) = ready!(self.stream_ids.local.poll_alloc_sid(cx, Dir::Uni)) else {
            return Poll::Ready(Ok(None));
        };

        let arc_sender = self.create_sender(sid, snd_buf_size);
        let io_state = IOState::send_only();
        output.insert(sid, Outgoing::new(arc_sender.clone()), io_state);
        self.tx_wakers.wake_all();
        Poll::Ready(Ok(Some((sid, Writer::new(arc_sender)))))
    }

    pub(super) fn accept_bi(&self) -> AcceptBiStream<'_, Ext<TX>> {
        self.listener.accept_bi_stream(&self.parameters)
    }

    pub(super) fn accept_uni(&self) -> AcceptUniStream<'_, Ext<TX>> {
        self.listener.accept_uni_stream()
    }

    fn try_accept_sid(&self, sid: StreamId) -> Result<(), ExceedLimitError> {
        match sid.dir() {
            Dir::Bi => self.try_accept_bi_sid(sid),
            Dir::Uni => self.try_accept_uni_sid(sid),
        }
    }

    fn try_accept_bi_sid(&self, sid: StreamId) -> Result<(), ExceedLimitError> {
        let Ok(mut output) = self.output.guard() else {
            return Ok(());
        };
        let Ok(mut input) = self.input.guard() else {
            return Ok(());
        };
        let Ok(mut listener) = self.listener.guard() else {
            return Ok(());
        };
        let result = self.stream_ids.remote.try_accept_sid(sid)?;

        match result {
            AcceptSid::Old => Ok(()),
            AcceptSid::New(need_create) => {
                for sid in need_create {
                    let arc_recver = self.create_recver(
                        sid,
                        self.parameters
                            .local(ParameterId::InitialMaxStreamDataBidiRemote),
                    );
                    // buf_size will be revised by Listener::poll_accept_bi_stream
                    let arc_sender = self.create_sender(sid, 0);
                    let io_state = IOState::bidirection();
                    input.insert(sid, Incoming::new(arc_recver.clone()), io_state.clone());
                    output.insert(sid, Outgoing::new(arc_sender.clone()), io_state);
                    self.tx_wakers.wake_all();
                    listener.push_bi_stream(sid, (arc_recver, arc_sender));
                }
                Ok(())
            }
        }
    }

    fn try_accept_uni_sid(&self, sid: StreamId) -> Result<(), ExceedLimitError> {
        let mut input = match self.input.guard() {
            Ok(input) => input,
            Err(_) => return Ok(()),
        };
        let mut listener = match self.listener.guard() {
            Ok(listener) => listener,
            Err(_) => return Ok(()),
        };
        let result = self.stream_ids.remote.try_accept_sid(sid)?;
        match result {
            AcceptSid::Old => Ok(()),
            AcceptSid::New(need_create) => {
                for sid in need_create {
                    let arc_receiver = self.create_recver(
                        sid,
                        self.parameters.local(ParameterId::InitialMaxStreamDataUni),
                    );
                    let io_state = IOState::receive_only();
                    input.insert(sid, Incoming::new(arc_receiver.clone()), io_state);
                    listener.push_uni_stream(sid, arc_receiver);
                }
                Ok(())
            }
        }
    }

    fn create_sender(&self, sid: StreamId, buf_size: u64) -> ArcSender<Ext<TX>> {
        ArcSender::new(
            sid,
            buf_size,
            Ext(self.ctrl_frames.clone()),
            self.metrics.clone(),
        )
    }

    fn create_recver(&self, sid: StreamId, buf_size: u64) -> ArcRecver<Ext<TX>> {
        ArcRecver::new(sid, buf_size, Ext(self.ctrl_frames.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use bytes::BytesMut;
    use qbase::{
        frame::{Frame, io::SendFrame},
        packet::PacketContent,
        param::{
            ArcParameters,
            handy::{client_parameters, server_parameters},
        },
        role::Role,
        sid::{Dir, handy::DemandConcurrency},
    };
    use tokio::io::AsyncWrite;

    use super::{DataStreams, IOState};
    use crate::send::{Outgoing, Writer};

    #[derive(Clone, Copy)]
    struct MockFrameSender;

    impl<F> SendFrame<F> for MockFrameSender {
        fn send_frame<I: IntoIterator<Item = F>>(&self, _iter: I) {}
    }

    fn packet_frames(
        streams: &DataStreams<MockFrameSender>,
        waker: &std::task::Waker,
    ) -> Vec<Frame> {
        use qbase::packet::{ConstraintBuffer, Constraints, GetType, OneRttHeader};

        let mut bytes = BytesMut::new();
        let mut frames = Vec::new();
        let mut limits = Constraints {
            flow_ctrl: 1200,
            send_quota: 1200,
            credit: 1200,
            max_size: 1200,
            ..Default::default()
        };
        let result = streams.poll_dump(
            &mut Context::from_waker(waker),
            &mut ConstraintBuffer::new(
                &mut bytes,
                &mut limits,
                OneRttHeader::new(Default::default(), Default::default()).get_type(),
                0,
                0,
            ),
            &mut frames,
        );
        assert!(matches!(result, Poll::Ready(Ok(n)) if n > 0));
        frames
    }

    #[test]
    fn busy_streams_take_turns_before_either_exhausts_its_window() {
        use crate::send::CancelStream;

        let streams = DataStreams::new(
            ArcParameters::new(
                Role::Client,
                Arc::new(client_parameters()),
                Arc::new(server_parameters()),
            ),
            Box::new(DemandConcurrency),
            MockFrameSender,
            None,
        );
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut writers = Vec::new();
        for _ in 0..2 {
            let Poll::Ready(Ok(Some((id, mut writer)))) = streams.poll_open_uni_stream(&mut cx)
            else {
                panic!("stream should open");
            };
            writer
                .write(bytes::Bytes::from(vec![7; 64 * 1024]))
                .unwrap();
            writers.push((id, writer));
        }
        let mut sent = std::collections::HashMap::new();
        assert_eq!(streams.fresh_bytes_up_to(0), 0);
        assert_eq!(streams.fresh_bytes_up_to(1200), 1200);
        assert_eq!(streams.fresh_bytes(), 128 * 1024);
        for _ in 0..10 {
            for frame in packet_frames(&streams, cx.waker()) {
                if let Frame::Stream(frame, ()) = frame {
                    *sent.entry(frame.stream_id()).or_insert(0usize) += frame.len();
                }
            }
        }
        assert_eq!(
            streams.fresh_bytes(),
            128 * 1024 - sent.values().sum::<usize>()
        );
        for (_, writer) in &mut writers {
            writer.cancel(0);
        }
        assert_eq!(sent.len(), 2, "one busy stream must not starve the other");
        let bytes = sent.values().copied().collect::<Vec<_>>();
        assert!(bytes[0].abs_diff(bytes[1]) <= 4096, "{sent:?}");
    }

    #[test]
    fn full_packet_does_not_subscribe_to_idle_streams() {
        use std::{
            sync::atomic::{AtomicUsize, Ordering},
            task::{Wake, Waker},
        };

        use crate::send::CancelStream;

        struct Counter(AtomicUsize);
        impl Wake for Counter {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let streams = DataStreams::new(
            ArcParameters::new(
                Role::Client,
                Arc::new(client_parameters()),
                Arc::new(server_parameters()),
            ),
            Box::new(DemandConcurrency),
            MockFrameSender,
            None,
        );
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let mut writers = Vec::new();
        for _ in 0..32 {
            let Poll::Ready(Ok(Some((_, writer)))) = streams.poll_open_uni_stream(&mut cx) else {
                panic!("stream should open");
            };
            writers.push(writer);
        }
        // The highest ID is visited first and fills the packet completely.
        writers
            .last_mut()
            .unwrap()
            .write(bytes::Bytes::from(vec![7; 4096]))
            .unwrap();
        packet_frames(&streams, &waker);
        for writer in &mut writers[..31] {
            writer.write(bytes::Bytes::from_static(b"next")).unwrap();
        }
        let wakes = counter.0.load(Ordering::Relaxed);
        for writer in &mut writers {
            writer.cancel(0);
        }
        assert_eq!(
            wakes, 0,
            "a full packet must not poll and subscribe idle streams"
        );
    }

    #[test]
    fn idle_stream_resumes_for_writes_retransmission_and_fin() {
        let streams = DataStreams::new(
            ArcParameters::new(
                Role::Client,
                Arc::new(client_parameters()),
                Arc::new(server_parameters()),
            ),
            Box::new(DemandConcurrency),
            MockFrameSender,
            None,
        );
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(Ok(Some((_, mut writer)))) = streams.poll_open_uni_stream(&mut cx) else {
            panic!("stream should open")
        };
        writer.write(bytes::Bytes::from_static(b"first")).unwrap();
        let frames = packet_frames(&streams, cx.waker());
        let Frame::Stream(first, ()) = frames[0] else {
            panic!("expected stream data")
        };
        assert_eq!(streams.fresh_bytes(), 0);

        streams.may_loss_data(&first);
        assert_eq!(
            streams.fresh_bytes(),
            0,
            "retransmissions use no new flow credit"
        );
        let frames = packet_frames(&streams, cx.waker());
        let Frame::Stream(resent, ()) = frames[0] else {
            panic!("expected retransmission")
        };
        assert_eq!(resent.range(), first.range());
        streams.on_data_acked(resent);

        writer.write(bytes::Bytes::from_static(b"next")).unwrap();
        assert_eq!(streams.fresh_bytes(), 4);
        let frames = packet_frames(&streams, cx.waker());
        let Frame::Stream(next, ()) = frames[0] else {
            panic!("expected new data")
        };
        assert_eq!(next.range(), 5..9);
        streams.on_data_acked(next);

        assert!(writer.poll_shutdown(&mut cx).is_pending());
        let frames = packet_frames(&streams, cx.waker());
        let Frame::Stream(fin, ()) = frames[0] else {
            panic!("expected FIN")
        };
        assert!(fin.is_fin());
        assert_eq!(fin.range(), 9..9);
        streams.may_loss_data(&fin);
        let frames = packet_frames(&streams, cx.waker());
        let Frame::Stream(resent_fin, ()) = frames[0] else {
            panic!("expected FIN retransmission")
        };
        assert!(resent_fin.is_fin());
        assert_eq!(resent_fin.range(), fin.range());
        streams.on_data_acked(resent_fin);
        assert!(matches!(writer.poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
    }

    #[test]
    fn receive_limits_follow_the_local_stream_direction() {
        use qbase::{error::ErrorKind, frame::StreamFrame, param::ParameterId, sid::StreamId};

        use crate::send::CancelStream;

        for role in [Role::Client, Role::Server] {
            for (local, dir, limit) in [
                (true, Dir::Bi, 3),
                (false, Dir::Bi, 5),
                (false, Dir::Uni, 7),
            ] {
                let mut client = client_parameters();
                let mut server = server_parameters();
                for (id, value) in [
                    (ParameterId::InitialMaxStreamDataBidiLocal, 3u32),
                    (ParameterId::InitialMaxStreamDataBidiRemote, 5),
                    (ParameterId::InitialMaxStreamDataUni, 7),
                ] {
                    client
                        .set(id, if role == Role::Client { value } else { 100 })
                        .unwrap();
                    server
                        .set(id, if role == Role::Server { value } else { 100 })
                        .unwrap();
                }
                let streams = DataStreams::new(
                    ArcParameters::new(role, Arc::new(client), Arc::new(server)),
                    Box::new(DemandConcurrency),
                    MockFrameSender,
                    None,
                );
                let sid = if local {
                    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
                    let Poll::Ready(Ok(Some((sid, (_, mut writer))))) =
                        streams.poll_open_bi_with_limit(&mut cx, 0)
                    else {
                        panic!("peer must allow a bidirectional stream");
                    };
                    writer.cancel(0);
                    sid
                } else {
                    StreamId::new(!role, dir, 0)
                };
                assert_eq!(
                    streams.recv_data((
                        StreamFrame::new(sid, limit - 1, 1),
                        bytes::Bytes::from_static(b"x"),
                    )),
                    Ok(limit as usize)
                );
                let error = streams
                    .recv_data((
                        StreamFrame::new(sid, limit, 1),
                        bytes::Bytes::from_static(b"x"),
                    ))
                    .unwrap_err();
                assert_eq!(error.kind(), ErrorKind::FlowControl);
            }
        }
    }

    #[test]
    fn open_uni_uses_the_remote_unidirectional_limit() {
        use qbase::param::ParameterId;

        use crate::send::CancelStream;

        let mut client = client_parameters();
        client
            .set(ParameterId::InitialMaxStreamDataUni, 0u32)
            .unwrap();
        let server = server_parameters();
        let streams = DataStreams::new(
            ArcParameters::new(Role::Server, Arc::new(client), Arc::new(server)),
            Box::new(DemandConcurrency),
            MockFrameSender,
            None,
        );
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let Poll::Ready(Ok(Some((_, mut writer)))) = streams.poll_open_uni_stream(&mut cx) else {
            panic!("ready parameters must allow opening the stream immediately");
        };
        let ready = writer.poll_ready(&mut cx);
        writer.cancel(0);
        assert!(ready.is_pending(), "zero uni limit must block writing");
    }

    #[test]
    fn ready_streams_use_current_parameters_even_with_remembered_limits() {
        use qbase::param::ServerParameters;

        use crate::send::CancelStream;

        let client = client_parameters();
        let server = server_parameters();
        // Remembered defaults prohibit writing; current parameters permit it.
        let parameters = ArcParameters::new(Role::Client, Arc::new(client), Arc::new(server))
            .with_remembered(Some(Arc::new(ServerParameters::default())));
        let streams = DataStreams::new(
            parameters,
            Box::new(DemandConcurrency),
            MockFrameSender,
            None,
        );
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let Poll::Ready(Ok(Some((_, (_, mut bi))))) = streams.poll_open_bi_stream(&mut cx) else {
            panic!("ready parameters must allow opening the bidirectional stream");
        };
        let Poll::Ready(Ok(Some((_, mut uni)))) = streams.poll_open_uni_stream(&mut cx) else {
            panic!("ready parameters must allow opening the unidirectional stream");
        };
        let bi_ready = bi.poll_ready(&mut cx);
        let uni_ready = uni.poll_ready(&mut cx);
        bi.cancel(0);
        uni.cancel(0);
        assert!(matches!(bi_ready, Poll::Ready(Ok(()))));
        assert!(matches!(uni_ready, Poll::Ready(Ok(()))));
    }

    #[tokio::test]
    async fn empty_collection_wakes_for_new_stream_and_cancels_stream_waiters() {
        use std::{
            sync::atomic::{AtomicUsize, Ordering},
            task::{Wake, Waker},
        };

        use tokio::io::AsyncWriteExt;
        struct Counter(AtomicUsize);
        impl Wake for Counter {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let streams = DataStreams::new(
            ArcParameters::new(
                Role::Client,
                Arc::new(client_parameters()),
                Arc::new(server_parameters()),
            ),
            Box::new(DemandConcurrency),
            MockFrameSender,
            None,
        );
        let a = Arc::new(Counter(AtomicUsize::new(0)));
        let b = Arc::new(Counter(AtomicUsize::new(0)));
        let wa = Waker::from(a.clone());
        let wb = Waker::from(b.clone());
        let poll = |waker: &Waker| {
            use qbase::packet::{Constraints, GetType, OneRttHeader};
            let mut bytes = BytesMut::new();
            let mut frames = Vec::new();
            let mut limits = Constraints {
                flow_ctrl: 100,
                send_quota: 128,
                credit: 128,
                min_size: 0,
                max_size: 128,
                ..Default::default()
            };
            streams.poll_dump(
                &mut Context::from_waker(waker),
                &mut qbase::packet::ConstraintBuffer::new(
                    &mut bytes,
                    &mut limits,
                    OneRttHeader::new(Default::default(), Default::default()).get_type(),
                    0,
                    0,
                ),
                &mut frames,
            )
        };
        assert!(poll(&wa).is_pending());
        assert!(poll(&wb).is_pending());
        let Poll::Ready(Ok(Some((_, mut writer)))) =
            streams.poll_open_uni_with_limit(&mut Context::from_waker(Waker::noop()), 100)
        else {
            panic!("stream should open");
        };
        assert_eq!(a.0.load(Ordering::Relaxed), 1);
        assert_eq!(b.0.load(Ordering::Relaxed), 1);
        // Re-polling discovers the new stream and subscribes both paths to its state.
        assert!(poll(&wa).is_pending());
        assert!(poll(&wb).is_pending());
        streams.unregister(&wa);
        writer.write_all(b"data").await.unwrap();
        assert_eq!(a.0.load(Ordering::Relaxed), 1);
        assert_eq!(b.0.load(Ordering::Relaxed), 2);
        assert!(matches!(poll(&wb), Poll::Ready(Ok(n)) if n > 0));
        streams.unregister(&wb);
        writer.write_all(b"more").await.unwrap();
        assert_eq!(b.0.load(Ordering::Relaxed), 2);
        let c = Arc::new(Counter(AtomicUsize::new(0)));
        let wc = Waker::from(c.clone());
        assert!(matches!(poll(&wc), Poll::Ready(Ok(n)) if n > 0));
        let Poll::Ready(Ok(Some((_, mut next)))) =
            streams.poll_open_uni_with_limit(&mut Context::from_waker(Waker::noop()), 100)
        else {
            panic!("stream should open");
        };
        assert_eq!(a.0.load(Ordering::Relaxed), 1);
        assert_eq!(b.0.load(Ordering::Relaxed), 2);
        assert_eq!(c.0.load(Ordering::Relaxed), 0);
        streams.unregister(&wc);
        use crate::send::CancelStream;
        writer.cancel(0);
        next.cancel(0);
    }

    #[test]
    fn connection_error_preserves_received_but_unread_stream() {
        use qbase::{
            error::{Error, ErrorKind, QuicError},
            frame::StreamFrame,
        };

        use crate::recv::{Incoming, Reader};

        let streams = DataStreams::new(
            ArcParameters::new(
                Role::Client,
                Arc::new(client_parameters()),
                Arc::new(server_parameters()),
            ),
            Box::new(DemandConcurrency),
            MockFrameSender,
            None,
        );
        let sid = qbase::sid::StreamId::new(Role::Client, Dir::Bi, 0);
        let recver = streams.create_recver(sid, 1024);
        streams.input.guard().unwrap().insert(
            sid,
            Incoming::new(recver.clone()),
            IOState::bidirection(),
        );
        let mut reader = Reader::new(recver);
        let mut frame = StreamFrame::new(sid, 0, 4);
        frame.set_eos_flag(true);
        streams
            .recv_data((frame, bytes::Bytes::from_static(b"data")))
            .unwrap();
        let error: Error = QuicError::with_default_fty(ErrorKind::Internal, "closed").into();
        streams.on_error(&error);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let mut buf = BytesMut::with_capacity(4);
        assert!(matches!(
            reader.poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(&buf[..], b"data");
        buf.clear();
        assert!(matches!(
            reader.poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert!(buf.is_empty());
    }

    #[test]
    fn empty_stream_fin_is_effective_packet_content() {
        let streams = Arc::new(DataStreams::new(
            ArcParameters::new(
                Role::Client,
                Arc::new(client_parameters()),
                Arc::new(server_parameters()),
            ),
            Box::new(DemandConcurrency),
            MockFrameSender,
            None,
        ));
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let sid = match streams.stream_ids.local.poll_alloc_sid(&mut cx, Dir::Uni) {
            Poll::Ready(Some(sid)) => sid,
            _ => panic!("the peer should permit a unidirectional stream"),
        };
        let sender = streams.create_sender(sid, 1024);
        streams
            .output
            .streams()
            .as_mut()
            .expect("streams should be open")
            .insert(sid, (Outgoing::new(sender.clone()), IOState::send_only()));

        let mut writer = Writer::new(sender);
        assert!(Pin::new(&mut writer).poll_shutdown(&mut cx).is_pending());

        let mut packet = BytesMut::with_capacity(128);
        let mut limits = qbase::packet::Constraints {
            flow_ctrl: 0,
            send_quota: 128,
            credit: 128,
            min_size: 0,
            max_size: 128,
            ..Default::default()
        };
        use qbase::packet::GetType;
        let mut buffer = qbase::packet::ConstraintBuffer::new(
            &mut packet,
            &mut limits,
            qbase::packet::OneRttHeader::new(Default::default(), Default::default()).get_type(),
            0,
            0,
        );
        let mut frames = Vec::new();
        assert!(
            matches!(streams.poll_dump(&mut cx, &mut buffer, &mut frames), Poll::Ready(Ok(n)) if n > 0)
        );
        assert_eq!(
            qbase::packet::assemble::content(&frames),
            PacketContent::EffectivePayload
        );
        assert!(
            frames
                .iter()
                .any(|frame| matches!(frame, Frame::Stream(frame, ()) if frame.is_fin()))
        );
    }
}

impl<TX> DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    /// Bound reservations by actual pending fresh bytes; idle polling must not reserve and refund flow credit.
    pub fn fresh_bytes(&self) -> usize {
        self.fresh_bytes_up_to(usize::MAX)
    }

    /// Stop counting once the caller has enough credit for its packet.
    pub fn fresh_bytes_up_to(&self, limit: usize) -> usize {
        if limit == 0 {
            return 0;
        }
        let streams = self.output.streams();
        let Ok(output) = streams.as_ref() else {
            return 0;
        };
        let remote = self.stream_ids.remote.role();
        let bidi = self.stream_ids.local.opened_streams(Dir::Bi);
        let uni = self.stream_ids.local.opened_streams(Dir::Uni);
        let mut total = 0usize;
        for (_, (stream, _)) in output.outgoings.iter().filter(|(sid, _)| {
            sid.role() == remote
                || (sid.dir() == Dir::Bi && sid.id() < bidi)
                || (sid.dir() == Dir::Uni && sid.id() < uni)
        }) {
            total = total.saturating_add(stream.fresh_bytes());
            if total >= limit {
                return limit;
            }
        }
        total
    }

    pub(crate) fn poll_dump<B: BufMut + ?Sized>(
        &self,
        cx: &mut Context<'_>,
        buffer: &mut ConstraintBuffer<'_, B>,
        frames: &mut Vec<Frame>,
    ) -> Poll<Result<usize, Error>> {
        // Keep stream insertion serialized with checking readiness and registering.
        let mut guard = self.output.streams();
        let output = match guard.as_mut() {
            Ok(output) => output,
            Err(error) => return Poll::Ready(Err(error.clone())),
        };
        let start = frames.len();
        loop {
            // A full packet or a lengthless STREAM cannot accept another frame.
            buffer.for_frame(
                FrameType::Stream(
                    qbase::frame::Offset::Zero,
                    qbase::frame::Len::Explicit,
                    qbase::frame::Fin::No,
                ),
                frames,
            );
            if buffer.remaining_mut() < 2 {
                return Poll::Ready(Ok(frames.len() - start));
            }
            match self.poll_dump_once(output, cx, buffer, frames) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(n)) if n > 0 => {}
                _ if frames.len() != start => return Poll::Ready(Ok(frames.len() - start)),
                Poll::Pending => {
                    self.tx_wakers.register(cx.waker());
                    return Poll::Pending;
                }
                result => return result,
            }
        }
    }

    pub(crate) fn unregister(&self, waker: &Waker) {
        self.tx_wakers.unregister(waker);
        if let Ok(output) = self.output.streams().as_ref() {
            for (outgoing, _) in output.values() {
                outgoing.unregister(waker);
            }
        }
    }
}
