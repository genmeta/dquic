use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering::*},
    },
    task::{Context, Poll, ready},
};

use bytes::{BufMut, Bytes};
use qbase::{
    error::{Error, ErrorKind, QuicError},
    flow::ArcSendControler,
    frame::{
        DataBlockedFrame, FrameType, GetFrameType, ResetStreamFrame,
        STREAM_FRAME_MAX_ENCODING_SIZE, StreamCtlFrame, StreamFrame,
        io::{ReceiveFrame, SendFrame},
    },
    net::tx::{ArcSendWakers, Signals},
    packet::{Package, PacketContent},
    param::{ArcParameters, ParameterId, core::Parameters},
    role::Role,
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
/// Protocol layer will call [`try_load_data_into`] to read data from the streams into stream frames and
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
/// [`try_load_data_into`]: DataStreams::try_load_data_into
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

    role: Role,
    stream_ids: StreamIds<Ext<TX>, Ext<TX>>,
    // 所有流的待写端，要发送数据，就得向这些流索取
    output: ArcOutput<Ext<TX>>,
    // 所有流的待读端，收到了数据，交付给这些流
    input: ArcInput<Ext<TX>>,
    // 对方主动创建的流
    listener: ArcListener<Ext<TX>>,
    tls_fin: AtomicBool,
    tx_wakers: ArcSendWakers,

    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,

    metrics: Option<qbase::metric::ArcConnectionMetrics>,
}

fn wrapper_error(fty: FrameType) -> impl FnOnce(ExceedLimitError) -> QuicError {
    move |e| QuicError::new(ErrorKind::StreamLimit, fty.into(), e.to_string())
}

impl<TX> DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    /// Try to load data from streams into the `packet`,
    /// with a `flow_limit` which limits the max size of fresh data.
    /// Returns the size of fresh data.
    fn try_load_data_into_once<P, FTX>(
        &self,
        packet: &mut P,
        flow_ctrl: &ArcSendControler<FTX>,
        zero_rtt: bool,
    ) -> Result<(), Signals>
    where
        P: BufMut + ?Sized,
        for<'a> (StreamFrame, &'a [Bytes]): Package<P>,
        FTX: SendFrame<DataBlockedFrame>,
    {
        // todo: use core::range instead in rust 2024
        use core::ops::Bound::*;

        if packet.remaining_mut() < STREAM_FRAME_MAX_ENCODING_SIZE {
            return Err(Signals::CONGESTION);
        }

        let mut guard = self.output.streams();
        let output = guard.as_mut().map_err(|_| Signals::empty())?; // connection closed

        if zero_rtt && self.tls_fin.load(Acquire) {
            return Err(Signals::TLS_FIN); // should load 1rtt
        }

        let Ok(mut credit) = flow_ctrl.credit(packet.remaining_mut()) else {
            return Err(Signals::empty()); // connection closed
        };

        fn try_load_data_into_once<'s, P, TX: 's + Clone>(
            streams: impl Iterator<Item = (StreamId, &'s (Outgoing<TX>, IOState), usize)>,
            packet: &mut P,
            flow_limit: usize,
        ) -> Result<(StreamId, usize, usize), Signals>
        where
            P: BufMut + ?Sized,
            for<'a> (StreamFrame, &'a [Bytes]): Package<P>,
        {
            let mut signals = Signals::TRANSPORT;
            for (sid, (outgoing, _ios), tokens) in streams {
                match outgoing.try_load_data_into(packet, sid, flow_limit, tokens) {
                    Ok((data_len, is_fresh)) => {
                        let remain_tokens = tokens - data_len;
                        let fresh_bytes = if is_fresh { data_len } else { 0 };
                        return Ok((sid, remain_tokens, fresh_bytes));
                    }
                    Err(s) => signals |= s,
                }
            }
            Err(signals)
        }

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
        let (sid, remain_tokens, fresh_bytes) = match &output.cursor {
            // rev([..=sid]) + rev([sid+1..])
            Some((sid, tokens)) if *tokens == 0 => try_load_data_into_once(
                (output.outgoings.range(..=sid).rev())
                    .chain(output.outgoings.range((Excluded(sid), Unbounded)).rev())
                    .map(|(sid, outgoing)| (*sid, outgoing, DEFAULT_TOKENS))
                    .filter(|(sid, ..)| stream_allowed(sid)),
                packet,
                credit.available(),
            ),
            // [sid] + rev([..sid]) + rev([sid+1..])
            Some((sid, tokens)) => try_load_data_into_once(
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
                packet,
                credit.available(),
            ),
            // rev([..])
            None => try_load_data_into_once(
                (output.outgoings.range(..).rev())
                    .map(|(sid, outgoing)| (*sid, outgoing, DEFAULT_TOKENS))
                    .filter(|(sid, ..)| stream_allowed(sid)),
                packet,
                credit.available(),
            ),
        }?;

        output.cursor = Some((sid, remain_tokens));
        credit.post_sent(fresh_bytes);

        // Update metrics when fresh data is sent
        if fresh_bytes > 0
            && let Some(metrics) = &self.metrics
        {
            metrics.on_data_sent(fresh_bytes as u64);
        }

        Ok(())
    }

    #[inline]
    pub fn package(
        self: &Arc<Self>,
        flow_ctrl: ArcSendControler<TX>,
        zero_rtt: bool,
    ) -> StreamFramePackages<TX>
    where
        TX: SendFrame<DataBlockedFrame>,
    {
        StreamFramePackages {
            data_stream: self.clone(),
            flow_ctrl,
            zero_rtt,
        }
    }

    /// Try to load data from streams into the packet.
    ///
    /// # Fairness
    ///
    /// It's fair between streams.
    ///
    /// We have implemented a token bucket algorithm, and this method will read the data of each stream
    /// sequentially.  Starting from the first stream, when a stream exhausts its tokens (default is 4096,
    /// depending on the priority of the stream), or there is no data to send, the method will move to
    /// the next stream, and so on.
    ///
    /// # Flow control
    ///
    /// QUIC employs a limit-based flow control scheme where a receiver advertises the limit of total
    /// bytes it is prepared to receive on a given stream or for the entire connection. This leads to
    /// two levels of data flow control in QUIC, stream level and connection level.
    ///
    /// Stream-level flow control had limited by the [`write`] calls on [`Writer`], if the application
    /// wants to write more data than the stream's flow control limit , the [`write`] call will be
    /// blocked until the sending window is updated.
    ///
    /// For connection-level flow control, it's limited by the parameter `flow_limit` of this method.
    /// The amount of new data(never sent) will be read from the stream is less or equal to `flow_limit`.
    ///
    /// # Returns
    ///
    /// If no data written to the buffer, the method will return [`None`], or a tuple will be
    /// returned:
    ///
    /// * [`StreamFrame`]: The stream frame to be sent.
    /// * [`usize`]: The number of bytes written to the buffer.
    /// * [`usize`]: The number of new data writen to the buffer.
    ///
    /// [`write`]: tokio::io::AsyncWriteExt::write
    pub fn try_load_data_into<P, FTX>(
        &self,
        packet: &mut P,
        flow_ctrl: &ArcSendControler<FTX>,
        zero_rtt: bool,
    ) -> Result<(), Signals>
    where
        P: BufMut + ?Sized,
        for<'a> (StreamFrame, &'a [Bytes]): Package<P>,
        FTX: SendFrame<DataBlockedFrame>,
    {
        use core::ops::ControlFlow::*;

        // 取唯一一个最新的错误（如果有）
        let (Continue(result) | Break(result)) =
            core::iter::from_fn(|| Some(self.try_load_data_into_once(packet, flow_ctrl, zero_rtt)))
                .try_fold(Err(Signals::empty()), |result, once| match (result, once) {
                    (_, Ok(())) => Continue(Ok(())),
                    (Ok(()), Err(_no_more)) => Break(Ok(())),
                    (Err(_), Err(signals)) => Break(Err(signals)),
                });
        result
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
        if sid.role() != self.role {
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
                if sid.role() != self.role {
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
                if sid.role() != self.role {
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
                if sid.role() != self.role {
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
                if sid.role() != self.role {
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
    pub fn on_conn_error(&self, error: &Error) {
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

        output.on_conn_error(error);
        input.on_conn_error(error);
        listener.on_conn_error(error);
    }
}

pub struct StreamFramePackages<TX> {
    data_stream: Arc<DataStreams<TX>>,
    flow_ctrl: ArcSendControler<TX>,
    zero_rtt: bool,
}

impl<TX, P> Package<P> for StreamFramePackages<TX>
where
    TX: SendFrame<StreamCtlFrame> + SendFrame<DataBlockedFrame> + Clone + Send + 'static,
    P: BufMut + ?Sized,
    for<'a> (StreamFrame, &'a [Bytes]): Package<P>,
{
    #[inline]
    fn dump(&mut self, packet: &mut P) -> Result<PacketContent, Signals> {
        self.data_stream
            .try_load_data_into_once(packet, &self.flow_ctrl, self.zero_rtt)?;
        Ok(PacketContent::EffectivePayload)
    }
}

impl<TX> DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    pub(super) fn new<LR, RR>(
        role: Role,
        local_params: &Parameters<LR>,
        remote_params: &Parameters<RR>,
        ctrl: Box<dyn ControlStreamsConcurrency>,
        ctrl_frames: TX,
        tx_wakers: ArcSendWakers,
        metrics: Option<qbase::metric::ArcConnectionMetrics>,
    ) -> Self {
        use ParameterId::*;
        Self {
            role,
            stream_ids: StreamIds::new(
                role,
                local_params
                    .get::<u64>(InitialMaxStreamsBidi)
                    .expect("unreachable: default value will be got if the value unset"),
                local_params
                    .get::<u64>(InitialMaxStreamsUni)
                    .expect("unreachable: default value will be got if the value unset"),
                remote_params
                    .get::<u64>(InitialMaxStreamsBidi)
                    .expect("unreachable: default value will be got if the value unset"),
                remote_params
                    .get::<u64>(InitialMaxStreamsUni)
                    .expect("unreachable: default value will be got if the value unset"),
                Ext(ctrl_frames.clone()),
                ctrl,
                tx_wakers.clone(),
            ),
            output: ArcOutput::new(),
            input: ArcInput::default(),
            listener: ArcListener::new(),
            ctrl_frames,
            tls_fin: AtomicBool::new(false),
            tx_wakers,
            initial_max_stream_data_bidi_local: local_params
                .get::<u64>(ParameterId::InitialMaxStreamDataBidiLocal)
                .expect("unreachable: default value will be got if the value unset"),
            initial_max_stream_data_bidi_remote: local_params
                .get::<u64>(ParameterId::InitialMaxStreamDataBidiRemote)
                .expect("unreachable: default value will be got if the value unset"),
            initial_max_stream_data_uni: local_params
                .get::<u64>(ParameterId::InitialMaxStreamDataUni)
                .expect("unreachable: default value will be got if the value unset"),
            metrics,
        }
    }

    pub fn revise_params<Role>(&self, zero_rtt_rejected: bool, remote_params: &Parameters<Role>) {
        if let Ok(output) = self.output.guard() {
            // enter 1rtt state, old state must be 0rtt
            self.tls_fin.store(true, Release);

            let opened_bidi = self.stream_ids.local.opened_streams(Dir::Bi);
            let opened_uni = self.stream_ids.local.opened_streams(Dir::Uni);
            let opened_bidi_snd_wnd_size = remote_params
                .get::<u64>(ParameterId::InitialMaxStreamDataBidiRemote)
                .expect("unreachable: default value will be got if the value unset");
            let opened_uni_snd_wnd_size = remote_params
                .get::<u64>(ParameterId::InitialMaxStreamDataUni)
                .expect("unreachable: default value will be got if the value unset");
            output.revise_max_stream_data(
                zero_rtt_rejected,
                opened_bidi,
                opened_uni,
                opened_bidi_snd_wnd_size,
                opened_uni_snd_wnd_size,
            );
            let max_streams_bidi = remote_params
                .get::<u64>(ParameterId::InitialMaxStreamsBidi)
                .expect("unreachable: default value will be got if the value unset");
            let max_streams_uni = remote_params
                .get::<u64>(ParameterId::InitialMaxStreamsUni)
                .expect("unreachable: default value will be got if the value unset");
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
        arc_params: &ArcParameters,
    ) -> Poll<Result<Option<(StreamId, (Reader<Ext<TX>>, Writer<Ext<TX>>))>, Error>> {
        let mut output = self.output.guard()?;
        let mut input = self.input.guard()?;
        let mut params = arc_params.lock_guard()?;

        let snd_buf_size = match params.remembered() {
            Some(remembered) => remembered
                .get(ParameterId::InitialMaxStreamDataBidiRemote)
                .expect("unreachable: default value will be got if the value unset"),
            None => match params.get_remote(ParameterId::InitialMaxStreamDataBidiRemote) {
                Some(value) => value,
                None => {
                    ready!(params.poll_ready(cx));
                    // tail recursion should be optimized by compiler
                    return self.poll_open_bi_stream(cx, arc_params);
                }
            },
        };

        let Some(sid) = ready!(self.stream_ids.local.poll_alloc_sid(cx, Dir::Bi)) else {
            return Poll::Ready(Ok(None));
        };

        let arc_sender = self.create_sender(sid, snd_buf_size);
        let arc_recver = self.create_recver(sid, self.initial_max_stream_data_bidi_local);
        let io_state = IOState::bidirection();
        output.insert(sid, Outgoing::new(arc_sender.clone()), io_state.clone());
        input.insert(sid, Incoming::new(arc_recver.clone()), io_state);
        Poll::Ready(Ok(Some((
            sid,
            (Reader::new(arc_recver), Writer::new(arc_sender)),
        ))))
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn poll_open_uni_stream(
        &self,
        cx: &mut Context<'_>,
        arc_params: &ArcParameters,
    ) -> Poll<Result<Option<(StreamId, Writer<Ext<TX>>)>, Error>> {
        let mut output = self.output.guard()?;
        let mut params = arc_params.lock_guard()?;

        let snd_buf_size = match params.remembered() {
            Some(remembered) => remembered
                .get(ParameterId::InitialMaxStreamDataUni)
                .expect("unreachable: default value will be got if the value unset"),
            None => match params.get_remote(ParameterId::InitialMaxStreamDataBidiRemote) {
                Some(value) => value,
                None => {
                    ready!(params.poll_ready(cx));
                    // tail recursion should be optimized by compiler
                    return self.poll_open_uni_stream(cx, arc_params);
                }
            },
        };

        let Some(sid) = ready!(self.stream_ids.local.poll_alloc_sid(cx, Dir::Uni)) else {
            return Poll::Ready(Ok(None));
        };

        let arc_sender = self.create_sender(sid, snd_buf_size);
        let io_state = IOState::send_only();
        output.insert(sid, Outgoing::new(arc_sender.clone()), io_state);
        Poll::Ready(Ok(Some((sid, Writer::new(arc_sender)))))
    }

    pub(super) fn accept_bi<'a>(
        &'a self,
        params: &'a ArcParameters,
    ) -> AcceptBiStream<'a, Ext<TX>> {
        self.listener.accept_bi_stream(params)
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
                    let arc_recver =
                        self.create_recver(sid, self.initial_max_stream_data_bidi_remote);
                    // buf_size will be revised by Listener::poll_accept_bi_stream
                    let arc_sender = self.create_sender(sid, 0);
                    let io_state = IOState::bidirection();
                    input.insert(sid, Incoming::new(arc_recver.clone()), io_state.clone());
                    output.insert(sid, Outgoing::new(arc_sender.clone()), io_state);
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
                    let arc_receiver = self.create_recver(sid, self.initial_max_stream_data_uni);
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
            self.tx_wakers.clone(),
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

    use bytes::{BufMut, BytesMut, buf::UninitSlice};
    use qbase::{
        flow::ArcSendControler,
        frame::{Frame, io::SendFrame},
        net::tx::ArcSendWakers,
        packet::{Package, PacketContent, RecordFrame},
        param::handy::{client_parameters, server_parameters},
        role::Role,
        sid::{Dir, handy::DemandConcurrency},
        util::ContinuousData,
    };
    use tokio::io::AsyncWrite;

    use super::{DataStreams, IOState};
    use crate::send::{Outgoing, Writer};

    #[derive(Clone, Copy)]
    struct MockFrameSender;

    impl<F> SendFrame<F> for MockFrameSender {
        fn send_frame<I: IntoIterator<Item = F>>(&self, _iter: I) {}
    }

    struct TestPacket(BytesMut);

    // Safety: every method delegates to BytesMut without changing its initialized-length rules.
    unsafe impl BufMut for TestPacket {
        fn remaining_mut(&self) -> usize {
            self.0.remaining_mut()
        }

        unsafe fn advance_mut(&mut self, cnt: usize) {
            unsafe { self.0.advance_mut(cnt) };
        }

        fn chunk_mut(&mut self) -> &mut UninitSlice {
            self.0.chunk_mut()
        }
    }

    impl<D: ContinuousData> RecordFrame<Frame<D>, D> for TestPacket {
        fn record_frame(&mut self, _frame: &Frame<D>) {}
    }

    #[test]
    fn empty_stream_fin_is_effective_packet_content() {
        let streams = Arc::new(DataStreams::new(
            Role::Client,
            &client_parameters(),
            &server_parameters(),
            Box::new(DemandConcurrency),
            MockFrameSender,
            ArcSendWakers::default(),
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

        let flow_ctrl = ArcSendControler::new(1024, MockFrameSender, ArcSendWakers::default());
        let mut package = streams.package(flow_ctrl, false);
        let mut packet = TestPacket(BytesMut::with_capacity(128));
        assert_eq!(
            package.dump(&mut packet),
            Ok(PacketContent::EffectivePayload)
        );
    }
}
