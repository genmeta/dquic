use bytes::Bytes;
use qbase::{
    error::{Error, ErrorKind, QuicError},
    frame::{
        FrameType, GetFrameType, ResetStreamFrame, StreamCtlFrame, StreamFrame,
        io::{ReceiveFrame, SendFrame},
    },
    sid::{Dir, remote_sid::ExceedLimitError},
    varint::VarInt,
};

use super::{ArcDataStreams, DataStreams};

fn wrapper_error(fty: FrameType) -> impl FnOnce(ExceedLimitError) -> QuicError {
    move |e| QuicError::new(ErrorKind::StreamLimit, fty.into(), e.to_string())
}

impl<TX> DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    /// Called when the stream frame acked.
    ///
    /// Actually calls the [`Outgoing::on_data_acked`](crate::send::Outgoing::on_data_acked) method of the corresponding stream.
    pub fn on_data_acked(&self, frame: StreamFrame) {
        if let Ok(set) = self.output.streams().as_mut() {
            let mut is_all_rcvd = false;
            if let Some((o, s)) = set.get(&frame.stream_id()) {
                is_all_rcvd = o.on_data_acked(&frame);

                // Update metrics when data is acknowledged
                let acked_len = frame.range().end - frame.range().start;
                if acked_len > 0 {
                    self.metrics.on_data_acked(acked_len);
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
    /// Actually calls the [`Outgoing::may_loss_data`](crate::send::Outgoing::may_loss_data) method of the corresponding stream.
    pub fn may_loss_data(&self, stream_frame: &StreamFrame) {
        if let Some((o, _s)) = self.output.streams().as_mut().ok().and_then(|set| set.get(&stream_frame.stream_id())) {
            o.may_loss_data(stream_frame);
        }
    }

    /// Called when the stream reset frame acked.
    ///
    /// Actually calls the [`Outgoing::on_reset_acked`](crate::send::Outgoing::on_reset_acked) method of the corresponding stream.
    pub fn on_reset_acked(&self, reset_frame: ResetStreamFrame) {
        if let Ok(set) = self.output.streams().as_mut()
            && let Some((o, s)) = set.remove(&reset_frame.stream_id())
        {
            o.on_reset_acked(reset_frame.stream_id());
            s.shutdown_send();
            if s.is_terminated() {
                self.stream_ids.remote.on_end_of_stream(reset_frame.stream_id());
            }
        }
        // 如果流是双向的，接收部分的流独立地管理结束。其实是上层应用决定接收的部分是否同时结束
    }

    /// Called when a stream frame which from peer is received by local.
    ///
    /// If the correspoding stream is not exist, `accept` the stream.
    ///
    /// Actually calls the [`Incoming::recv_data`](crate::recv::Incoming::recv_data) method of the corresponding stream.
    pub fn recv_data(&self, (stream_frame, body): (StreamFrame, bytes::Bytes)) -> Result<usize, Error> {
        if self.input.streams().is_err() {
            return Ok(0);
        }
        let frame_type = stream_frame.frame_type();
        let sid = stream_frame.stream_id();
        // 对方必须是发送端，才能发送此帧
        if sid.role() != self.parameters.role() {
            // 对方的sid，看是否跳跃，把跳跃的流给创建好
            self.try_accept_sid(sid).map_err(wrapper_error(stream_frame.frame_type()))?;
        } else {
            // 我方的sid，那必须是双向流才能收到对方的数据，否则就是错误
            if sid.dir() == Dir::Uni {
                return Err(QuicError::new(
                    ErrorKind::StreamState,
                    stream_frame.frame_type().into(),
                    format!("local {sid} cannot receive STREAM_FRAME"),
                )
                .into());
            }
        }

        let fresh = if let Ok(set) = self.input.streams().as_mut()
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
            fresh_data
        } else {
            0
        };
        self.flow_ctrl.recver.on_new_rcvd(frame_type, fresh)
    }

    /// Called when a stream control frame which from peer is received by local.
    ///
    /// If the correspoding stream is not exist, `accept` the stream first.
    ///
    /// Actually calls the corresponding method of the corresponding stream for the corresponding frame type.
    pub fn recv_stream_control(&self, stream_ctl_frame: StreamCtlFrame) -> Result<usize, Error> {
        let frame_type = stream_ctl_frame.frame_type();
        let mut sync_fresh_data = 0;
        match stream_ctl_frame {
            StreamCtlFrame::MaxData(frame) => {
                self.flow_ctrl.sender.recv_frame(frame)?;
                return Ok(0);
            }
            StreamCtlFrame::DataBlocked(frame) => {
                self.flow_ctrl.recver.recv_frame(frame)?;
                return Ok(0);
            }
            _ if self.output.streams().is_err() => return Ok(0),
            StreamCtlFrame::ResetStream(reset) => {
                let sid = reset.stream_id();
                // 对方必须是发送端，才能发送此帧
                if sid.role() != self.parameters.role() {
                    self.try_accept_sid(sid).map_err(wrapper_error(reset.frame_type()))?;
                } else {
                    // 我方创建的流必须是双向流，对方才能发送ResetStream,否则就是错误
                    if sid.dir() == Dir::Uni {
                        return Err(QuicError::new(
                            ErrorKind::StreamState,
                            reset.frame_type().into(),
                            format!("local {sid} cannot receive RESET_STREAM frame"),
                        )
                        .into());
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
                        )
                        .into());
                    }
                    self.try_accept_sid(sid).map_err(wrapper_error(stop_sending.frame_type()))?;
                }

                if let Some(final_size) = self
                    .output
                    .streams()
                    .as_mut()
                    .ok()
                    .and_then(|set| set.get(&sid))
                    .and_then(|(outgoing, _s)| outgoing.be_stopped(stop_sending.app_err_code()))
                {
                    self.ctrl_frames
                        .send_frame([StreamCtlFrame::ResetStream(stop_sending.reset_stream(VarInt::from_u64(final_size).unwrap()))]);
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
                        )
                        .into());
                    }
                    self.try_accept_sid(sid).map_err(wrapper_error(max_stream_data.frame_type()))?;
                }
                if let Some((outgoing, _s)) = self.output.streams().as_ref().ok().and_then(|set| set.get(&sid)) {
                    outgoing.update_window(max_stream_data.max_stream_data());
                }
            }
            StreamCtlFrame::StreamDataBlocked(stream_data_blocked) => {
                let sid = stream_data_blocked.stream_id();
                // 对方必须是发送端，才能发送此帧
                if sid.role() != self.parameters.role() {
                    self.try_accept_sid(sid).map_err(wrapper_error(stream_data_blocked.frame_type()))?;
                } else {
                    // 我方创建的，必须是双向流，对方才是发送端，才能发出StreamDataBlocked；否则就是错误
                    if sid.dir() == Dir::Uni {
                        return Err(QuicError::new(
                            ErrorKind::StreamState,
                            stream_data_blocked.frame_type().into(),
                            format!("local {sid} cannot receive STREAM_DATA_BLOCKED_FRAME"),
                        )
                        .into());
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
        self.flow_ctrl.recver.on_new_rcvd(frame_type, sync_fresh_data)
    }
}

impl<TX> ReceiveFrame<StreamCtlFrame> for ArcDataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = usize;

    fn recv_frame(&self, frame: StreamCtlFrame) -> Result<Self::Output, Error> {
        self.0.recv_stream_control(frame)
    }
}

impl<TX> ReceiveFrame<(StreamFrame, Bytes)> for ArcDataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = usize;

    fn recv_frame(&self, frame: (StreamFrame, Bytes)) -> Result<Self::Output, Error> {
        self.0.recv_data(frame)
    }
}
