use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
};

use qbase::{
    error::Error,
    frame::{StreamCtlFrame, io::SendFrame},
    param::ParameterId,
    sid::{
        Dir, StreamId,
        remote_sid::{AcceptSid, ExceedLimitError},
    },
};

use super::{
    ArcDataStreams, DataStreams, Ext,
    io::IOState,
    listener::{AcceptBiStream, AcceptUniStream},
};
use crate::{
    recv::{ArcRecver, Incoming, Reader},
    send::{ArcSender, Outgoing, Writer},
};

impl<TX> ArcDataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    /// Create a bidirectional stream, see the method of the same name on `QuicConnection` for more.
    #[inline]
    pub fn open_bi(&self) -> OpenBiStream<'_, TX> {
        OpenBiStream { streams: self }
    }

    /// Create a unidirectional stream, see the method of the same name on `QuicConnection` for more.
    #[inline]
    pub fn open_uni(&self) -> OpenUniStream<'_, TX> {
        OpenUniStream { streams: self }
    }

    /// accept a bidirectional stream, see the method of the same name on `QuicConnection` for more.
    #[inline]
    pub fn accept_bi(&self) -> AcceptBiStream<'_, Ext<TX>> {
        self.0.accept_bi()
    }

    /// accept a unidirectional stream, see the method of the same name on `QuicConnection` for more.
    #[inline]
    pub fn accept_uni(&self) -> AcceptUniStream<'_, Ext<TX>> {
        self.0.accept_uni()
    }
}

impl<TX> DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    #[allow(clippy::type_complexity)]
    pub(super) fn poll_open_bi_stream(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<(StreamId, (Reader<Ext<TX>>, Writer<Ext<TX>>))>, Error>> {
        let snd_buf_size = self.parameters.remote(ParameterId::InitialMaxStreamDataBidiRemote);
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
        let arc_recver = self.create_recver(sid, self.parameters.local(ParameterId::InitialMaxStreamDataBidiLocal));
        let io_state = IOState::bidirection();
        output.insert(sid, Outgoing::new(arc_sender.clone()), io_state.clone());
        input.insert(sid, Incoming::new(arc_recver.clone()), io_state);
        self.tx_wakers.wake_all();
        Poll::Ready(Ok(Some((sid, (Reader::new(arc_recver), Writer::new(arc_sender))))))
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn poll_open_uni_stream(&self, cx: &mut Context<'_>) -> Poll<Result<Option<(StreamId, Writer<Ext<TX>>)>, Error>> {
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

    pub(super) fn try_accept_sid(&self, sid: StreamId) -> Result<(), ExceedLimitError> {
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
                    let arc_recver = self.create_recver(sid, self.parameters.local(ParameterId::InitialMaxStreamDataBidiRemote));
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
                    let arc_receiver = self.create_recver(sid, self.parameters.local(ParameterId::InitialMaxStreamDataUni));
                    let io_state = IOState::receive_only();
                    input.insert(sid, Incoming::new(arc_receiver.clone()), io_state);
                    listener.push_uni_stream(sid, arc_receiver);
                }
                Ok(())
            }
        }
    }

    fn create_sender(&self, sid: StreamId, buf_size: u64) -> ArcSender<Ext<TX>> {
        ArcSender::new(sid, buf_size, Ext(self.ctrl_frames.clone()), self.metrics.clone())
    }

    fn create_recver(&self, sid: StreamId, buf_size: u64) -> ArcRecver<Ext<TX>> {
        ArcRecver::new(sid, buf_size, Ext(self.ctrl_frames.clone()))
    }
}

/// Future to open a bidirectional stream.
///
/// The creation of the stream is limited by the stream id. Once the stream id is available, the
/// future will complete immediately.
///
/// If a connection error occurred, the future will return an error.
///
/// Although this is a bidirectional stream, the peer will not be aware of this stream until we send
/// a frame on this stream.
pub struct OpenBiStream<'d, TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    streams: &'d DataStreams<TX>,
}

impl<TX> Future for OpenBiStream<'_, TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = Result<Option<(StreamId, (Reader<Ext<TX>>, Writer<Ext<TX>>))>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.streams.poll_open_bi_stream(cx)
    }
}

/// Future to open a unidirectional stream.
///
/// The creation of the stream is limited by the stream id. Once the stream id is available, the
/// future will complete immediately.
///
/// If a connection error occurred, the future will return an error.
///
/// Note that the peer will not be aware of this stream until we send a frame on this stream.
pub struct OpenUniStream<'a, TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    streams: &'a DataStreams<TX>,
}

impl<TX> Future for OpenUniStream<'_, TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = Result<Option<(StreamId, Writer<Ext<TX>>)>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.streams.poll_open_uni_stream(cx)
    }
}
