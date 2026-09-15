use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker, ready},
};

use qbase::{
    error::Error as QuicError,
    frame::{ResetStreamFrame, io::SendFrame},
    param::{ArcParameters, ParameterId},
    sid::StreamId,
};

use crate::{
    recv::{ArcRecver, Reader},
    send::{ArcSender, Writer},
};

#[derive(Debug)]
struct Listener<TX> {
    // 对方主动创建的流
    #[allow(clippy::type_complexity)]
    bi_streams: VecDeque<(StreamId, (ArcRecver<TX>, ArcSender<TX>))>,
    uni_streams: VecDeque<(StreamId, ArcRecver<TX>)>,
    bi_waker: Option<Waker>,
    uni_waker: Option<Waker>,
}

impl<TX> Listener<TX> {
    fn new() -> Self {
        Self {
            bi_streams: VecDeque::with_capacity(4),
            uni_streams: VecDeque::with_capacity(2),
            bi_waker: None,
            uni_waker: None,
        }
    }

    fn push_bi_stream(&mut self, sid: StreamId, stream: (ArcRecver<TX>, ArcSender<TX>)) {
        self.bi_streams.push_back((sid, stream));
        if let Some(waker) = self.bi_waker.take() {
            waker.wake();
        }
    }

    fn push_recv_stream(&mut self, sid: StreamId, stream: ArcRecver<TX>) {
        self.uni_streams.push_back((sid, stream));
        if let Some(waker) = self.uni_waker.take() {
            waker.wake();
        }
    }

    #[allow(clippy::type_complexity)]
    fn poll_accept_bi_stream(
        &mut self,
        cx: &mut Context<'_>,
        arc_params: &ArcParameters,
    ) -> Poll<Result<(StreamId, (Reader<TX>, Writer<TX>)), QuicError>> {
        let mut params = arc_params.lock_guard()?;
        let snd_buf_size = match params.get_remote(ParameterId::InitialMaxStreamDataBidiLocal) {
            Some(value) => value,
            None => {
                ready!(params.poll_ready(cx));
                return self.poll_accept_bi_stream(cx, arc_params);
            }
        };
        if let Some((sid, (recver, sender))) = self.bi_streams.pop_front() {
            sender.update_window(snd_buf_size);
            // recver.update_window(rcv_buf_size);
            Poll::Ready(Ok((sid, (Reader::new(recver), Writer::new(sender)))))
        } else {
            self.bi_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn poll_accept_recv_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(StreamId, Reader<TX>), QuicError>> {
        if let Some((sid, recver)) = self.uni_streams.pop_front() {
            // recver.update_window(rcv_buf_size);
            Poll::Ready(Ok((sid, Reader::new(recver))))
        } else {
            self.uni_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArcListener<TX>(Arc<Mutex<Result<Listener<TX>, QuicError>>>);

impl<TX> ArcListener<TX> {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(Ok(Listener::new()))))
    }

    pub(crate) fn guard(&self) -> Result<ListenerGuard<'_, TX>, QuicError> {
        let guard = self.0.lock().unwrap();
        match guard.as_ref() {
            Ok(_) => Ok(ListenerGuard { inner: guard }),
            Err(e) => Err(e.clone()),
        }
    }

    pub fn accept_bi_stream<'a>(&'a self, params: &'a ArcParameters) -> AcceptBiStream<'a, TX> {
        AcceptBiStream {
            listener: self,
            params,
        }
    }

    pub fn accept_uni_stream(&self) -> AcceptUniStream<'_, TX> {
        AcceptUniStream { listener: self }
    }

    #[allow(clippy::type_complexity)]
    pub fn poll_accept_bi_stream(
        &self,
        cx: &mut Context<'_>,
        arc_params: &ArcParameters,
    ) -> Poll<Result<(StreamId, (Reader<TX>, Writer<TX>)), QuicError>> {
        match self.0.lock().unwrap().as_mut() {
            Ok(set) => set.poll_accept_bi_stream(cx, arc_params),
            Err(e) => Poll::Ready(Err(e.clone())),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn poll_accept_bi_with_limit(
        &self,
        cx: &mut Context<'_>,
        snd_buf_size: u64,
    ) -> Poll<Result<(StreamId, (Reader<TX>, Writer<TX>)), QuicError>> {
        let mut guard = self.0.lock().unwrap();
        let set = guard.as_mut().map_err(|error| error.clone())?;
        if let Some((sid, (recver, sender))) = set.bi_streams.pop_front() {
            sender.update_window(snd_buf_size);
            Poll::Ready(Ok((sid, (Reader::new(recver), Writer::new(sender)))))
        } else {
            set.bi_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub fn poll_accept_uni_stream(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(StreamId, Reader<TX>), QuicError>> {
        match self.0.lock().unwrap().as_mut() {
            Ok(set) => set.poll_accept_recv_stream(cx),
            Err(e) => Poll::Ready(Err(e.clone())),
        }
    }
}

pub(crate) struct ListenerGuard<'a, TX> {
    inner: MutexGuard<'a, Result<Listener<TX>, QuicError>>,
}

impl<TX> ListenerGuard<'_, TX>
where
    TX: SendFrame<ResetStreamFrame> + Clone + Send + 'static,
{
    pub(crate) fn push_bi_stream(&mut self, sid: StreamId, stream: (ArcRecver<TX>, ArcSender<TX>)) {
        match self.inner.as_mut() {
            Ok(set) => set.push_bi_stream(sid, stream),
            Err(e) => unreachable!("listener is invalid: {e}"),
        }
    }

    pub(crate) fn push_uni_stream(&mut self, sid: StreamId, stream: ArcRecver<TX>) {
        match self.inner.as_mut() {
            Ok(set) => set.push_recv_stream(sid, stream),
            Err(e) => unreachable!("listener is invalid: {e}"),
        }
    }

    pub(crate) fn on_conn_error(&mut self, e: &QuicError) {
        match self.inner.as_mut() {
            Ok(set) => {
                if let Some(waker) = set.bi_waker.take() {
                    waker.wake();
                }
                if let Some(waker) = set.uni_waker.take() {
                    waker.wake();
                }
            }
            Err(e) => unreachable!("listener is invalid: {e}"),
        };
        *self.inner = Err(e.clone());
    }
}

/// Future to accept a bidirectional stream.
///
/// This future is created by `accept_bi_stream` method of `QuicConnection`.
///
/// When the peer created a new bidirectional stream, the future will resolve with a [`Reader`] and
/// a [`Writer`] to read and write data on the stream.
#[derive(Debug, Clone)]
pub struct AcceptBiStream<'a, TX> {
    listener: &'a ArcListener<TX>,
    params: &'a ArcParameters,
}

impl<TX> Future for AcceptBiStream<'_, TX>
where
    TX: SendFrame<ResetStreamFrame> + Clone + Send + 'static,
{
    type Output = Result<(StreamId, (Reader<TX>, Writer<TX>)), QuicError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.listener.poll_accept_bi_stream(cx, self.params)
    }
}

/// Future to accept a bidirectional stream.
///
/// This future is created by `accept_uni_stream` method of `QuicConnection`.
///
/// When the peer created a new bidirectional stream, the future will resolve with a [`Reader`] to
/// read data on the stream.
#[derive(Debug, Clone)]
pub struct AcceptUniStream<'l, TX> {
    listener: &'l ArcListener<TX>,
}

impl<TX> Future for AcceptUniStream<'_, TX>
where
    TX: SendFrame<ResetStreamFrame> + Clone + Send + 'static,
{
    type Output = Result<(StreamId, Reader<TX>), QuicError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.listener.poll_accept_uni_stream(cx)
    }
}
