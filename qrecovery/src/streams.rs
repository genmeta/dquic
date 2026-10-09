//! The internal implementation of the QUIC stream.
//!
//! If you want to know how to create a stream, see the `QuicConnection` in another crate for more.
//!
//! If you want to know how to use a stream, see the [`Reader`] and [`Writer`] for more details.
//!
//! The structure in this module does not have the ability to actually send and receive frames, or
//! sense the loss or confirmation of frames. These functions are implemented by other modules. This
//! module provides the ability to generate frames, process frames, handle the frame lost and acked,
//! manage the state of all streams.
//!
//! [`DataStreams`] provides a large number of APIs for other blocks to call to achieve the above functions.
//! It corresponds to all streams on the connection.
//!
//! [`Incoming`] and[`Outgoing`] correspond to the input and output of a stream. They manage the sending and
//! receiving state machines and provide APIs for DataStream to use.
//!
//! [`Incoming`]: crate::recv::Incoming
//! [`Outgoing`]: crate::send::Outgoing
use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use derive_more::Deref;
pub use listener::{AcceptBiStream, AcceptUniStream};
use qbase::{
    Close,
    error::Error,
    frame::{
        StreamCtlFrame, StreamFrame,
        io::{ReceiveFrame, SendFrame},
    },
    metric::ArcConnectionMetrics,
    net::tx::UnregisterWaker,
    packet::{Package, PacketBuffer},
    param::ArcParameters,
    sid::{ControlStreamsConcurrency, StreamId},
};

use crate::{recv::Reader, send::Writer};
pub mod error;
mod io;
mod listener;
pub mod raw;

#[derive(Debug, Clone)]
pub struct Ext<T>(T);

impl<TX, F> SendFrame<F> for Ext<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
    F: Into<StreamCtlFrame>,
{
    fn send_frame<I: IntoIterator<Item = F>>(&self, iter: I) {
        self.0.send_frame(iter.into_iter().map(Into::into));
    }
}

/// Shared data streams, one for each connection.
///
/// App layer can use it to create and accept bidirectional or unidirectional streams.
/// QUIC layer will read frames and data from the streams and send them to peer,
/// and also write the frames and data received from peer to this data streams.
///
/// The `TX` is the frame sender, it should be able to send the [`StreamCtlFrame`], including:
/// - [`StreamCtlFrame::MaxStreamData`]
/// - [`StreamCtlFrame::MaxStreams`]
/// - [`StreamCtlFrame::StreamDataBlocked`]
/// - [`StreamCtlFrame::StreamsBlocked`]
/// - [`StreamCtlFrame::StopSending`]
/// - [`StreamCtlFrame::ResetStream`]
///
/// See [`raw::DataStreams`] for more details.
#[derive(Debug, Clone, Deref)]
pub struct DataStreams<TX>(Arc<raw::DataStreams<TX>>)
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static;

impl<TX> Close for DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + Sync + 'static,
{
    fn close_with_error(&self, error: Error) {
        self.on_error(&error);
    }
}

impl<TX> DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    /// Creates a new instance of [`DataStreams`].
    ///
    /// The `ctrl_frames` is the frame sender, read [`raw::DataStreams`] for more details.
    pub fn new(
        parameters: ArcParameters,
        ctrl: Box<dyn ControlStreamsConcurrency>,
        ctrl_frames: TX,
        metrics: Option<ArcConnectionMetrics>,
    ) -> Self {
        Self(Arc::new(raw::DataStreams::new(
            parameters,
            ctrl,
            ctrl_frames,
            metrics,
        )))
    }

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

impl<TX> ReceiveFrame<StreamCtlFrame> for DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = usize;

    fn recv_frame(&self, frame: StreamCtlFrame) -> Result<Self::Output, Error> {
        self.0.recv_stream_control(frame).map_err(Error::Quic)
    }
}

impl<TX> ReceiveFrame<(StreamFrame, Bytes)> for DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    type Output = usize;

    fn recv_frame(&self, frame: (StreamFrame, Bytes)) -> Result<Self::Output, Error> {
        self.0.recv_data(frame).map_err(Error::Quic)
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
    streams: &'d raw::DataStreams<TX>,
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
    streams: &'a raw::DataStreams<TX>,
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

impl<TX, B: bytes::BufMut + ?Sized> Package<B> for DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut PacketBuffer<'_, B>,
    ) -> Poll<Result<usize, Error>> {
        self.0.poll_dump(cx, buffer)
    }
}

impl<TX> UnregisterWaker for DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    fn unregister(&self, waker: &std::task::Waker) {
        self.0.unregister(waker);
    }
}
