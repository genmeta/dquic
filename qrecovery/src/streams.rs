//! The internal implementation of the QUIC stream.
//!
//! If you want to know how to create a stream, see the `QuicConnection` in another crate for more.
//!
//! If you want to know how to use a stream, see the [`Reader`](crate::recv::Reader) and [`Writer`](crate::send::Writer) for more details.
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
use std::{fmt::Debug, sync::Arc};

use derive_more::Deref;
pub use listener::{AcceptBiStream, AcceptUniStream};
pub use op::{OpenBiStream, OpenUniStream};
use qbase::{
    Close,
    error::Error,
    flow::FlowController,
    frame::{StreamCtlFrame, io::SendFrame},
    metric::ArcConnectionMetrics,
    param::{ArcParameters, ParameterId},
    sid::{ControlStreamsConcurrency, StreamIds},
};

use self::{
    io::{ArcInput, ArcOutput},
    listener::ArcListener,
};
mod ctrl;
pub mod error;
mod fair;
mod io;
mod listener;
mod op;

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
/// [`Incoming`]: crate::recv::Incoming
/// [`Outgoing`]: crate::send::Outgoing
/// [`Reader`]: crate::recv::Reader
/// [`Writer`]: crate::send::Writer
/// [`Incoming::recv_data`]: crate::recv::Incoming::recv_data
/// [`Incoming::recv_reset`]: crate::recv::Incoming::recv_reset
/// [`Outgoing::be_stopped`]: crate::send::Outgoing::be_stopped
/// [`Outgoing::update_window`]: crate::send::Outgoing::update_window
/// [`Outgoing::on_data_acked`]: crate::send::Outgoing::on_data_acked
/// [`Outgoing::may_loss_data`]: crate::send::Outgoing::may_loss_data
/// [`Outgoing::on_reset_acked`]: crate::send::Outgoing::on_reset_acked
///
#[derive(Debug)]
pub struct DataStreams<TX> {
    // 该queue与space中的transmitter中的frame_queue共享，为了方便向transmitter中写入帧
    ctrl_frames: TX,
    flow_ctrl: FlowController<Ext<TX>>,

    parameters: ArcParameters,
    stream_ids: StreamIds<Ext<TX>, Ext<TX>>,
    // 所有流的待写端，要发送数据，就得向这些流索取
    output: ArcOutput<Ext<TX>>,
    // 所有流的待读端，收到了数据，交付给这些流
    input: ArcInput<Ext<TX>>,
    // 对方主动创建的流
    listener: ArcListener<Ext<TX>>,

    metrics: ArcConnectionMetrics,
}

impl<TX> DataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    fn new(
        parameters: ArcParameters,
        ctrl_streams: Box<dyn ControlStreamsConcurrency>,
        ctrl_frames: TX,
        metrics: ArcConnectionMetrics,
    ) -> Self {
        Self {
            flow_ctrl: FlowController::new(
                parameters.remote(ParameterId::InitialMaxData),
                parameters.local(ParameterId::InitialMaxData),
                Ext(ctrl_frames.clone()),
            ),
            stream_ids: StreamIds::new(&parameters, Ext(ctrl_frames.clone()), ctrl_streams),
            parameters,
            output: ArcOutput::new(),
            input: ArcInput::default(),
            listener: ArcListener::new(),
            ctrl_frames,
            metrics,
        }
    }

    /// Called when a connection error occured.
    ///
    /// After the method called, read on [`Reader`](crate::recv::Reader) or write on [`Writer`](crate::send::Writer) will return an error,
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
    }
}

/// Shared data streams, one for each connection.
///
/// App layer can use it to create and accept bidirectional or unidirectional streams.
/// QUIC layer will read frames and data from the streams and send them to peer,
/// and also write the frames and data received from peer to this data streams.
///
/// The `TX` is the frame sender, it should be able to send the [`StreamCtlFrame`], including:
/// - [`StreamCtlFrame::MaxData`]
/// - [`StreamCtlFrame::DataBlocked`]
/// - [`StreamCtlFrame::MaxStreamData`]
/// - [`StreamCtlFrame::MaxStreams`]
/// - [`StreamCtlFrame::StreamDataBlocked`]
/// - [`StreamCtlFrame::StreamsBlocked`]
/// - [`StreamCtlFrame::StopSending`]
/// - [`StreamCtlFrame::ResetStream`]
///
/// Connection flow control and its MAX_DATA/DATA_BLOCKED frames are handled internally.
///
/// See [`DataStreams`] for more details.
#[derive(Debug, Clone, Deref)]
pub struct ArcDataStreams<TX>(Arc<DataStreams<TX>>)
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static;

impl<TX> Close for ArcDataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + Sync + 'static,
{
    fn close_with_error(&self, error: Error) {
        self.on_error(&error);
    }
}

impl<TX> ArcDataStreams<TX>
where
    TX: SendFrame<StreamCtlFrame> + Clone + Send + 'static,
{
    /// Creates a new instance of [`ArcDataStreams`].
    ///
    /// The `ctrl_frames` is the frame sender, read [`DataStreams`] for more details.
    pub fn new(
        parameters: ArcParameters,
        ctrl_streams: Box<dyn ControlStreamsConcurrency>,
        ctrl_frames: TX,
        metrics: ArcConnectionMetrics,
    ) -> Self {
        Self(Arc::new(DataStreams::new(parameters, ctrl_streams, ctrl_frames, metrics)))
    }
}
