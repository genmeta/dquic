use std::ops::DerefMut;

use bytes::{BufMut, Bytes};
use qbase::{
    error::Error as QuicError,
    frame::{ResetStreamError, StreamFrame},
    net::tx::Signals,
    packet::Package,
    sid::StreamId,
    util::Buffer,
    varint::VarInt,
};
use qevent::quic::transport::{GranularStreamStates, StreamSide, StreamStateUpdated};

use super::sender::{ArcSender, Sender, SendingSender, StreamData};

/// An struct for protocol layer to manage the sending part of a stream.
#[derive(Debug, Clone)]
pub struct Outgoing<TX>(ArcSender<TX>);

impl<TX: Clone> Outgoing<TX> {
    /// Try to load data that the application wants to sent to the packet.
    ///
    /// See [`DataStreams::try_load_data_into`] for more about this method.
    ///
    /// Return the size of data loaded, and whether the data is fresh.
    ///
    /// [`DataStreams::try_load_data_into`]: crate::streams::raw::DataStreams::try_load_data_into
    // consume the token internally, return the number of fresh data have been written to the buffer.
    // return None indicates that the stream write no data to the buffer.
    pub fn try_load_data_into<P>(
        &self,
        packet: &mut P,
        sid: StreamId,
        flow_limit: usize,
        tokens: usize,
    ) -> Result<(usize, bool), Signals>
    where
        P: BufMut + ?Sized,
        for<'a> (StreamFrame, &'a [Bytes]): Package<P>,
    {
        let origin_len = packet.remaining_mut();
        let mut write = |(range, is_fresh, data, is_eos): StreamData| {
            let mut frame = StreamFrame::new(sid, range.start, (range.end - range.start) as usize);

            frame.set_eos_flag(is_eos);
            let strategy = frame.encoding_strategy(origin_len);
            frame.set_len_bit(strategy.len_bit());
            packet.put_bytes(0, strategy.pre_padding());
            (frame, data.as_slice()).dump(packet).unwrap();

            (Buffer::len(data.as_slice()), is_fresh)
        };

        let predicate = |offset| {
            StreamFrame::estimate_max_capacity(origin_len, sid, offset)
                .map(|capacity| tokens.min(capacity))
        };
        let mut sender = self.0.sender();
        let sending_state = sender.as_mut().or(Err(Signals::empty()))?; // other(connection closed)

        match sending_state {
            Sender::Ready(s) => {
                let mut s: SendingSender<TX> = s.upgrade();
                let (result, finished) = s
                    .pick_up(predicate, flow_limit)
                    .map(|payload @ (.., with_eos)| (Ok(write(payload)), with_eos))
                    .map_err(|s| (Err(s), false))
                    .unwrap_or_else(|x| x);
                if finished {
                    *sending_state = Sender::DataSent(s.upgrade());
                } else {
                    *sending_state = Sender::Sending(s);
                }
                result
            }
            Sender::Sending(s) => {
                let (result, finished) = s
                    .pick_up(predicate, flow_limit)
                    .map(|payload @ (.., with_eos)| (Ok(write(payload)), with_eos))
                    .map_err(|s| (Err(s), false))
                    .unwrap_or_else(|x| x);
                if finished {
                    *sending_state = Sender::DataSent(s.upgrade());
                }
                result
            }
            Sender::DataSent(s) => s.pick_up(predicate, flow_limit).map(write),
            _ => Err(Signals::TRANSPORT),
        }
    }
}

impl<TX> Outgoing<TX> {
    /// Create a new instance of [`Outgoing`]
    pub fn new(sender: ArcSender<TX>) -> Self {
        Self(sender)
    }

    /// Update the sending window to `max_data_size`
    ///
    /// Callded when the  [`MAX_STREAM_DATA frame`] belonging to the stream is received.
    ///
    /// [`MAX_STREAM_DATA frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-max_stream_data-frames
    pub fn update_window(&self, max_stream_data: u64) {
        self.0.update_window(max_stream_data);
    }

    /// Called when the data sent to peer is acknowlwged.
    ///
    /// * `frame`: the stream frame that has been acknowledged.
    ///
    /// Return `true` if the stream is completely acknowledged, all data has been sent and received.
    ///
    /// [`SendBuf`]: crate::send::SendBuf
    pub fn on_data_acked(&self, frame: &StreamFrame) -> bool {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            match sending_state {
                Sender::Ready(_) => {
                    unreachable!("never send data before recv data");
                }
                Sender::Sending(s) => {
                    s.on_data_acked(frame);
                }
                Sender::DataSent(s) => {
                    s.on_data_acked(frame);
                    if s.is_all_rcvd() {
                        qevent::event!(StreamStateUpdated {
                            stream_id: frame.stream_id(),
                            stream_type: frame.stream_id().dir(),
                            old: GranularStreamStates::DataSent,
                            new: GranularStreamStates::DataReceived,
                            stream_side: StreamSide::Sending
                        });
                        *sending_state = Sender::DataRcvd;
                        return true;
                    }
                }
                // ignore recv
                _ => {}
            }
        };
        false
    }

    /// Called when the data sent to peer may lost.
    ///
    /// * `frame`: the stream frame that may be lost.
    pub fn may_loss_data(&self, frame: &StreamFrame) {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            match sending_state {
                Sender::Ready(_) => {
                    unreachable!("never send data before recv data");
                }
                Sender::Sending(s) => {
                    s.may_loss_data(frame);
                }
                Sender::DataSent(s) => {
                    s.may_loss_data(frame);
                }
                // ignore loss
                _ => (),
            }
        };
    }

    pub fn revise_max_stream_data(&self, zero_rtt_rejected: bool, max_stream_data: u64) {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            match sending_state {
                Sender::Ready(s) => s.revise_max_stream_data(zero_rtt_rejected, max_stream_data),
                Sender::Sending(s) => s.revise_max_stream_data(zero_rtt_rejected, max_stream_data),
                Sender::DataSent(s) => s.revise_max_stream_data(zero_rtt_rejected, max_stream_data),
                _ => (),
            }
        };
    }

    /// Called when the [`STOP_SENDING frame`] sent by the peer is received.
    ///
    /// If the stream has not been closed, the stream will be reset and then a [`RESET_STREAM frame`] will
    /// be sent to the peer to reset the peer with the `final_size`.
    /// In this case, the method will return the `final_size`.
    ///
    /// If the stream has closed, `None` will be returned, and the method will do nothing.
    ///
    /// [`STOP_SENDING frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames
    /// [`STREAM_RESET frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
    pub fn be_stopped(&self, error_code: u64) -> Option<u64> {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => {
                // THINK: sending_state.stream_id() -> StreamId, sending_state.state() -> GranularStreamStates
                let (stream_id, old_state, final_size) = match sending_state {
                    Sender::Ready(s) => {
                        (s.stream_id(), GranularStreamStates::Ready, s.be_stopped())
                    }
                    Sender::Sending(s) => {
                        (s.stream_id(), GranularStreamStates::Send, s.be_stopped())
                    }
                    Sender::DataSent(s) => (
                        s.stream_id(),
                        GranularStreamStates::DataSent,
                        s.be_stopped(),
                    ),
                    _ => return None,
                };
                let reset = ResetStreamError::new(
                    // TODO: many places in the codebase perform VarInt -> u64 -> VarInt conversion
                    //  which is redundant and may cause bugs, consider refactor call-chain.
                    VarInt::from_u64(error_code).expect("app error code must not exceed 2^62"),
                    VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
                );

                qevent::event!(StreamStateUpdated {
                    stream_id: stream_id.id(),
                    stream_type: stream_id.dir(),
                    old: old_state,
                    new: GranularStreamStates::ResetReceived,
                    stream_side: StreamSide::Sending
                });
                *sending_state = Sender::ResetSent(reset);
                Some(final_size)
            }
            Err(_) => None,
        }
    }

    /// Called When the [`RESET_STREAM frame`] previously sent to the peer is acknowledged
    ///
    /// [`RESET_STREAM frame`]: https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
    // TODO: stream id not from stream state, consider refactor. (many other places in qrecovery)
    pub fn on_reset_acked(&self, sid: StreamId) {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        if let Ok(sending_state) = inner {
            match sending_state {
                Sender::ResetSent(r) => {
                    qevent::event!(StreamStateUpdated {
                        stream_id: sid.id(),
                        stream_type: sid.dir(),
                        old: GranularStreamStates::ResetSent,
                        new: GranularStreamStates::ResetReceived,
                        stream_side: StreamSide::Sending
                    });
                    *sending_state = Sender::ResetRcvd(*r);
                }
                Sender::ResetRcvd(..) => {}
                _ => unreachable!(
                    "If no RESET_STREAM has been sent, how can there be a received acknowledgment?"
                ),
            }
        }
    }

    /// When a connection-level error occurs, all data streams must be notified.
    /// Their reading and writing should be terminated, accompanied the error of the connection.
    pub fn on_conn_error(&self, err: &QuicError) {
        let mut sender = self.0.sender();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state {
                Sender::Ready(s) => s.wake_all(),
                Sender::Sending(s) => s.wake_all(),
                Sender::DataSent(s) => s.wake_all(),
                _ => return,
            },
            Err(_) => return,
        };
        *inner = Err(err.clone());
    }
}
