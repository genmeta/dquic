use std::ops::DerefMut;

use bytes::Bytes;
use qbase::{
    error::{Error, QuicError},
    frame::{MaxStreamDataFrame, ResetStreamFrame, StopSendingFrame, StreamFrame, io::SendFrame},
};

use super::recver::{ArcRecver, Recver};

/// An struct for protocol layer to manage the receiving part of a stream.
#[derive(Debug, Clone)]
pub struct Incoming<TX>(ArcRecver<TX>);

impl<TX> Incoming<TX>
where
    TX: SendFrame<StopSendingFrame> + SendFrame<MaxStreamDataFrame> + Clone + Send + 'static,
{
    /// Receive a stream frame from peer.
    ///
    /// The stream frame will be handed over to the receive state machine.
    ///
    /// The data in a stream frame is just a fragment of the data on the stream. The data transmitted
    /// by different stream frames may not continuous. The data will be assembled by [`RecvBuf`] into
    /// continuous data for the application layer to read through [`Reader`].
    ///
    /// [`RecvBuf`]: crate::recv::RecvBuf
    /// [`Reader`]: crate::recv::Reader
    pub fn recv_data(
        &self,
        stream_frame: StreamFrame,
        body: Bytes,
    ) -> Result<(bool, usize), QuicError> {
        let mut recver = self.0.recver();
        let inner = recver.deref_mut();
        let mut is_into_rcvd = false;
        let mut fresh_data = 0;
        if let Ok(receiving_state) = inner {
            match receiving_state {
                Recver::Recv(r) => {
                    if stream_frame.is_fin() {
                        let mut size_known = r.determin_size(&stream_frame)?;
                        fresh_data = size_known.recv(stream_frame, body)?;
                        if size_known.is_all_rcvd() {
                            is_into_rcvd = true;
                            *receiving_state = Recver::DataRcvd(size_known.upgrade());
                        } else {
                            *receiving_state = Recver::SizeKnown(size_known);
                        }
                    } else {
                        fresh_data = r.recv(stream_frame, body)?;
                    }
                }
                Recver::SizeKnown(r) => {
                    fresh_data = r.recv(stream_frame, body)?;
                    if r.is_all_rcvd() {
                        is_into_rcvd = true;
                        *receiving_state = Recver::DataRcvd(r.upgrade());
                    }
                }
                _ => {}
            }
        }
        Ok((is_into_rcvd, fresh_data))
    }

    /// Receive a stream reset frame from peer.
    ///
    /// If all data sent by the peer has not been received, receiving a stream reset frame will cause
    /// any read calls to return an error, received data will be discarded.
    pub fn recv_reset(&self, reset_frame: ResetStreamFrame) -> Result<usize, QuicError> {
        // TODO: ResetStream中还有错误信息，比如http3的错误码，看是否能用到
        let mut sync_fresh_data = 0;
        let mut recver = self.0.recver();
        let inner = recver.deref_mut();
        if let Ok(receiving_state) = inner {
            match receiving_state {
                Recver::Recv(r) => {
                    sync_fresh_data = r.recv_reset(&reset_frame)?;
                    *receiving_state = Recver::ResetRcvd(reset_frame);
                }
                Recver::SizeKnown(r) => {
                    r.recv_reset(&reset_frame)?;
                    *receiving_state = Recver::ResetRcvd(reset_frame);
                }
                _ => unreachable!(),
            }
        }
        Ok(sync_fresh_data)
    }
}

impl<TX> Incoming<TX> {
    pub fn new(recver: ArcRecver<TX>) -> Self {
        Self(recver)
    }

    /// Called when a connecion error occured
    ///
    /// After the connection error occured, trying to read the data from [`Reader`] will result an
    /// Error.
    ///
    /// [`Reader`]: crate::recv::Reader
    pub fn on_error(&self, err: &Error) {
        let mut recver = self.0.recver();
        let inner = recver.deref_mut();
        match inner {
            Ok(receiving_state) => match receiving_state {
                Recver::Recv(r) => r.wake_reader(),
                Recver::SizeKnown(r) => r.wake_reader(),
                _ => return,
            },
            Err(_) => return,
        };
        *inner = Err(err.clone());
    }
}
