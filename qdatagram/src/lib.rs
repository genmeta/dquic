mod reader;
use bytes::Bytes;
pub use reader::*;
mod writer;
use std::io;

use qbase::{
    error::Error,
    frame::{DatagramFrame, io::ReceiveFrame},
};
pub use writer::*;

/// Combination of [`DatagramIncoming`] and [`DatagramOutgoing`]
#[derive(Debug, Clone)]
pub struct DatagramFlow {
    /// The incoming datagram frame, see type's doc for more details.
    incoming: DatagramIncoming,
    /// The outgoing datagram frame, see type's doc for more details.
    outgoing: DatagramOutgoing,
}

impl DatagramFlow {
    /// Creates a new instance of [`DatagramFlow`].
    ///
    /// This method takes local protocol parameter [`max_datagram_frame_size`],
    /// the local's transport parameter [`max_datagram_frame_size`] limits the size of the datagram frames that peer
    /// can send.
    ///
    /// [`max_datagram_frame_size`]: https://www.rfc-editor.org/rfc/rfc9221.html#name-transport-parameter
    #[inline]
    pub fn new(local_max_datagram_frame_size: u64) -> Self {
        Self {
            incoming: DatagramIncoming::new(local_max_datagram_frame_size as _),
            outgoing: DatagramOutgoing::new(),
        }
    }

    /// Create a new **unique** instance of [`DatagramReader`].
    ///
    /// Return an error if the connection is closing or already closed,
    /// or datagram is disenabled by local.
    ///
    /// See [`DatagramIncoming::new_reader`] for more details.
    #[inline]
    pub fn reader(&self) -> io::Result<DatagramReader> {
        self.incoming.new_reader()
    }

    /// Create a new instance of [`DatagramWriter`].
    ///
    /// Return an error if the connection is closing or already closed,
    /// or datagram is disenabled by peer(`max_datagram_frame_size` is `0`)
    ///
    /// See [`DatagramOutgoing::new_writer`] for more details.
    #[inline]
    pub fn writer(&self, max_datagram_frame_size: u64) -> io::Result<DatagramWriter> {
        self.outgoing.new_writer(max_datagram_frame_size)
    }

    /// See [`DatagramOutgoing::on_conn_error`] and [`DatagramIncoming::on_conn_error`] for more details.
    #[inline]
    pub fn on_conn_error(&self, error: &Error) {
        self.incoming.on_conn_error(error);
        self.outgoing.on_conn_error(error);
    }
}

/// See [`DatagramIncoming::recv_datagram`] for more details.
impl ReceiveFrame<(DatagramFrame, Bytes)> for DatagramFlow {
    type Output = ();

    #[inline]
    fn recv_frame(&self, (frame, body): (DatagramFrame, Bytes)) -> Result<Self::Output, Error> {
        self.incoming.recv_datagram(frame, body)
    }
}
