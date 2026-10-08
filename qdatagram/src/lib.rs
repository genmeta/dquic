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

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll, Waker};

    use qbase::{
        error::AppError,
        packet::{Constraints, GetType, OneRttHeader, Package, PacketBuffer},
    };

    use super::*;

    #[test]
    fn closed_datagrams_ignore_transport_io_but_fail_application_io() {
        let mut flow = DatagramFlow::new(64);
        let reader = flow.reader().unwrap();
        let writer = flow.writer(64).unwrap();
        writer.send_bytes(Bytes::from_static(b"queued")).unwrap();
        let error = AppError::new(42u32.into(), "closed").into();
        flow.on_conn_error(&error);
        let mut cx = Context::from_waker(Waker::noop());
        let mut bytes = Vec::new();
        let mut frames = Vec::new();
        let mut limits = Constraints {
            send_quota: 128,
            credit: 128,
            max_size: 128,
            ..Default::default()
        };
        let packet_type = OneRttHeader::new(Default::default(), Default::default()).get_type();
        for _ in 0..2 {
            let mut buffer =
                PacketBuffer::new(&mut bytes, &mut limits, &mut frames, packet_type, 0, 0);
            assert_eq!(
                flow.outgoing.poll_dump(&mut cx, &mut buffer),
                Poll::Ready(Ok(0))
            );
        }
        assert!(bytes.is_empty());
        assert!(frames.is_empty());
        // Even an oversized datagram is ignored after close.
        assert_eq!(
            flow.recv_frame((
                DatagramFrame::new(true, 128u32.into()),
                Bytes::from(vec![0; 128])
            )),
            Ok(())
        );
        assert!(matches!(reader.poll_recv(&mut cx), Poll::Ready(Err(_))));
        let failure = writer.send_bytes(Bytes::from_static(b"late")).unwrap_err();
        assert_eq!(
            failure.get_ref().unwrap().downcast_ref::<Error>(),
            Some(&error)
        );
        assert!(flow.reader().is_err());
        assert!(flow.writer(64).is_err());
    }
}
