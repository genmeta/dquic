use std::{
    io,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    frame::GuaranteedFrame,
    packet::{
        OneRttHeader,
        assemble::{Assemble, Constraints, Package},
    },
};
use qtransport::{
    packet::assemble::{Envelope, Packet},
    space::{DataSpace, Recover},
};

use super::PunchPacketEncoder;

const MAX_PUNCH_PACKET_SIZE: usize = 128;

/// Builds pathless probes using the connection's shared 1-RTT keys and packet numbers.
#[derive(Clone)]
pub struct ProbeEncoder {
    space: Arc<DataSpace>,
    peer_cid: ConnectionId,
}

impl ProbeEncoder {
    pub fn new(space: Arc<DataSpace>, peer_cid: ConnectionId) -> Self {
        Self { space, peer_cid }
    }
}

impl PunchPacketEncoder for ProbeEncoder {
    fn encode_probe<P>(&self, mut frame: P) -> io::Result<BytesMut>
    where
        P: for<'b> Package<&'b mut BytesMut>,
    {
        let space = &self.space;
        let keys = space.keys.get().map_err(io::Error::other)?;
        let (pn, key) = keys
            .reserve(|_| space.next_pn().map_err(Into::into))
            .map_err(io::Error::other)?;
        let result = (|| {
            let mut bytes = BytesMut::with_capacity(MAX_PUNCH_PACKET_SIZE);
            let header = OneRttHeader::new(Default::default(), self.peer_cid);
            let packet = Packet::new(header, pn, &mut bytes).map_err(io::Error::other)?;
            let mut limits = Constraints {
                flow_ctrl: usize::MAX,
                send_quota: usize::MAX,
                credit: usize::MAX,
                min_size: 0,
                max_size: MAX_PUNCH_PACKET_SIZE,
                ..Default::default()
            };
            let mut sending = Envelope {
                packet,
                keys: &key,
                limits: &mut limits,
            };
            let mut frames = Vec::<GuaranteedFrame>::with_capacity(1);
            match sending.assemble(
                &mut Context::from_waker(Waker::noop()),
                [&mut frame],
                &mut frames,
            ) {
                Poll::Ready(Ok(1)) => {
                    sending.seal().map_err(io::Error::other)?;
                    Ok(bytes)
                }
                Poll::Ready(Err(error)) => Err(io::Error::other(error)),
                _ => Err(io::Error::other("punch frame did not fit")),
            }
        })();
        match result {
            Ok(bytes) => {
                space.on_sent([(pn.0, false)], Duration::ZERO, Duration::ZERO);
                Ok(bytes)
            }
            Err(error) => {
                space.cancel(pn.0, &mut std::iter::empty());
                Err(error)
            }
        }
    }
}
