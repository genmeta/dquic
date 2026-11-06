use std::{
    io,
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    Epoch,
    cid::ArcDcid,
    frame::GuaranteedFrame,
    packet::{DataHeader, OneRttHeader, PacketContent, assemble::Package},
};
use qtransport::{
    ArcReliableFrames,
    packet::encrypt::Packet,
    space::{Allocate, ArcSpaces, DataSpace, Keys, Recover},
};

use super::PunchPacketEncoder;

const MAX_PUNCH_PACKET_SIZE: usize = 128;

/// Builds pathless probes using the connection's shared 1-RTT keys and packet numbers.
#[derive(Clone)]
pub struct ProbeEncoder {
    spaces: ArcSpaces,
    peer_cid: ArcDcid<ArcReliableFrames>,
}

impl ProbeEncoder {
    /// Retain a handshake CID handle so probes follow the initial peer SCID.
    pub fn new(spaces: ArcSpaces, peer_cid: ArcDcid<ArcReliableFrames>) -> Self {
        Self { spaces, peer_cid }
    }
}

impl PunchPacketEncoder for ProbeEncoder {
    fn encode_probe<P>(&self, mut frame: P) -> io::Result<BytesMut>
    where
        P: for<'b> Package<&'b mut [u8]>,
    {
        let space = self
            .spaces
            .get_as::<DataSpace>(Epoch::Data)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Data space is not installed"))?;
        let Poll::Ready(Some(peer_cid)) = self.peer_cid.poll_borrow(&mut Context::from_waker(Waker::noop())) else {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "peer CID is unavailable"));
        };
        self.peer_cid.refresh();
        let (pn, Keys::Short(key)) = space.pn_and_keys().ok_or_else(|| io::Error::other("keys retired"))? else {
            unreachable!("Data space uses 1-RTT keys");
        };
        let mut bytes = BytesMut::zeroed(MAX_PUNCH_PACKET_SIZE);
        let header = OneRttHeader::new(Default::default(), peer_cid);
        let mut frames = Vec::<GuaranteedFrame>::with_capacity(1);
        let mut sending = Packet::new(DataHeader::Short(header), pn, key.as_ref());
        match sending.assemble(
            &mut Context::from_waker(Waker::noop()),
            &mut std::io::Cursor::new(bytes.as_mut()),
            usize::MAX,
            PacketContent::EffectivePayload,
            &mut frames,
            &mut [&mut frame],
        ) {
            Poll::Ready((size, _)) if size > 0 => {
                bytes.resize(sending.len(), 0);
                sending.seal(&mut bytes);
                space.on_sent(pn.0, false, Duration::ZERO, Duration::ZERO);
                Ok(bytes)
            }
            _ => {
                space.cancel(pn.0, &mut std::iter::empty());
                Err(io::Error::other("punch frame did not fit"))
            }
        }
    }
}
