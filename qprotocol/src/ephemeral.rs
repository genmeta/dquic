use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::Arc,
};

use futures::future::AbortHandle;
use qbase::net::route::Link;

use crate::{
    UdpSocket,
    protocol::stun::{StunError, StunProtocol},
};

/// Owns a temporary socket and stops reception on drop.
/// The receiver then unregisters and releases the socket without notifying
/// [`crate::Dock::on_socket_closed`]. UDP handles must not outlive this owner.
pub struct EphemeralSocket {
    pub(super) socket: Arc<UdpSocket>,
    pub(super) reception: AbortHandle,
}

impl EphemeralSocket {
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }

    pub async fn outer_addr(&self, stun: &Arc<StunProtocol>, agent: SocketAddr) -> Result<SocketAddr, StunError> {
        stun.detect_outer(self.socket.local_addr()?, agent)
            .await?
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "STUN mapping probe timed out").into())
    }

    pub async fn send(&self, packets: &[IoSlice<'_>], link: Link) -> io::Result<usize> {
        let segment_size = packets.first().map_or(0, |packet| packet.len());
        let line =
            qbase::net::route::Line::new(link, qbase::net::route::Line::DEFAULT_TTL, None, segment_size.min(u16::MAX as usize) as u16);
        self.socket.send(packets, line).await
    }
}

impl Drop for EphemeralSocket {
    fn drop(&mut self) {
        self.reception.abort();
    }
}
