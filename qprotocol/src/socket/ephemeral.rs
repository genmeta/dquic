use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::Arc,
};

use qbase::net::{addr::EndpointAddr, route::Link};
use tokio::task::AbortHandle;

use super::UdpSocket;
use crate::{
    dock::Dock,
    protocol::stun::{StunError, StunProtocol},
};

/// Owns a temporary socket's receive task and Direct QUIC registration.
/// Move this owner to retain a successful probe socket; dropping it revokes both
/// registrations and cancels reception, even when other UDP handles still exist.
pub struct EphemeralSocket {
    udp: Arc<UdpSocket>,
    endpoint: EndpointAddr,
    registration: AbortHandle,
}

impl EphemeralSocket {
    /// Bind the target address and register with the global Dock and QUIC protocol.
    /// Port zero lets the OS choose a port.
    pub fn bind(bound: SocketAddr) -> io::Result<Self> {
        let dock = Dock::global();
        let udp = Arc::new(UdpSocket::bind(bound)?);
        let endpoint = EndpointAddr::direct(udp.local_addr()?);
        let registration = dock.add(udp.clone())?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                "socket is already registered in Dock",
            )
        })?;
        let socket = Self {
            udp,
            endpoint,
            registration,
        };
        Ok(socket)
    }

    pub fn udp_socket(&self) -> &Arc<UdpSocket> {
        &self.udp
    }

    pub async fn outer_addr(
        &self,
        stun: &Arc<StunProtocol>,
        agent: SocketAddr,
    ) -> Result<SocketAddr, StunError> {
        stun.detect_outer(self.udp.local_addr()?, agent)
            .await?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "STUN mapping probe timed out").into()
            })
    }

    pub async fn send(&self, packets: &[IoSlice<'_>], link: Link) -> io::Result<usize> {
        let segment_size = packets.first().map_or(0, |packet| packet.len());
        let line = qbase::net::route::Line::new(
            link,
            qbase::net::route::Line::DEFAULT_TTL,
            None,
            segment_size.min(u16::MAX as usize) as u16,
        );
        self.udp.send(packets, line).await
    }
}

impl Drop for EphemeralSocket {
    fn drop(&mut self) {
        Dock::global().remove_registration(self.endpoint.addr(), self.registration.id());
    }
}
