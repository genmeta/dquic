use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::Arc,
};

use qbase::net::{addr::EndpointAddr, route::Link};
use tokio::task::AbortHandle;

use super::UdpSocket;
use crate::{
    bind_uri::ResolvedBindUri,
    dock::Dock,
    protocol::stun::{StunError, StunProtocol},
};

/// Owns a temporary socket's receive task and Direct QUIC registration.
/// Move this owner to retain a successful probe socket; dropping it revokes both
/// registrations and cancels reception, even when other UDP handles still exist.
pub struct EphemeralSocket {
    udp: Arc<UdpSocket>,
    dock: Arc<Dock>,
    endpoint: EndpointAddr,
    registration: AbortHandle,
}

impl EphemeralSocket {
    pub fn bind(dock: Arc<Dock>, binding: ResolvedBindUri) -> io::Result<Self> {
        let udp = Arc::new(match binding.device {
            Some(device) => UdpSocket::bind_to_device(
                binding.addr,
                qudp::BoundDevice::new(device.name, device.index)?,
            )?,
            None => UdpSocket::bind(binding.addr)?,
        });
        let endpoint = EndpointAddr::direct(udp.local_addr()?);
        let registration = dock.register(udp.clone())?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                "socket is already registered in Dock",
            )
        })?;
        let socket = Self {
            udp,
            dock,
            endpoint,
            registration,
        };
        // The owner rolls back its Dock registration if QUIC registration fails.
        socket
            .dock
            .topology()
            .quic()
            .register(endpoint, &socket.udp)
            .map_err(|error| io::Error::new(io::ErrorKind::AddrInUse, error))?;
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
        self.dock
            .topology()
            .quic()
            .unregister(self.endpoint, &self.udp);
        self.dock
            .remove_registration(self.endpoint.addr(), self.registration.id());
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;
    use crate::{BindUri, ForwardProtocol, QuicProtocol, topology::Topology};

    #[tokio::test]
    async fn bind_receives_quic_and_drop_unregisters_even_with_a_live_udp_handle() {
        let stun = Arc::new(StunProtocol::new());
        let quic = Arc::new(QuicProtocol::new());
        let dock = Dock::new(Arc::new(Topology::new(
            stun.clone(),
            Arc::new(ForwardProtocol::new()),
            quic.clone(),
        )));
        let (sent, mut received) = tokio::sync::mpsc::unbounded_channel();
        quic.on_receive(move |packet, pathway, _| {
            sent.send((packet, pathway)).unwrap();
        });
        let socket = EphemeralSocket::bind(
            dock.clone(),
            BindUri::from("127.0.0.1:0").resolve_binding().unwrap(),
        )
        .unwrap();
        let raw = socket.udp_socket().clone();
        let bound = raw.local_addr().unwrap();
        let endpoint = EndpointAddr::direct(bound);
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let packet = [0x40, 1, 2, 3];
        peer.send_to(&packet, bound).await.unwrap();
        let (received_packet, pathway) = timeout(Duration::from_secs(1), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received_packet.as_ref(), packet);
        assert_eq!(pathway.local(), endpoint);

        drop(socket);
        assert!(dock.find_socket(bound).is_none());
        assert!(quic.find_socket(endpoint).is_none());
        assert_eq!(raw.local_addr().unwrap(), bound);
        let error = stun
            .detect_outer(bound, peer.local_addr().unwrap())
            .await
            .unwrap_err();
        assert!(matches!(error, StunError::Io(error) if error.kind() == io::ErrorKind::NotFound));
    }

    #[tokio::test]
    async fn failed_quic_registration_rolls_back_dock_and_preserves_the_existing_alias() {
        let stun = Arc::new(StunProtocol::new());
        let quic = Arc::new(QuicProtocol::new());
        let dock = Dock::new(Arc::new(Topology::new(
            stun.clone(),
            Arc::new(ForwardProtocol::new()),
            quic.clone(),
        )));
        let existing = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let reservation = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let bound = reservation.local_addr().unwrap();
        let endpoint = EndpointAddr::direct(bound);
        quic.register(endpoint, &existing).unwrap();
        drop(reservation);

        let result = EphemeralSocket::bind(
            dock.clone(),
            ResolvedBindUri {
                addr: bound,
                device: None,
            },
        );
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::AddrInUse));
        assert!(dock.is_empty());
        assert!(Arc::ptr_eq(&quic.find_socket(endpoint).unwrap(), &existing));
        let error = stun
            .detect_outer(bound, existing.local_addr().unwrap())
            .await
            .unwrap_err();
        assert!(matches!(error, StunError::Io(error) if error.kind() == io::ErrorKind::NotFound));
    }

    #[tokio::test]
    async fn old_owner_does_not_remove_replacement_registrations() {
        let quic = Arc::new(QuicProtocol::new());
        let dock = Dock::new(Arc::new(Topology::new(
            Arc::new(StunProtocol::new()),
            Arc::new(ForwardProtocol::new()),
            quic.clone(),
        )));
        let socket = EphemeralSocket::bind(
            dock.clone(),
            BindUri::from("127.0.0.1:0").resolve_binding().unwrap(),
        )
        .unwrap();
        let raw = socket.udp_socket().clone();
        let bound = raw.local_addr().unwrap();
        let endpoint = EndpointAddr::direct(bound);
        assert!(dock.remove(&raw));
        assert!(dock.add(raw.clone()).unwrap());
        let replacement = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        quic.unregister(endpoint, &raw);
        quic.register(endpoint, &replacement).unwrap();

        drop(socket);
        assert!(Arc::ptr_eq(&dock.find_socket(bound).unwrap(), &raw));
        assert!(Arc::ptr_eq(
            &quic.find_socket(endpoint).unwrap(),
            &replacement
        ));
        assert!(dock.remove(&raw));
        quic.unregister(endpoint, &replacement);
    }

    #[tokio::test]
    async fn cancelling_the_owner_releases_the_receive_task_and_port() {
        let quic = Arc::new(QuicProtocol::new());
        let dock = Dock::new(Arc::new(Topology::new(
            Arc::new(StunProtocol::new()),
            Arc::new(ForwardProtocol::new()),
            quic.clone(),
        )));
        let socket = EphemeralSocket::bind(
            dock.clone(),
            BindUri::from("127.0.0.1:0").resolve_binding().unwrap(),
        )
        .unwrap();
        let bound = socket.udp_socket().local_addr().unwrap();
        let weak = Arc::downgrade(socket.udp_socket());
        let task = tokio::spawn(async move {
            let _socket = socket;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(dock.is_empty());
        assert!(quic.find_socket(EndpointAddr::direct(bound)).is_none());
        timeout(Duration::from_secs(1), async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let rebound = UdpSocket::bind(bound).unwrap();
        assert_eq!(rebound.local_addr().unwrap(), bound);
    }
}
