use std::sync::{Arc, RwLock, Weak};

use bytes::BytesMut;
use dashmap::DashMap;
use qbase::net::{
    addr::EndpointAddr,
    route::{Link, Pathway},
};
use thiserror::Error;

use crate::socket::quic::QuicSocket;

type DatagramHandler = dyn Fn(BytesMut, Arc<QuicSocket>, Pathway, Link) + Send + Sync + 'static;

#[derive(Debug, Error)]
#[error("a live QuicSocket is already bound to {0}")]
pub struct EndpointInUse(pub EndpointAddr);

pub struct QuicProtocol {
    sockets: DashMap<EndpointAddr, Weak<QuicSocket>>,
    handler: RwLock<Arc<DatagramHandler>>,
}

impl Default for QuicProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicProtocol {
    pub fn new() -> Self {
        Self {
            sockets: DashMap::new(),
            handler: RwLock::new(Arc::new(|_, _, _, _| {})),
        }
    }

    pub fn set_handler(
        &self,
        handler: impl Fn(BytesMut, Arc<QuicSocket>, Pathway, Link) + Send + Sync + 'static,
    ) {
        *self.handler.write().unwrap() = Arc::new(handler);
    }

    pub fn register(&self, socket: &Arc<QuicSocket>) -> Result<(), EndpointInUse> {
        let endpoint = socket.endpoint_addr();
        match self.sockets.entry(endpoint) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                if entry.get().upgrade().is_some() {
                    return Err(EndpointInUse(endpoint));
                }
                entry.insert(Arc::downgrade(socket));
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(Arc::downgrade(socket));
            }
        }
        Ok(())
    }

    pub fn unregister(&self, socket: &Arc<QuicSocket>) {
        let endpoint = socket.endpoint_addr();
        let weak = Arc::downgrade(socket);
        self.sockets
            .remove_if(&endpoint, |_, registered| Weak::ptr_eq(registered, &weak));
    }

    pub fn socket(&self, endpoint: EndpointAddr) -> Option<Arc<QuicSocket>> {
        let socket = self.sockets.get(&endpoint)?.upgrade();
        if socket.is_none() {
            self.sockets.remove(&endpoint);
        }
        socket
    }

    pub fn on_packet(&self, datagram: BytesMut, pathway: Pathway, link: Link) -> bool {
        let Some(socket) = self.socket(pathway.local()) else {
            return false;
        };
        let handler = self.handler.read().unwrap().clone();
        handler(datagram, socket, pathway, link);
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::socket::UdpSocket;

    #[tokio::test]
    async fn register_and_deliver_by_endpoint() {
        let raw = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let endpoint = EndpointAddr::direct(raw.local_addr().unwrap());
        let socket = Arc::new(QuicSocket::new(raw, endpoint));
        let protocol = QuicProtocol::new();
        let delivered = Arc::new(AtomicUsize::new(0));
        protocol.set_handler({
            let delivered = delivered.clone();
            move |_, _, _, _| {
                delivered.fetch_add(1, Ordering::Relaxed);
            }
        });

        protocol.register(&socket).unwrap();
        assert!(protocol.register(&socket).is_err());
        let link = Link::new(endpoint.addr(), "127.0.0.1:4433".parse().unwrap());
        assert!(protocol.on_packet(BytesMut::from(&b"quic"[..]), link.into(), link));
        assert_eq!(delivered.load(Ordering::Relaxed), 1);

        protocol.unregister(&socket);
        assert!(protocol.socket(endpoint).is_none());
    }
}
