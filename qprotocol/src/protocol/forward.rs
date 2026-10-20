use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::{Arc, Weak},
};

use dashmap::DashMap;
pub use qbase::datagram::forward::Payload as ForwardPayload;
use qbase::net::{
    addr::EndpointAddr,
    route::{Line, Link, Pathway},
};

use crate::socket::UdpSocket;

#[derive(Default)]
pub struct ForwardProtocol {
    agents: DashMap<SocketAddr, Weak<UdpSocket>>,
}

impl ForwardProtocol {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn serve(&self, agent: SocketAddr, socket: &Arc<UdpSocket>) {
        self.agents.insert(agent, Arc::downgrade(socket));
    }

    pub fn stop_serving(&self, agent: SocketAddr) {
        self.agents.remove(&agent);
    }

    pub async fn on_datagram(
        &self,
        link: Link,
        pathway: Pathway,
        payload: ForwardPayload,
    ) -> io::Result<usize> {
        let Some(socket) = self.find_agent(link.src) else {
            return Ok(0);
        };
        let destination = match pathway.remote() {
            EndpointAddr::Direct { addr } => addr,
            EndpointAddr::Mediate { agent, outer } => match self.find_agent(agent) {
                None => agent,
                Some(agent_socket) => {
                    debug_assert_or_warn!(
                        Arc::ptr_eq(&socket, &agent_socket),
                        "destination agent {agent} and receiving address {} map to different sockets",
                        link.src
                    );
                    outer
                }
            },
        };

        let encoded = payload.as_ref();
        let line = Line::new(
            Link::new(link.src, destination),
            Line::DEFAULT_TTL,
            None,
            encoded.len().min(u16::MAX as usize) as u16,
        );
        let slices = [IoSlice::new(encoded)];
        socket.send(&slices, line).await
    }

    pub(crate) fn find_agent(&self, agent: SocketAddr) -> Option<Arc<UdpSocket>> {
        let socket = self.agents.get(&agent)?.upgrade();
        if socket.is_none() {
            self.agents.remove(&agent);
        }
        socket
    }
}
