use std::{io, sync::Arc};

use bytes::BytesMut;
use qbase::{
    datagram::{Datagram, be_datagram},
    net::route::{Line, Pathway},
};
use qudp::UdpSocket;

use crate::protocol::{forward::ForwardProtocol, quic::QuicProtocol, stun::StunProtocol};

// A GRO message can span multiple sender bursts. Size it for the receive-side
// aggregation limit rather than the number of messages in one syscall.
const RECV_BUFFER_SIZE: usize = qbase::datagram::MAX_DATAGRAM_SIZE * qudp::MAX_GRO_SEGMENTS;

pub struct Topology {
    stun: Arc<StunProtocol>,
    forward: Arc<ForwardProtocol>,
    quic: Arc<QuicProtocol>,
}

impl Topology {
    pub fn new(stun: Arc<StunProtocol>, forward: Arc<ForwardProtocol>, quic: Arc<QuicProtocol>) -> Self {
        Self { stun, forward, quic }
    }

    pub fn stun(&self) -> &Arc<StunProtocol> {
        &self.stun
    }

    pub fn forward(&self) -> &Arc<ForwardProtocol> {
        &self.forward
    }

    pub fn quic(&self) -> &Arc<QuicProtocol> {
        &self.quic
    }

    pub async fn receive(&self, socket: Arc<UdpSocket>) -> io::Result<()> {
        let mut packets = (0..qudp::BATCH_SIZE).map(|_| BytesMut::zeroed(RECV_BUFFER_SIZE)).collect::<Vec<_>>();
        let mut lines = vec![Line::default(); qudp::BATCH_SIZE];

        loop {
            let received = socket.receive(&mut packets, &mut lines).await?;
            for index in 0..received {
                let mut packet = packets[index].split();
                packets[index].resize(RECV_BUFFER_SIZE, 0);
                let link = lines[index].link.flip();

                while !packet.is_empty() {
                    let len = (lines[index].seg_size as usize).min(packet.len());
                    let datagram = packet.split_to(len);
                    match be_datagram(datagram) {
                        Ok(Datagram::Stun(transaction_id, message)) => {
                            self.stun.on_datagram(&socket, transaction_id, message, link).await?;
                        }
                        Ok(Datagram::Forward(pathway, datagram)) => {
                            let remote = pathway.remote();
                            if self.forward.find_agent(remote.addr()).is_some() || self.quic.find_socket(remote).is_some() {
                                self.quic.on_packet(datagram.into_raw(), pathway.flip(), link);
                            } else {
                                self.forward.on_datagram(link, pathway, datagram).await?;
                            }
                        }
                        Ok(Datagram::Raw(packet)) => {
                            self.quic.on_packet(packet, Pathway::from(link), link);
                        }
                        Err(_) => continue,
                    }
                }
            }
        }
    }
}
