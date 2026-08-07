use std::{io, sync::Arc};

use bytes::BytesMut;
use qbase::{
    datagram::{Datagram, be_datagram},
    net::route::{Line, Pathway},
};

use crate::{
    protocol::{forward::ForwardProtocol, quic::QuicProtocol, stun::StunProtocol},
    socket::UdpSocket,
};

const MAX_DATAGRAM_SIZE: usize = 65_535;

pub struct Topology {
    stun: Arc<StunProtocol>,
    forward: Arc<ForwardProtocol>,
    quic: Arc<QuicProtocol>,
}

impl Topology {
    pub fn new(
        stun: Arc<StunProtocol>,
        forward: Arc<ForwardProtocol>,
        quic: Arc<QuicProtocol>,
    ) -> Self {
        Self {
            stun,
            forward,
            quic,
        }
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
        let mut packets = (0..qudp::BATCH_SIZE)
            .map(|_| BytesMut::zeroed(MAX_DATAGRAM_SIZE))
            .collect::<Vec<_>>();
        let mut lines = vec![Line::default(); qudp::BATCH_SIZE];

        loop {
            let received = socket.receive(&mut packets, &mut lines).await?;
            for index in 0..received {
                let packet = packets[index].split_to(lines[index].seg_size as usize);
                packets[index].resize(MAX_DATAGRAM_SIZE, 0);
                let link = lines[index].link.flip();

                match be_datagram(packet) {
                    Ok(Datagram::Stun(transaction_id, message)) => {
                        self.stun
                            .on_datagram(&socket, transaction_id, message, link)
                            .await?;
                    }
                    Ok(Datagram::Forward(pathway, datagram)) => {
                        self.forward
                            .on_datagram(&socket, pathway, datagram, link)
                            .await?;
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
