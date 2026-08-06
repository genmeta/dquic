use std::{io, sync::Arc};

use bytes::BytesMut;
use qbase::net::route::{Line, Pathway};

use crate::{
    UdpSocket,
    forward::{ForwardProtocol, decode_forward, looks_like_forward},
    quic::QuicProtocol,
    stun::{StunProtocol, decode_stun_header, looks_like_stun},
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
                let mut packet = packets[index].split_to(lines[index].seg_size as usize);
                packets[index].resize(MAX_DATAGRAM_SIZE, 0);
                let link = lines[index].link.flip();

                if looks_like_stun(&packet) {
                    let Ok((_, header_len)) = decode_stun_header(&packet) else {
                        continue;
                    };
                    let payload = packet.split_off(header_len);
                    self.stun.on_packet(&socket, payload, link).await?;
                    continue;
                }

                if looks_like_forward(&packet) {
                    let Ok((header, header_len)) = decode_forward(&packet) else {
                        continue;
                    };
                    self.forward
                        .on_packet(&socket, packet, link, header, header_len)
                        .await?;
                    continue;
                }

                self.quic.on_packet(packet, Pathway::from(link), link);
            }
        }
    }
}
