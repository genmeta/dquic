use std::{io, net::SocketAddr};

use bytes::BytesMut;
use qbase::{
    datagram::{Datagram, WriteDatagram, stun::Message},
    net::route::{Line, Link, Route},
};
use qinterface::io::{IO, IoExt};

use crate::nat::msg::{Packet, TransactionId};

pub trait StunIO: IO {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.bound_addr()
    }

    fn send_stun_packet(
        &self,
        packet: Packet,
        txid: TransactionId,
        dst: SocketAddr,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            let datagram = match packet {
                Packet::Request(body) => Datagram::Stun(txid, Message::Request(body)),
                Packet::Response(body) => Datagram::Stun(txid, Message::Response(body)),
            };
            let mut buf = BytesMut::with_capacity(128);
            buf.put_datagram(&datagram)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

            let bufs = &[io::IoSlice::new(&buf)];

            // assemble packet header
            let link = Link::new(self.bound_addr()?, dst);
            let pathway = link.into();
            let line = Line::new(link, 64, None, 0);
            let hdr = Route::new(pathway, line);

            self.sendmmsg(bufs, hdr).await
        }
    }
}

impl<I: IO + ?Sized> StunIO for I {}
