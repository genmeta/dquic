use std::{
    fmt,
    net::SocketAddr,
    sync::{Arc, OnceLock, RwLock},
};

use bytes::BytesMut;
use dashmap::DashMap;
pub use qbase::packet::Packet;
use qbase::{
    cid::{ConnectionId, GenUniqueCid, RetireCid},
    error::Error,
    frame::{
        NewConnectionIdFrame, RetireConnectionIdFrame,
        io::{ReceiveFrame, SendFrame},
    },
    net::route::{Link, Pathway},
    packet::{DataHeader, GetDcid, PacketReader, long},
};

use crate::packet::{CipherPacket, channel::Inbox};
pub type IncomingCallback = dyn Fn(CipherPacket<long::InitialHeader>, Pathway, Link) + Send + Sync;

pub struct QuicRouter {
    table: DashMap<Signpost, Inbox>,
    incoming_cb: RwLock<Box<IncomingCallback>>,
}

impl fmt::Debug for QuicRouter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("QuicRouter").finish_non_exhaustive()
    }
}

impl QuicRouter {
    pub fn global() -> &'static Arc<Self> {
        static GLOBAL_ROUTER: OnceLock<Arc<QuicRouter>> = OnceLock::new();
        GLOBAL_ROUTER.get_or_init(|| {
            let router = Arc::new(Self::new());
            let receiver = router.clone();
            qprotocol::QuicProtocol::global().on_receive(move |bytes, pathway, link| {
                receiver.receive(bytes, pathway, link, 8);
            });
            router
        })
    }

    pub fn new() -> Self {
        QuicRouter {
            table: DashMap::new(),
            incoming_cb: RwLock::new(Box::new(|_, _, _| {})),
        }
    }

    pub fn on_incoming<F>(&self, callback: F)
    where
        F: Fn(CipherPacket<long::InitialHeader>, Pathway, Link) + Send + Sync + 'static,
    {
        *self.incoming_cb.write().unwrap() = Box::new(callback);
    }

    // for origin_dcid
    pub fn insert(self: &Arc<Self>, signpost: Signpost, inbox: Inbox) -> QuicRouterEntry {
        self.table.insert(signpost, inbox.clone());
        QuicRouterEntry {
            signpost,
            inbox,
            router: self.clone(),
        }
    }

    pub fn remove(&self, signpost: &Signpost) {
        self.table.remove(signpost);
    }

    fn signpost(packet: &Packet, link: &Link) -> Signpost {
        let dcid = match packet {
            Packet::VN(packet) => packet.dcid(),
            Packet::Retry(packet) => packet.dcid(),
            Packet::Data(packet) => packet.dcid(),
        };
        if dcid.is_empty() {
            Signpost::from(link.dst)
        } else {
            Signpost::from(*dcid)
        }
    }

    fn find_entry(&self, packet: &Packet, link: &Link) -> Option<Inbox> {
        self.table
            .get(&Self::signpost(packet, link))
            .map(|queue| queue.clone())
    }

    /// Parse a UDP datagram without blocking the protocol's shared receive callback.
    pub fn receive(&self, bytes: BytesMut, pathway: Pathway, link: Link, cid_len: usize) {
        for packet in PacketReader::new(bytes, cid_len) {
            let Ok(packet) = packet else { break };
            self.deliver(packet, pathway, link);
        }
    }

    pub fn deliver(&self, packet: Packet, pathway: Pathway, link: Link) {
        if let Some(inbox) = self.find_entry(&packet, &link) {
            inbox.try_send(packet, pathway, link);
            return;
        }
        if let Packet::Data(qbase::packet::DataPacket {
            header: DataHeader::Long(long::DataHeader::Initial(header)),
            bytes,
            offset,
        }) = packet
        {
            (self.incoming_cb.read().unwrap())(
                CipherPacket::new(header, bytes, offset),
                pathway,
                link,
            );
        }
    }

    pub fn registry_on_issuing_scid<T>(
        self: &Arc<Self>,
        inbox: Inbox,
        issued_cids: T,
    ) -> QuicRouterRegistry<T> {
        QuicRouterRegistry {
            router: self.clone(),
            inbox,
            issued_cids,
        }
    }
}

impl Default for QuicRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub struct Signpost {
    cid: ConnectionId,
    peer: Option<SocketAddr>,
}

impl From<ConnectionId> for Signpost {
    fn from(value: ConnectionId) -> Self {
        Self {
            cid: value,
            peer: None,
        }
    }
}

impl From<SocketAddr> for Signpost {
    fn from(value: SocketAddr) -> Self {
        Self {
            cid: ConnectionId::default(),
            peer: Some(value),
        }
    }
}

#[must_use = "When RouterEntry dropped, this will remove the entry from the router table"]
pub struct QuicRouterEntry {
    signpost: Signpost,
    inbox: Inbox,
    router: Arc<QuicRouter>,
}

impl QuicRouterEntry {
    pub fn signpost(&self) -> Signpost {
        self.signpost
    }

    pub fn router(&self) -> &Arc<QuicRouter> {
        &self.router
    }

    pub fn inbox(&self) -> Inbox {
        self.inbox.clone()
    }

    pub fn remove(&self) {
        self.router
            .table
            .remove_if(&self.signpost, |_, inbox| inbox.same_channel(&self.inbox));
    }
}

impl Drop for QuicRouterEntry {
    fn drop(&mut self) {
        self.remove();
    }
}

#[derive(Clone)]
pub struct QuicRouterRegistry<TX> {
    router: Arc<QuicRouter>,
    inbox: Inbox,
    issued_cids: TX,
}

impl<T> GenUniqueCid for QuicRouterRegistry<T>
where
    T: Send + Sync + 'static,
{
    fn gen_unique_cid(&self) -> ConnectionId {
        core::iter::from_fn(|| Some(ConnectionId::random_gen_with_mark(8, 0x80, 0x7F)))
            .find(|cid| {
                let signpost = Signpost::from(*cid);
                let entry = self.router.table.entry(signpost);

                if matches!(entry, dashmap::Entry::Occupied(..)) {
                    return false;
                }

                entry.insert(self.inbox.clone());
                true
            })
            .unwrap()
    }
}

impl<TX> RetireCid for QuicRouterRegistry<TX>
where
    TX: Send + Sync + 'static,
{
    fn retire_cid(&self, cid: ConnectionId) {
        self.router.remove(&Signpost::from(cid));
    }
}

impl<TX> SendFrame<NewConnectionIdFrame> for QuicRouterRegistry<TX>
where
    TX: SendFrame<NewConnectionIdFrame>,
{
    fn send_frame<I: IntoIterator<Item = NewConnectionIdFrame>>(&self, iter: I) {
        self.issued_cids.send_frame(iter);
    }
}

impl<RX> ReceiveFrame<RetireConnectionIdFrame> for QuicRouterRegistry<RX>
where
    RX: ReceiveFrame<RetireConnectionIdFrame, Output = ()>,
{
    type Output = ();

    fn recv_frame(&self, frame: RetireConnectionIdFrame) -> Result<Self::Output, Error> {
        self.issued_cids.recv_frame(frame)
    }
}

#[cfg(test)]
mod tests;
