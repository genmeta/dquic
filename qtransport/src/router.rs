//! CID routing only. qconn consumes the bounded Initial queue and owns route removal.
use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Mutex,
};

use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    net::route::{Link, Pathway},
    packet::{DataHeader, GetDcid, Packet, PacketReader, long},
};
use tokio::{sync::mpsc, time::Instant};

/// The last field credits one UDP datagram, once per connection; subsequent packets carry zero.
pub type ReceivedPacket = (Packet, Pathway, Link, usize);
pub const PACKET_QUEUE_CAPACITY: usize = 32;

pub struct QuicRouter {
    routes: Mutex<HashMap<ConnectionId, mpsc::Sender<ReceivedPacket>>>,
    incoming: mpsc::Sender<(ConnectionId, mpsc::Receiver<ReceivedPacket>, Instant)>,
}

impl QuicRouter {
    pub fn new(
        incoming: mpsc::Sender<(ConnectionId, mpsc::Receiver<ReceivedPacket>, Instant)>,
    ) -> Self {
        Self {
            routes: Mutex::new(HashMap::new()),
            incoming,
        }
    }

    /// Every local CID of one connection points to the same bounded inbox.
    pub fn insert(&self, cid: ConnectionId, packets: mpsc::Sender<ReceivedPacket>) -> bool {
        match self.routes.lock().unwrap().entry(cid) {
            Entry::Vacant(entry) => {
                entry.insert(packets);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    pub fn get(&self, cid: &ConnectionId) -> Option<mpsc::Sender<ReceivedPacket>> {
        self.routes.lock().unwrap().get(cid).cloned()
    }

    pub fn remove(&self, cid: &ConnectionId) {
        self.routes.lock().unwrap().remove(cid);
    }

    /// Called by the connection owner after Closing/Draining finishes.
    pub fn remove_connection(&self, packets: &mpsc::Sender<ReceivedPacket>) {
        self.routes
            .lock()
            .unwrap()
            .retain(|_, sender| !sender.same_channel(packets));
    }

    /// Wire directly to qprotocol::QuicProtocol::on_receive. Never waits for a consumer.
    pub fn receive(&self, bytes: BytesMut, pathway: Pathway, link: Link, cid_len: usize) {
        let size = bytes.len();
        let mut credited: Vec<mpsc::Sender<ReceivedPacket>> = Vec::new();
        for packet in PacketReader::new(bytes, cid_len) {
            let Ok(packet) = packet else { break };
            let cid = *match &packet {
                Packet::Data(packet) => packet.dcid(),
                Packet::Retry(packet) => packet.dcid(),
                Packet::VN(packet) => packet.dcid(),
            };
            let mut routes = self.routes.lock().unwrap();
            if let Some(sender) = routes.get(&cid) {
                let counted = credited
                    .iter()
                    .any(|previous| previous.same_channel(sender));
                if sender
                    .try_send((packet, pathway, link, if counted { 0 } else { size }))
                    .is_ok()
                    && !counted
                {
                    credited.push(sender.clone());
                }
                continue;
            }
            // Only a sufficiently large Initial can start a new server-side connection.
            if size < 1200
                || cid.len() < 8
                || !matches!(
                    &packet, Packet::Data(packet) if matches!(packet.header, DataHeader::Long(long::DataHeader::Initial(_)))
                )
            {
                continue;
            }
            let Ok(slot) = self.incoming.try_reserve() else {
                continue;
            };
            let (sender, receiver) = mpsc::channel(PACKET_QUEUE_CAPACITY);
            // A fresh bounded queue has room for its first packet.
            let _ = sender.try_send((packet, pathway, link, size));
            credited.push(sender.clone());
            routes.insert(cid, sender);
            slot.send((cid, receiver, Instant::now()));
        }
    }
}
