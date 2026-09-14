use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, Weak},
};

use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    net::route::{Link, Pathway},
    packet::{DataHeader, GetDcid, Packet, PacketReader, long},
};
use tokio::{sync::mpsc, time::Instant};

use crate::handshake::incoming::Incoming;

pub(crate) const CID_LEN: usize = 8;
const PACKET_QUEUE_CAPACITY: usize = 32;

// The final field credits the UDP datagram once per receiving connection.
pub(crate) type ReceivedPacket = (Packet, Pathway, Link, usize);

pub(crate) struct RouteEntry {
    packets: mpsc::Sender<ReceivedPacket>,
}

pub(crate) struct Router {
    entries: Mutex<HashMap<ConnectionId, Arc<RouteEntry>>>,
    incoming: mpsc::Sender<Incoming>,
}

/// Owns removal of all aliases for one stable packet inbox.
pub(crate) struct RouteLease {
    router: Weak<Router>,
    pub(crate) entry: Arc<RouteEntry>,
    cids: Vec<ConnectionId>,
}

impl Router {
    pub(crate) fn new(incoming: mpsc::Sender<Incoming>) -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(HashMap::new()),
            incoming,
        })
    }

    pub(crate) fn receive(self: &Arc<Self>, bytes: BytesMut, pathway: Pathway, link: Link) {
        let datagram_len = bytes.len();
        let mut credited = HashSet::new();
        for result in PacketReader::new(bytes, CID_LEN) {
            let Ok(packet) = result else { break };
            let cid = *match &packet {
                Packet::Data(p) => p.dcid(),
                Packet::Retry(p) => p.dcid(),
                Packet::VN(p) => p.dcid(),
            };
            let mut entries = self.entries.lock().unwrap();
            if let Some(entry) = entries.get(&cid) {
                let identity = Arc::as_ptr(entry);
                let size = if credited.contains(&identity) {
                    0
                } else {
                    datagram_len
                };
                if entry
                    .packets
                    .try_send((packet, pathway, link, size))
                    .is_ok()
                {
                    credited.insert(identity);
                }
                continue;
            }
            if datagram_len < 1200
                || cid.len() < CID_LEN
                || !matches!(
                    &packet, Packet::Data(p) if matches!(p.header, DataHeader::Long(long::DataHeader::Initial(_)))
                )
            {
                continue;
            }
            // Reserve only the channel position, under the same short lock as CID
            // insertion. There is no connection permit or task for queued work.
            let Ok(slot) = self.incoming.try_reserve() else {
                continue;
            };
            let (packets, receiver) = mpsc::channel(PACKET_QUEUE_CAPACITY);
            let entry = Arc::new(RouteEntry { packets });
            let _ = entry
                .packets
                .try_send((packet, pathway, link, datagram_len));
            credited.insert(Arc::as_ptr(&entry));
            entries.insert(cid, entry.clone());
            drop(entries); // Closing the receiver may drop Incoming inside send.
            slot.send(Incoming {
                route: RouteLease {
                    router: Arc::downgrade(self),
                    entry,
                    cids: vec![cid],
                },
                packets: receiver,
                received_at: Instant::now(),
            });
        }
    }

    pub(crate) fn register(
        self: &Arc<Self>,
        cid: ConnectionId,
    ) -> Option<(RouteLease, mpsc::Receiver<ReceivedPacket>)> {
        let mut entries = self.entries.lock().unwrap();
        if entries.contains_key(&cid) {
            return None;
        }
        let (packets, receiver) = mpsc::channel(PACKET_QUEUE_CAPACITY);
        let entry = Arc::new(RouteEntry { packets });
        entries.insert(cid, entry.clone());
        Some((
            RouteLease {
                router: Arc::downgrade(self),
                entry,
                cids: vec![cid],
            },
            receiver,
        ))
    }
}

impl RouteLease {
    pub(crate) fn initial_cid(&self) -> ConnectionId {
        self.cids[0]
    }

    pub(crate) fn insert(&mut self, cid: ConnectionId) -> bool {
        let Some(router) = self.router.upgrade() else {
            return false;
        };
        let mut entries = router.entries.lock().unwrap();
        if let Some(existing) = entries.get(&cid) {
            return Arc::ptr_eq(existing, &self.entry);
        }
        entries.insert(cid, self.entry.clone());
        self.cids.push(cid);
        true
    }
}

impl Drop for RouteLease {
    fn drop(&mut self) {
        if let Some(router) = self.router.upgrade() {
            let mut entries = router.entries.lock().unwrap();
            for cid in &self.cids {
                if entries
                    .get(cid)
                    .is_some_and(|e| Arc::ptr_eq(e, &self.entry))
                {
                    entries.remove(cid);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BufMut;
    use qbase::{
        packet::{LongHeaderBuilder, header::io::WriteHeader},
        varint::{VarInt, WriteVarInt},
    };

    use super::*;

    fn initial(cid: ConnectionId, size: usize) -> BytesMut {
        let header =
            LongHeaderBuilder::with_cid(cid, ConnectionId::from_slice(b"clientid")).initial(vec![]);
        let mut bytes = BytesMut::new();
        bytes.put_header(&header);
        bytes.put_varint(&VarInt::from_u32((size - bytes.len() - 2) as u32));
        bytes.resize(size, 0);
        bytes
    }

    fn deliver(router: &Arc<Router>, bytes: BytesMut) {
        let link = Link::new(
            "127.0.0.1:4433".parse().unwrap(),
            "127.0.0.1:9000".parse().unwrap(),
        );
        router.receive(bytes, link.into(), link);
    }

    #[tokio::test]
    async fn full_queue_drops_new_connections_but_routes_existing_ones() {
        let (tx, mut rx) = mpsc::channel(1);
        let router = Router::new(tx);
        let a = ConnectionId::from_slice(b"aaaaaaaa");
        let b = ConnectionId::from_slice(b"bbbbbbbb");
        deliver(&router, initial(a, 1200));
        deliver(&router, initial(b, 1200));
        deliver(&router, initial(a, 1200));
        assert_eq!(router.entries.lock().unwrap().len(), 1);
        let mut incoming = rx.try_recv().unwrap();
        assert!(incoming.packets.try_recv().is_ok());
        assert!(incoming.packets.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
        drop(incoming);
        assert!(router.entries.lock().unwrap().is_empty());
        deliver(&router, initial(b, 1200));
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn concurrent_initials_share_one_entry_and_aliases_keep_the_same_inbox() {
        let (tx, mut rx) = mpsc::channel(4);
        let router = Router::new(tx);
        let cid = ConnectionId::from_slice(b"same-cid");
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| deliver(&router, initial(cid, 1200)));
            }
        });
        let mut incoming = rx.try_recv().unwrap();
        assert!(rx.try_recv().is_err());
        let alias = ConnectionId::from_slice(b"newalias");
        assert!(incoming.route.insert(alias));
        deliver(&router, initial(alias, 1200));
        for _ in 0..9 {
            assert!(incoming.packets.try_recv().is_ok());
        }
        drop(incoming);
        assert!(router.entries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn coalesced_packets_credit_one_datagram_and_inbox_is_bounded() {
        let (tx, _rx) = mpsc::channel(1);
        let router = Router::new(tx);
        let cid = ConnectionId::from_slice(b"existing");
        let (_route, mut packets) = router.register(cid).unwrap();
        let mut bytes = initial(cid, 600);
        bytes.put_slice(&initial(cid, 600));
        deliver(&router, bytes);
        assert_eq!(packets.try_recv().unwrap().3, 1200);
        assert_eq!(packets.try_recv().unwrap().3, 0);
        for _ in 0..PACKET_QUEUE_CAPACITY + 10 {
            deliver(&router, initial(cid, 1200));
        }
        assert_eq!(packets.len(), PACKET_QUEUE_CAPACITY);
    }

    #[tokio::test]
    async fn closed_queue_and_short_unknown_packets_leave_no_routes() {
        let (tx, mut rx) = mpsc::channel(1);
        let router = Router::new(tx);
        let cid = ConnectionId::from_slice(b"unknown!");
        deliver(&router, initial(cid, 600));
        assert!(router.entries.lock().unwrap().is_empty());
        rx.close();
        deliver(&router, initial(cid, 1200));
        assert!(router.entries.lock().unwrap().is_empty());
    }
}
