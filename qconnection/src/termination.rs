use std::{
    io, mem,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use qbase::{
    cid::ConnectionId,
    error::Error,
    frame::ConnectionCloseFrame,
    net::{route::Pathway, tx::Signals},
    packet::{
        header::{
            long::{HandshakeHeader, InitialHeader, io::LongHeaderBuilder},
            short::OneRttHeader,
        },
        io::ProductHeader,
    },
};
use qinterface::component::route::RcvdPacketQueue;
use tokio::time::Instant;

use crate::{Components, path::ArcPathContexts};

/// Keep a few states to support sending packets with ccf.
pub struct Terminator {
    last_recv_time: Mutex<Instant>,
    rcvd_packets: AtomicUsize,
    scid: Option<ConnectionId>,
    dcid: Option<ConnectionId>,
    ccf: ConnectionCloseFrame,
    paths: ArcPathContexts,
}

impl ProductHeader<InitialHeader> for Terminator {
    fn new_header(&self) -> Result<InitialHeader, Signals> {
        let (Some(dcid), Some(scid)) = (self.dcid, self.scid) else {
            return Err(Signals::empty());
        };
        // TODO: initial token
        Ok(LongHeaderBuilder::with_cid(dcid, scid).initial(vec![]))
    }
}

impl ProductHeader<HandshakeHeader> for Terminator {
    fn new_header(&self) -> Result<HandshakeHeader, Signals> {
        let (Some(dcid), Some(scid)) = (self.dcid, self.scid) else {
            return Err(Signals::empty());
        };
        Ok(LongHeaderBuilder::with_cid(dcid, scid).handshake())
    }
}

impl ProductHeader<OneRttHeader> for Terminator {
    fn new_header(&self) -> Result<OneRttHeader, Signals> {
        let Some(dcid) = self.dcid else {
            return Err(Signals::empty());
        };
        // TODO: spin bit
        Ok(OneRttHeader::new(false.into(), dcid))
    }
}

impl Terminator {
    pub fn new(ccf: ConnectionCloseFrame, components: &Components) -> Self {
        Self {
            last_recv_time: Mutex::new(Instant::now()),
            rcvd_packets: AtomicUsize::new(0),
            scid: components.cid_registry.local.initial_scid(),
            dcid: components.cid_registry.remote.latest_dcid(),
            ccf,
            paths: components.paths.clone(),
        }
    }

    pub fn should_send(&self) -> bool {
        let mut last_recv_time_guard = self.last_recv_time.lock().unwrap();
        self.rcvd_packets.fetch_add(1, Ordering::AcqRel);

        if self.rcvd_packets.load(Ordering::Acquire) >= 3
            || last_recv_time_guard.elapsed() > Duration::from_secs(1)
        {
            *last_recv_time_guard = tokio::time::Instant::now();
            self.rcvd_packets.store(0, Ordering::Release);
            true
        } else {
            false
        }
    }

    pub async fn try_send<W>(&self, mut write: W)
    where
        W: FnMut(&mut [u8], &ConnectionCloseFrame) -> Option<usize>,
    {
        for (_pathway, path) in self.paths.paths::<Vec<_>>() {
            let mut datagram = vec![0; path.mtu() as _];
            if let Some(written) = write(&mut datagram, &self.ccf)
                && written > 0
            {
                _ = path
                    .send_packets(&[io::IoSlice::new(&datagram[..written])])
                    .await;
            }
        }
    }

    pub async fn try_send_on<W>(&self, pathway: Pathway, write: W)
    where
        W: FnOnce(&mut [u8], &ConnectionCloseFrame) -> Option<usize>,
    {
        let Some(path) = self.paths.get(&pathway) else {
            return;
        };

        let mut datagram = vec![0; path.mtu() as _];
        match write(&mut datagram, &self.ccf) {
            Some(written) if written > 0 => {
                _ = path
                    .send_packets(&[io::IoSlice::new(&datagram[..written])])
                    .await;
            }
            _ => {}
        };
    }
}

#[derive(Clone)]
enum State {
    Closing {
        rcvd_pkt_q: Arc<RcvdPacketQueue>,
        paths: ArcPathContexts,
    },
    Draining,
}

#[derive(Clone)]
pub struct Termination {
    // for generate io::Error
    error: Error,
    state: State,
}

impl Termination {
    pub fn closing(error: Error, rcvd_pkt_q: Arc<RcvdPacketQueue>, paths: ArcPathContexts) -> Self {
        Self {
            error,
            state: State::Closing { rcvd_pkt_q, paths },
        }
    }

    pub fn draining(error: Error) -> Self {
        Self {
            error,
            state: State::Draining,
        }
    }

    pub fn error(&self) -> Error {
        self.error.clone()
    }

    // Close packets queues, dont send and receive any more packets.
    pub fn enter_draining(&mut self) -> bool {
        match mem::replace(&mut self.state, State::Draining) {
            State::Closing { rcvd_pkt_q, paths } => {
                rcvd_pkt_q.close_all();
                paths.close();
                true
            }
            State::Draining => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use qbase::{
        cid::{ConnectionId, GenUniqueCid},
        error::{Error, ErrorKind, QuicError},
        net::{
            route::{Link, Pathway},
            tx::ArcSendWakers,
        },
        packet::{LongHeaderBuilder, Packet},
    };
    use qinterface::{
        bind_uri::BindUri,
        component::route::{QuicRouter, RcvdPacketQueue},
    };
    use tokio::sync::mpsc;

    use super::*;
    use crate::{
        ArcLocalCids, ArcReliableFrameDeque, events::ArcEventBroker, path::ArcPathContexts,
        state::ArcConnState,
    };

    fn test_local_cids(router: Arc<QuicRouter>) -> (ArcLocalCids, ConnectionId) {
        let queue = Arc::new(RcvdPacketQueue::new());
        let tx_wakers = ArcSendWakers::default();
        let reliable = ArcReliableFrameDeque::with_capacity_and_wakers(8, tx_wakers);
        let registry = router.registry_on_issuing_scid(queue, reliable);
        let initial_scid = registry.gen_unique_cid();
        (ArcLocalCids::new(initial_scid, registry), initial_scid)
    }

    fn test_paths() -> ArcPathContexts {
        let tx_wakers = ArcSendWakers::default();
        let (tx, _rx) = mpsc::unbounded_channel();
        let broker = ArcEventBroker::new(ArcConnState::new(), tx);
        ArcPathContexts::new(tx_wakers, broker)
    }

    fn test_error() -> Error {
        QuicError::with_default_fty(ErrorKind::NoViablePath, "closed").into()
    }

    fn test_way() -> (BindUri, Pathway, Link) {
        let src = SocketAddr::from(([127, 0, 0, 1], 9000));
        let dst = SocketAddr::from(([127, 0, 0, 1], 4433));
        let link = Link::new(src, dst);
        (BindUri::from(dst), Pathway::from(link), link)
    }

    fn test_routed_packet(dcid: ConnectionId) -> Packet {
        Packet::VN(LongHeaderBuilder::with_cid(dcid, ConnectionId::from_slice(b"scid")).vn(vec![1]))
    }

    async fn route_exists(router: &Arc<QuicRouter>, dcid: ConnectionId) -> bool {
        router
            .try_deliver((test_routed_packet(dcid), None), test_way())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn enter_draining_closes_closing_packet_queues() {
        let rcvd_pkt_q = Arc::new(RcvdPacketQueue::new());
        let packets = rcvd_pkt_q.one_rtt().clone();
        let paths = test_paths();
        let mut termination = Termination::closing(test_error(), rcvd_pkt_q, paths);

        assert!(termination.enter_draining());

        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), packets.recv())
                .await
                .expect("closed queue should wake")
                .is_none()
        );
    }

    #[test]
    fn enter_draining_is_idempotent() {
        let rcvd_pkt_q = Arc::new(RcvdPacketQueue::new());
        let paths = test_paths();
        let mut termination = Termination::closing(test_error(), rcvd_pkt_q, paths);

        assert!(termination.enter_draining());
        assert!(!termination.enter_draining());
    }

    #[tokio::test]
    async fn deferred_local_cids_and_odcid_route_clear_at_same_boundary() {
        let router = Arc::new(QuicRouter::default());
        let (local_cids, initial_scid) = test_local_cids(router.clone());
        let rcvd_pkt_q = Arc::new(RcvdPacketQueue::new());
        let odcid = ConnectionId::from_slice(b"odcid");
        let odcid_router_entry = Arc::new(router.insert(odcid.into(), rcvd_pkt_q.clone()));

        let deferred_local_cids = local_cids.clone();
        let deferred_odcid_router_entry = Some(odcid_router_entry.clone());
        drop(odcid_router_entry);

        assert!(route_exists(&router, initial_scid).await);
        assert!(route_exists(&router, odcid).await);

        deferred_local_cids.clear();
        drop(deferred_odcid_router_entry);

        assert!(!route_exists(&router, initial_scid).await);
        assert!(!route_exists(&router, odcid).await);
    }
}
