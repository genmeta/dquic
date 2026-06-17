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

use crate::{ArcLocalCids, Components, path::ArcPathContexts};

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
    // keep this to keep the routing
    _local_cids: ArcLocalCids,
    state: State,
}

impl Termination {
    pub fn closing(
        error: Error,
        local_cids: ArcLocalCids,
        rcvd_pkt_q: Arc<RcvdPacketQueue>,
        paths: ArcPathContexts,
    ) -> Self {
        Self {
            error,
            _local_cids: local_cids,
            state: State::Closing { rcvd_pkt_q, paths },
        }
    }

    pub fn draining(error: Error, local_cids: ArcLocalCids) -> Self {
        Self {
            error,
            _local_cids: local_cids,
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
                paths.clear();
                true
            }
            State::Draining => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use qbase::{
        cid::GenUniqueCid,
        error::{Error, ErrorKind, QuicError},
        net::tx::ArcSendWakers,
    };
    use qinterface::component::route::{QuicRouter, RcvdPacketQueue};
    use tokio::sync::mpsc;

    use super::*;
    use crate::{
        events::ArcEventBroker, path::ArcPathContexts, state::ArcConnState, ArcLocalCids,
        ArcReliableFrameDeque,
    };

    fn test_local_cids() -> ArcLocalCids {
        let queue = Arc::new(RcvdPacketQueue::new());
        let tx_wakers = ArcSendWakers::default();
        let reliable = ArcReliableFrameDeque::with_capacity_and_wakers(8, tx_wakers);
        let registry = Arc::new(QuicRouter::default()).registry_on_issuing_scid(queue, reliable);
        let initial_scid = registry.gen_unique_cid();
        ArcLocalCids::new(initial_scid, registry)
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

    #[tokio::test]
    async fn enter_draining_closes_closing_packet_queues() {
        let rcvd_pkt_q = Arc::new(RcvdPacketQueue::new());
        let packets = rcvd_pkt_q.one_rtt().clone();
        let paths = test_paths();
        let mut termination =
            Termination::closing(test_error(), test_local_cids(), rcvd_pkt_q, paths);

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
        let mut termination =
            Termination::closing(test_error(), test_local_cids(), rcvd_pkt_q, paths);

        assert!(termination.enter_draining());
        assert!(!termination.enter_draining());
    }
}
