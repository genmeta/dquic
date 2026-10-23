//! Path validation and per-path congestion control. One sending owner per path.
use std::{
    sync::{Arc, atomic::AtomicU16},
    time::Duration,
};

use qbase::{
    Epoch,
    net::{route::Pathway, tx::ArcSendWakers},
    packet::assemble::Metadata,
    time::{heartbeat::ArcHeartbeat, timer::ArcIdleTimer},
    util::ArcIndexDeque,
    validate::ArcValidation,
};
use qcongestion::{Algorithm, ArcCC, CongestionController, HandshakeStatus, MSS, Resend};
use qprotocol::QuicProtocol;
use tokio::time::Instant;

mod cids;
pub use cids::{PathCid, PathCids};

pub struct Path {
    pub pathway: Pathway,
    pub cid: Arc<PathCid>,
    pub cc: ArcCC,
    pub send_waker: ArcSendWakers,
    pub validation: ArcValidation,
    pub heartbeat: ArcHeartbeat,
}

impl Path {
    /// Construct a path using the connection's shared handshake lifecycle.
    pub fn new(
        pathway: Pathway,
        handshake: Arc<HandshakeStatus>,
        heartbeat: ArcHeartbeat,
        trackers: ArcIndexDeque<Arc<dyn Resend>, 2>,
        cids: &Arc<PathCids>,
    ) -> Self {
        let send_waker = ArcSendWakers::default();
        let validation = ArcValidation::new();
        let cc = ArcCC::new(
            Algorithm::NewReno,
            Duration::from_millis(25),
            trackers,
            handshake,
            Arc::new(AtomicU16::new(MSS as u16)),
            send_waker.clone(),
        );
        Self {
            pathway,
            cid: cids.register(pathway, send_waker.clone()),
            cc,
            send_waker,
            validation,
            heartbeat,
        }
    }

    /// Account one successfully submitted datagram under the submission's CC lock.
    pub fn on_sent(
        &self,
        cc: &mut CongestionController,
        bytes: usize,
        packets: [Option<Metadata>; 3],
        idle: &ArcIdleTimer,
    ) {
        let overhead = QuicProtocol::packet_overhead(self.pathway);
        let charged = packets
            .iter()
            .position(|p| p.as_ref().is_some_and(|meta| meta.in_flight))
            .or_else(|| packets.iter().position(Option::is_some));
        let now = Instant::now();
        self.validation.on_sent(bytes + overhead);
        let _ = idle.on_sent_at(now);
        for (epoch, packet) in Epoch::EPOCHS.into_iter().zip(packets) {
            let Some(meta) = packet else { continue };
            let sent_bytes = meta.pktlen
                + if charged == Some(epoch as usize) {
                    overhead
                } else {
                    0
                };
            cc.on_pkt_sent(
                epoch,
                meta.pn,
                meta.content.is_ack_eliciting(),
                sent_bytes,
                meta.in_flight,
                meta.ack,
            );
            let _ = self.heartbeat.on_sent_at(meta.content, now);
        }
    }

    pub fn close(&self) {
        self.validation.cancel();
        self.cid.retire();
        self.heartbeat.stop();
        self.send_waker.wake_all();
    }
}
