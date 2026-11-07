//! Path validation and per-path congestion control. One sending owner per path.
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::Duration,
};

use qbase::{
    Epoch,
    handshake::HandshakeFacts,
    net::{route::Pathway, tx::ArcSendWakers, validate::ArcValidation},
    packet::assemble::Metadata,
    time::heartbeat::ArcHeartbeat,
};
use qcongestion::{Algorithm, ArcCC, CongestionController, MSS};
use qprotocol::QuicProtocol;
use tokio::time::Instant;

use crate::{ArcDcid, ArcProgress, ArcResend, space::ArcSpaces, terminate::ArcTerminator};

mod send;
pub use send::{Datagram, update_amplification_blocked};

pub struct Path {
    pub pathway: Pathway,
    pub dcid: ArcDcid,
    pub cc: ArcCC,
    pub send_waker: ArcSendWakers,
    pub validation: ArcValidation,
    pub heartbeat: ArcHeartbeat,
    /// Connection-wide packet sources shared by every path.
    pub spaces: ArcSpaces,
    /// Connection-wide termination and CLOSE source.
    pub terminator: ArcTerminator,
    /// Connection-wide handshake transitions shared by every path.
    pub progress: ArcProgress,
    /// Payload eligibility; ACKs and heartbeats remain available while inactive.
    is_active: AtomicBool,
}

impl Path {
    /// Construct a path using the connection's shared handshake lifecycle.
    /// New paths stay inactive between handshake path selection and confirmation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dcid: ArcDcid,
        pathway: Pathway,
        hs_facts: Arc<HandshakeFacts>,
        spaces: ArcSpaces,
        resenders: ArcResend,
        heartbeat: ArcHeartbeat,
        terminator: ArcTerminator,
        progress: ArcProgress,
    ) -> Self {
        let is_active = !hs_facts.has_selected_path() || hs_facts.is_handshake_done();
        let send_waker = ArcSendWakers::default();
        let validation = ArcValidation::new();
        let cc = ArcCC::new(
            Algorithm::NewReno,
            Duration::from_millis(25),
            resenders,
            hs_facts,
            Arc::new(AtomicU16::new(MSS as u16)),
            send_waker.clone(),
        );
        Self { pathway, dcid, cc, send_waker, validation, heartbeat, spaces, terminator, progress, is_active: AtomicBool::new(is_active) }
    }

    /// Allow payload collection and wake this path's sender.
    pub fn enable(&self) {
        if !self.is_active.swap(true, Ordering::AcqRel) {
            self.send_waker.wake_all();
        }
    }

    /// Keep ACKs and heartbeats running without collecting payload.
    pub fn disable(&self) {
        if self.is_active.swap(false, Ordering::AcqRel) {
            self.send_waker.wake_all();
        }
    }

    pub fn is_active(&self) -> bool {
        self.is_active.load(Ordering::Acquire)
    }

    /// Account one successfully submitted datagram under the submission's CC lock.
    pub fn on_sent(&self, cc: &mut CongestionController, bytes: usize, packets: [Option<Metadata>; 3]) {
        let overhead = QuicProtocol::packet_overhead(self.pathway);
        let charged =
            packets.iter().position(|p| p.as_ref().is_some_and(|meta| meta.in_flight)).or_else(|| packets.iter().position(Option::is_some));
        let now = Instant::now();
        self.validation.on_sent(bytes + overhead);
        for (epoch, packet) in Epoch::EPOCHS.into_iter().zip(packets) {
            let Some(meta) = packet else { continue };
            let sent_bytes = meta.pktlen
                + if charged == Some(epoch as usize) {
                    overhead
                } else {
                    0
                };
            cc.on_pkt_sent(epoch, meta.pn, meta.content.is_ack_eliciting(), sent_bytes, meta.in_flight, meta.ack);
            let _ = self.heartbeat.on_sent_at(meta.content, now);
        }
    }

    pub fn close(&self) {
        self.is_active.store(false, Ordering::Release);
        self.validation.cancel();
        self.dcid.retire();
        self.heartbeat.stop();
        self.send_waker.wake_all();
    }
}
