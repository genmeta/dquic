use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
};

use qbase::{
    Epoch,
    error::Error,
    frame::{PathChallengeFrame, PathResponseFrame, io::ReceiveFrame},
    net::{
        route::{Line, Link, Pathway, Route},
        tx::{ArcSendWaker, Signals},
    },
    packet::PacketContent,
    param::ParameterId,
    time::PathIdleTimer,
};
use qcongestion::{Algorithm, ArcCC, Feedback, HandshakeStatus, MSS, PathStatus, Transport};
use qevent::{quic::connectivity::PathAssigned, telemetry::Instrument};
use qinterface::{
    Interface,
    bind_uri::BindUri,
    component::route::Way,
    io::{IO, IoExt},
};
use tokio::time::Duration;

mod aa;
mod burst;
mod drive;
pub mod error;
pub mod paths;
pub mod util;
mod validate;
pub use aa::*;
pub use burst::PacketSpace;
pub use error::*;
pub use paths::*;
use tracing::Instrument as _;
pub use util::*;

use crate::{ArcDcidCell, Components, path::burst::BurstError};
// pub mod burst;

pub struct Path {
    interface: Interface,
    validated: AtomicBool,
    active: AtomicBool,
    link: Link,
    pathway: Pathway,
    cc: ArcCC,
    dcid_cell: ArcDcidCell,
    anti_amplifier: AntiAmplifier,
    idle_timer: PathIdleTimer,
    challenge_sndbuf: SendBuffer<PathChallengeFrame>,
    response_sndbuf: SendBuffer<PathResponseFrame>,
    response_rcvbuf: RecvBuffer<PathResponseFrame>,
    tx_waker: ArcSendWaker,
    pmtu: Arc<AtomicU16>,
    status: PathStatus,
}

impl Components {
    pub fn get_or_try_create_path(
        &self,
        way: Way,
        is_probed: bool,
    ) -> Result<Arc<Path>, CreatePathFailure> {
        let validate = if is_probed {
            qinterface::component::route::validate_received_way
        } else {
            qinterface::component::route::validate_outbound_candidate
        };
        validate(&way).map_err(CreatePathFailure::InvalidWay)?;
        let (bind_uri, pathway, link) = way;
        let try_create = || {
            let interface = self
                .interfaces
                .borrow(&bind_uri)
                .ok_or(CreatePathFailure::NoInterface(bind_uri))?;
            let dcid_cell = self.cid_registry.remote.apply_dcid();
            let max_ack_delay = self
                .parameters
                .lock_guard()?
                .get_local(ParameterId::MaxAckDelay)
                .expect("unreachable: default value will be got if the value unset");

            let is_initial_path = self.conn_state.try_entry_attempted(self, link)?;
            qevent::event!(PathAssigned {
                path_id: pathway.to_string(),
                path_local: link.src,
                path_remote: link.dst,
            });

            let path = Arc::new(Path::new(
                interface,
                link,
                pathway,
                dcid_cell,
                max_ack_delay,
                self.conn_idle.timer(),
                [
                    Arc::new(
                        self.spaces
                            .initial()
                            .tracker(self.crypto_streams[Epoch::Initial].clone()),
                    ),
                    Arc::new(
                        self.spaces
                            .handshake()
                            .tracker(self.crypto_streams[Epoch::Handshake].clone()),
                    ),
                    Arc::new(self.spaces.data().tracker(
                        self.crypto_streams[Epoch::Data].clone(),
                        self.data_streams.clone(),
                        self.reliable_frames.clone(),
                    )),
                ],
                self.quic_handshake.status(),
            ));

            let validate = {
                let path = path.clone();
                let paths = self.paths.clone();
                let tls_handshake = self.tls_handshake.clone();
                let conn_state = self.conn_state.clone();
                async move {
                    if !is_probed {
                        path.grant_anti_amplification();
                    }
                    if tls_handshake.info().await.is_err() {
                        return Ok(());
                    }

                    match paths.handshake_path() {
                        Some(handshake_path) if Arc::ptr_eq(&handshake_path, &path) => {
                            path.validated();
                            Ok(())
                        }
                        _ => {
                            if conn_state.handshaked().await.is_err() {
                                return Ok(());
                            }
                            path.validate().await
                        }
                    }
                }
            };

            let drive = {
                let path = path.clone();
                let tls_handshake = self.tls_handshake.clone();
                async move { path.drive(tls_handshake).await }
            };

            let burst = {
                let path = path.clone();
                let mut packages = self.packages();
                let burst = path.new_burst(self);
                async move {
                    let mut buffers = vec![];
                    loop {
                        match burst.burst(&mut packages, &mut buffers) {
                            Ok((segments, packet_content)) => {
                                if !path.is_active() {
                                    return Ok(());
                                }
                                path.send_packets(&segments).await?;
                                path.idle_timer.on_sent(packet_content);
                            }
                            Err(BurstError::Signals(s)) => path.tx_waker.wait_for(s).await,
                            Err(BurstError::PathDeactived) => return io::Result::Ok(()),
                        }
                    }
                }
            };

            let lifecycle_path = path.clone();
            let task = async move {
                let reason = tokio::select! {
                    Err(error) = validate.instrument_in_current().in_current_span() => PathDeactivated::from(error),
                    Err(reason) = drive.instrument_in_current().in_current_span() => reason,
                    Err(error) = burst.instrument_in_current().in_current_span() => PathDeactivated::from(error),
                };
                lifecycle_path.deactivate();
                Err(reason)
            };

            let task =
                Instrument::instrument(task, qevent::span!(@current, path=pathway.to_string()))
                    .in_current_span();

            tracing::trace!(target: "dquic", %pathway, %link, is_probed, is_initial_path, "add new path");

            Ok((path, task))
        };
        self.paths.get_or_try_create_with(pathway, try_create)
    }
}

impl Path {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        interface: Interface,
        link: Link,
        pathway: Pathway,
        dcid_cell: ArcDcidCell,
        max_ack_delay: Duration,
        idle_timer: PathIdleTimer,
        feedbacks: [Arc<dyn Feedback>; 3],
        handshake_status: Arc<HandshakeStatus>,
    ) -> Self {
        let pmtu = Arc::new(AtomicU16::new(MSS as u16));
        let path_status = PathStatus::new(handshake_status, pmtu.clone());
        let tx_waker = ArcSendWaker::new();

        let cc = ArcCC::new(
            Algorithm::NewReno,
            max_ack_delay,
            feedbacks,
            path_status.clone(),
            tx_waker.clone(),
        );
        Self {
            interface,
            link,
            pathway,
            cc,
            dcid_cell,
            validated: AtomicBool::new(false),
            active: AtomicBool::new(true),
            anti_amplifier: AntiAmplifier::new(tx_waker.clone()),
            idle_timer,
            challenge_sndbuf: SendBuffer::new(tx_waker.clone()),
            response_sndbuf: SendBuffer::new(tx_waker.clone()),
            response_rcvbuf: Default::default(),
            tx_waker,
            pmtu,
            status: path_status,
        }
    }

    pub fn cc(&self) -> &ArcCC {
        &self.cc
    }

    pub fn on_packet_rcvd(
        &self,
        epoch: Epoch,
        pn: u64,
        datagram_size: Option<usize>,
        packet_content: PacketContent,
    ) {
        if let Some(datagram_size) = datagram_size {
            self.anti_amplifier.on_rcvd(datagram_size);
            self.status.release_anti_amplification_limit();
        }
        self.idle_timer.on_rcvd(packet_content);
        self.cc()
            .on_pkt_rcvd(epoch, pn, packet_content.is_ack_eliciting());
    }

    pub fn grant_anti_amplification(&self) {
        self.anti_amplifier.grant();
        self.cc().grant_anti_amplification();
    }

    fn keep_alive_due(&self, one_rtt_ready: bool, now: tokio::time::Instant) -> bool {
        one_rtt_ready
            && self.validated.load(Ordering::Acquire)
            // Periodic PINGs both maintain the NAT binding and sample path reachability.
            // Recovery manages existing in-flight packets with a backing-off PTO, so an
            // ack-eliciting packet in flight must not suppress the fixed KeepAlive cadence.
            && self.idle_timer.keep_alive_due(now)
    }

    fn wake_keep_alive_if_due(&self, one_rtt_ready: bool) {
        if self.keep_alive_due(one_rtt_ready, tokio::time::Instant::now()) {
            self.tx_waker.wake_by(Signals::TRANSPORT);
        }
    }

    pub fn mtu(&self) -> u16 {
        self.pmtu.load(Ordering::Acquire)
    }

    pub async fn send_packets(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<()> {
        self.anti_amplifier
            .on_sent(bufs.iter().map(|s| s.len()).sum());
        if self.anti_amplifier.balance().is_err() {
            self.status.enter_anti_amplification_limit();
        }
        let line = Line::new(self.link, 64, None, self.mtu());
        let route = Route::new(self.pathway, line);
        self.interface.sendmmsg(bufs, route).await
    }

    pub fn deactivate(&self) {
        if !self.active.swap(false, Ordering::AcqRel) {
            return;
        }
        self.anti_amplifier.abort();
        self.response_rcvbuf.dismiss();
        self.tx_waker.wake_by(Signals::all());
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub fn link(&self) -> &Link {
        &self.link
    }

    pub fn pathway(&self) -> &Pathway {
        &self.pathway
    }

    pub fn bind_uri(&self) -> BindUri {
        self.interface.bind_uri()
    }
}

impl Drop for Path {
    fn drop(&mut self) {
        self.response_rcvbuf.dismiss();
    }
}

impl ReceiveFrame<PathChallengeFrame> for Path {
    type Output = ();

    fn recv_frame(&self, frame: PathChallengeFrame) -> Result<Self::Output, Error> {
        self.response_sndbuf.write(frame.into());
        Ok(())
    }
}

impl ReceiveFrame<PathResponseFrame> for Path {
    type Output = ();

    fn recv_frame(&self, frame: PathResponseFrame) -> Result<Self::Output, Error> {
        self.response_rcvbuf.write(frame);
        Ok(())
    }
}
