pub use qtransport::packet::assemble as packet;
pub(crate) mod task;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
pub use packet::{Envelope, Packet};
use qbase::{
    Epoch,
    cid::{ArcCidCell, BorrowedCid, ConnectionId},
    error::{ErrorKind, QuicError},
    frame::{GuaranteedFrame, PingFrame},
    packet::Package,
    param::ParameterId,
    role::Role,
};
use qcongestion::{ArcCC, Transport as _};
use qprotocol::QuicProtocol;
use qtransport::{
    path::{AntiAmplifier, Path},
    space::{Spaces, assemble::Constraints},
};
pub(crate) use task::sending;

use crate::{ArcReliableFrames, ConnPhase, Error, Paths};

pub const MAX_BURST_PACKETS: usize = 8;
/// One slot per epoch in each UDP datagram. Packet properties live in the journals.
pub type BurstPns = [[Option<u64>; 3]; MAX_BURST_PACKETS];

pub struct Burst<'a> {
    cc: &'a ArcCC,
    anti_amplifier: &'a AntiAmplifier,
    pub(crate) datagrams: &'a mut [BytesMut],
    pub(crate) frames: &'a mut Vec<GuaranteedFrame>,
    pub(crate) pns: &'a mut BurstPns,
}

pub fn burst<'a>(
    cc: &'a ArcCC,
    anti_amplifier: &'a AntiAmplifier,
    datagrams: &'a mut [BytesMut],
    frames: &'a mut Vec<GuaranteedFrame>,
    pns: &'a mut BurstPns,
) -> Burst<'a> {
    Burst {
        cc,
        anti_amplifier,
        datagrams,
        frames,
        pns,
    }
}

pub struct Collector<'a, 'path> {
    pub(crate) burst: Burst<'a>,
    paths: &'path Arc<Paths>,
    path: &'path Arc<Path>,
    dcid_cell: &'path OnceLock<ArcCidCell<ArcReliableFrames>>,
    pub(crate) dcid: Option<BorrowedCid<'path, ArcReliableFrames>>,
    pub(crate) spaces: Option<Spaces>,
}

impl<'a> Burst<'a> {
    pub fn collect<'path>(
        self,
        paths: &'path Arc<Paths>,
        path: &'path Arc<Path>,
        dcid_cell: &'path OnceLock<ArcCidCell<ArcReliableFrames>>,
    ) -> Collector<'a, 'path> {
        Collector {
            burst: self,
            paths,
            path,
            dcid_cell,
            dcid: None,
            spaces: None,
        }
    }
}

impl Future for Collector<'_, '_> {
    type Output = Result<usize, Error>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let phase = this.paths.phase().poll_phase(cx).clone();
        let mut limits = Constraints {
            send_quota: ready!(this.burst.cc.poll_send_quota(cx)).map_err(|error| {
                QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string())
            })?,
            credit: ready!(this.burst.anti_amplifier.poll_credit(cx))?,
            probe_quota: Epoch::EPOCHS.map(|epoch| {
                if this.burst.cc.need_send_ack_eliciting(epoch) > 0 {
                    1200
                } else {
                    0
                }
            }),
            flow_ctrl: 0,
        };
        if this.path.selected() == Path::SUSPEND {
            return Poll::Pending;
        }
        this.spaces = Some(phase.spaces().read().unwrap().snapshot());
        let spaces = this.spaces.as_ref().unwrap();
        let mut flow = None;
        let data_cid = if let ConnPhase::Mature(phase) = &phase {
            if this.path.selected() != Path::MP_INITIAL
                && spaces.0.get(Epoch::Data as u64).is_some()
            {
                if this.dcid.is_none() {
                    this.path.send_waker.register(cx.waker());
                    let cell = this
                        .dcid_cell
                        .get_or_init(|| phase.cid_registry.remote.apply_dcid());
                    match cell.borrow_cid(this.path.send_waker.clone()) {
                        Poll::Ready(Some(dcid)) => this.dcid = Some(dcid),
                        Poll::Ready(None) => {
                            return Poll::Ready(Err(QuicError::with_default_fty(
                                ErrorKind::NoViablePath,
                                "path CID retired",
                            )
                            .into()));
                        }
                        Poll::Pending => {}
                    }
                }
                let requested = if limits.send_quota >= 1200 {
                    spaces
                        .0
                        .get(Epoch::Data as u64)
                        .unwrap()
                        .fresh_bytes_up_to(limits.send_quota)
                } else {
                    0
                };
                flow = ready!(phase.flow_ctrl.sender.poll_credit(cx, requested)).ok();
                limits.flow_ctrl = flow.as_ref().map_or(0, |credit| credit.available());
                this.dcid.as_ref().map(|cid| **cid)
            } else {
                None
            }
        } else {
            None
        };
        let mut count = 0;
        let mut acked = [None; 3];
        let overhead = QuicProtocol::packet_overhead(this.path.pathway);
        let multipath = this.path.selected() == Path::MP_INITIAL
            && this.paths.role() == Role::Client
            && matches!(phase, ConnPhase::Initial(_));
        let result = (|| {
            for (buffer, pns) in this
                .burst
                .datagrams
                .iter_mut()
                .zip(this.burst.pns.iter_mut())
            {
                if limits.credit <= overhead {
                    break;
                }
                let before = limits.clone();
                limits.credit -= overhead;
                limits.send_quota = limits.send_quota.saturating_sub(overhead);
                limits
                    .probe_quota
                    .iter_mut()
                    .for_each(|quota| *quota = quota.saturating_sub(overhead));
                buffer.resize(1200, 0);
                let (size, _) = phase.package(
                    cx,
                    spaces,
                    this.path,
                    data_cid,
                    multipath,
                    &mut limits,
                    buffer,
                    this.burst.frames,
                    pns,
                    &acked,
                )?;
                buffer.truncate(size);
                if size == 0 {
                    limits = before;
                    break;
                }
                let mut flight = false;
                for epoch in Epoch::EPOCHS {
                    if let Some(pn) = pns[epoch] {
                        let journal = spaces
                            .0
                            .get(epoch as u64)
                            .unwrap()
                            .sent_journal()
                            .lock_guard();
                        let packet = journal.packet(pn).expect("sealed packet");
                        flight |= packet.in_flight;
                        acked[epoch] = acked[epoch].max(packet.ack);
                        // PTO permits the first packet in this epoch, not more PINGs
                        // just because its packet was smaller than the allowance.
                        limits.probe_quota[epoch] = 0;
                    }
                }
                if !flight {
                    limits.send_quota = before.send_quota;
                }
                count += 1;
            }
            Ok(count)
        })();
        if let Some(flow) = &mut flow {
            flow.post_sent(flow.available() - limits.flow_ctrl);
        }
        match result {
            Err(error) => Poll::Ready(Err(error)),
            Ok(0) => {
                this.dcid.take();
                Poll::Pending
            }
            Ok(count) => Poll::Ready(Ok(count)),
        }
    }
}

impl ConnPhase {
    /// Prepare path-local sources; the ordered spaces own all packet assembly and sealing.
    fn package(
        &self,
        cx: &mut Context<'_>,
        spaces: &Spaces,
        path: &Path,
        data_cid: Option<ConnectionId>,
        multipath: bool,
        limits: &mut Constraints,
        buffer: &mut [u8],
        frames: &mut Vec<GuaranteedFrame>,
        pns: &mut [Option<u64>; 3],
        acked: &[Option<u64>; 3],
    ) -> Result<(usize, usize), Error> {
        let (dcid, terminator, exponent) = match self {
            Self::Initial(p) => (p.dcid(), &p.terminator, 0),
            Self::Handshake(p) => (p.dcid, &p.terminator, 0),
            Self::Mature(p) => (
                p.dcid,
                &p.terminator,
                p.parameters.local::<u64>(ParameterId::AckDelayExponent) as u32,
            ),
        };
        let mut acks = Epoch::EPOCHS.map(|epoch| {
            spaces.0.get(epoch as u64).map(|space| {
                let mut ack = space.rcvd_journal().ack_package(
                    path.cc
                        .need_ack(epoch)
                        .filter(|(pn, _)| acked[epoch].is_none_or(|sent| *pn > sent)),
                );
                if epoch == Epoch::Data {
                    ack.exponent = exponent;
                }
                ack
            })
        });
        let [a0, a1, a2] = &mut acks;
        let mut probes = limits
            .probe_quota
            .map(|quota| (quota > 0).then_some(PingFrame));
        let [p0, p1, p2] = &mut probes;
        let mut t0 = terminator;
        let mut t1 = terminator;
        let mut t2 = terminator;
        let mut h0 = path.heartbeat.clone();
        let mut h1 = path.heartbeat.clone();
        let mut h2 = path.heartbeat.clone();
        let mut validation = path;
        let mut initial: [&mut dyn for<'b> Package<&'b mut [u8]>; 4] = [&mut t0, a0, &mut h0, p0];
        let mut handshake: [&mut dyn for<'b> Package<&'b mut [u8]>; 4] = [&mut t1, a1, &mut h1, p1];
        let mut data: [&mut dyn for<'b> Package<&'b mut [u8]>; 5] =
            [&mut t2, a2, &mut validation, &mut h2, p2];
        let mut external = [&mut initial[..], &mut handshake[..], &mut data[..]];
        let compatible = data_cid.filter(|cid| *cid == dcid);
        let result = spaces.package(
            cx,
            [Some(dcid), Some(dcid), compatible],
            &mut external,
            buffer,
            limits,
            frames,
            pns,
            multipath,
        )?;
        if result.0 == 0 && data_cid.is_some() && compatible.is_none() {
            return spaces.package(
                cx,
                [None, None, data_cid],
                &mut external,
                buffer,
                limits,
                frames,
                pns,
                multipath,
            );
        }
        Ok(result)
    }
}
