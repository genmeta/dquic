pub use qtransport::packet::assemble as packet;
pub(crate) mod task;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
pub use packet::{Packet, SendingPacket};
use qbase::{
    Epoch,
    cid::{ArcCidCell, BorrowedCid},
    error::{ErrorKind, QuicError},
    frame::{Frame, GetFrameType, PingFrame},
    packet::{
        HeaderSize, LongHeaderBuilder, OneRttHeader, PacketContent,
        assemble::{Assemble, Constraints, Limit, Package, in_flight},
        header::{GetType, io::WriteHeader},
    },
    param::ParameterId,
    role::Role,
};
use qcongestion::{ArcCC, Transport as _};
use qprotocol::QuicProtocol;
use qtransport::{
    keys::ArcKeys,
    path::{AntiAmplifier, Path},
    space::Space,
    terminate::ArcTerminator,
};
pub(crate) use task::sending;

use crate::{ArcReliableFrames, ConnPhase, Error, MaturePhase, Paths};

pub const MAX_BURST_PACKETS: usize = 8;
/// Submission metadata retained independently of frames that an early ACK can release.
#[derive(Clone, Copy)]
pub struct PendingPacket {
    pub index: usize,
    pub pn: u64,
    pub content: PacketContent,
    pub in_flight: bool,
    pub ack: Option<u64>,
}

pub type BurstPns = [Vec<PendingPacket>; 3];

fn packet_error(error: qtransport::keys::PacketError) -> crate::Error {
    match error {
        qtransport::keys::PacketError::Connection(error) => error,
        error => qbase::error::QuicError::with_default_fty(
            qbase::error::ErrorKind::Internal,
            error.to_string(),
        )
        .into(),
    }
}

pub struct Burst<'a> {
    cc: &'a ArcCC,
    anti_amplifier: &'a AntiAmplifier,
    pub(crate) datagrams: &'a mut [BytesMut],
    pub(crate) frames: &'a mut Vec<Frame>,
    pub(crate) pns: &'a mut BurstPns,
}

pub fn burst<'a>(
    cc: &'a ArcCC,
    anti_amplifier: &'a AntiAmplifier,
    datagrams: &'a mut [BytesMut],
    frames: &'a mut Vec<Frame>,
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
        }
    }
}

impl Future for Collector<'_, '_> {
    type Output = Result<usize, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let shared_phase = this.paths.phase();
        let phase = shared_phase.poll_phase(cx).clone();
        let mut limits = Constraints {
            flow_ctrl: 0,
            send_quota: ready!(this.burst.cc.poll_send_quota(cx)).map_err(|error| {
                QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string())
            })?,
            credit: ready!(this.burst.anti_amplifier.poll_credit(cx))?,
            min_size: 0,
            max_size: 1200,
            overhead: QuicProtocol::packet_overhead(this.path.pathway),
            probe_quota: 0,
        };
        let mut count = 0;
        let mut acked = [None; 3];
        let selected = this.path.selected();
        // Quota polling registered the sender for path selection and retirement wakeups.
        if selected == Path::SUSPEND {
            return Poll::Pending;
        }
        match &phase {
            ConnPhase::Initial(phase) => {
                let dcid = phase.dcid();
                while count < this.burst.datagrams.len() && limits.credit > 0 {
                    let header =
                        LongHeaderBuilder::with_cid(dcid, phase.scid).initial(vec![]);
                    let crypto: &mut dyn for<'b> Package<&'b mut BytesMut> =
                        if selected == Path::MP_INITIAL && this.paths.role() == Role::Client {
                            &mut phase.initial_space.crypto.multipath()
                        } else {
                            &mut phase.initial_space.crypto.outgoing()
                        };
                    let n = this.collect_long(
                        cx,
                        &phase.initial_space,
                        &phase.terminator,
                        header,
                        crypto,
                        &mut limits,
                        &mut acked[Epoch::Initial],
                    )?;
                    if n == 0 {
                        break;
                    }
                    count += n;
                }
            }
            ConnPhase::Handshake(phase) => {
                while count < this.burst.datagrams.len() && limits.credit > 0 {
                    let before = count;
                    let header =
                        LongHeaderBuilder::with_cid(phase.dcid, phase.scid).initial(vec![]);
                    count += this.collect_long(
                        cx,
                        &phase.initial_space,
                        &phase.terminator,
                        header,
                        &mut phase.initial_space.crypto.outgoing(),
                        &mut limits,
                        &mut acked[Epoch::Initial],
                    )?;
                    let header = LongHeaderBuilder::with_cid(phase.dcid, phase.scid).handshake();
                    count += this.collect_long(
                        cx,
                        &phase.handshake_space,
                        &phase.terminator,
                        header,
                        &mut phase.handshake_space.crypto.outgoing(),
                        &mut limits,
                        &mut acked[Epoch::Handshake],
                    )?;
                    if count == before {
                        break;
                    }
                }
            }
            ConnPhase::Mature(phase) => {
                while count < this.burst.datagrams.len() && limits.credit > 0 {
                    let before = count;
                    let header =
                        LongHeaderBuilder::with_cid(phase.dcid, phase.scid).initial(vec![]);
                    count += this.collect_long(
                        cx,
                        &phase.spaces.initial,
                        &phase.terminator,
                        header,
                        &mut phase.spaces.initial.crypto.outgoing(),
                        &mut limits,
                        &mut acked[Epoch::Initial],
                    )?;
                    let header = LongHeaderBuilder::with_cid(phase.dcid, phase.scid).handshake();
                    count += this.collect_long(
                        cx,
                        &phase.spaces.handshake,
                        &phase.terminator,
                        header,
                        &mut phase.spaces.handshake.crypto.outgoing(),
                        &mut limits,
                        &mut acked[Epoch::Handshake],
                    )?;
                    if selected != Path::MP_INITIAL {
                        count += ready!(this.collect_one_rtt(
                            cx,
                            phase,
                            &mut limits,
                            &mut acked[Epoch::Data]
                        ))?;
                    }
                    if count == before {
                        break;
                    }
                }
            }
        }
        if count == 0 {
            this.dcid.take();
            Poll::Pending
        } else {
            Poll::Ready(Ok(count))
        }
    }
}

impl Collector<'_, '_> {
    fn count(&self) -> usize {
        self.burst.pns.iter().map(Vec::len).sum()
    }

    pub(crate) fn collect_long<H>(
        &mut self,
        cx: &mut Context<'_>,
        space: &Space<ArcKeys>,
        mut terminator: &ArcTerminator,
        header: H,
        crypto: &mut dyn for<'b> Package<&'b mut BytesMut>,
        limits: &mut Constraints,
        acked: &mut Option<u64>,
    ) -> Result<usize, Error>
    where
        H: GetType + HeaderSize,
        for<'b> &'b mut BytesMut: WriteHeader<H>,
    {
        let index = self.count();
        let Ok(keys) = space.keys.get() else {
            return Ok(0);
        };
        let mut ack = space.rcvd_journal.ack_package(
            self.burst
                .cc
                .need_ack(space.epoch)
                .filter(|(pn, _)| acked.is_none_or(|sent| *pn > sent)),
        );
        let mut ping = (self.burst.pns[space.epoch].is_empty()
            && self.burst.cc.need_send_ack_eliciting(space.epoch) > 0)
            .then_some(PingFrame);
        let mut heartbeat = (self.count() == 0).then(|| self.path.heartbeat.clone());
        limits.probe_quota = if ping.is_some() { 1200 } else { 0 };
        limits.max_size = 1200;
        limits.min_size = if space.epoch == Epoch::Initial {
            1200
        } else {
            0
        };
        let Some(buffer) = self.burst.datagrams.get_mut(index) else {
            return Ok(0);
        };
        buffer.clear();
        let pn = space.next_pn()?;
        let packet = Packet::new(header, pn, buffer)?;
        let mut packet = SendingPacket {
            packet,
            keys: &keys.sealing,
            limits,
        };
        let closing = packet.assemble(cx, [&mut terminator], self.burst.frames);
        let result = match closing {
            Poll::Ready(Ok(n)) if n > 0 => closing,
            Poll::Ready(Err(_)) => closing,
            _ if packet.limits.max_size() == 0 => closing,
            _ => packet.assemble(
                cx,
                [&mut ack, crypto, &mut heartbeat, &mut ping],
                self.burst.frames,
            ),
        };
        match result {
            Poll::Ready(Ok(n)) if n > 0 => {
                packet.seal()?;
            }
            Poll::Ready(Err(error)) => {
                space.cancel(pn.0);
                return Err(error);
            },
            _ => {
                space.cancel(pn.0);
                return Ok(0);
            }
        }
        self.record(space.epoch, pn.0, acked);
        space.on_assembled(pn.0, self.burst.frames.drain(..));
        Ok(1)
    }

    fn collect_one_rtt(
        &mut self,
        cx: &mut Context<'_>,
        phase: &MaturePhase,
        limits: &mut Constraints,
        acked: &mut Option<u64>,
    ) -> Poll<Result<usize, Error>> {
        let index = self.count();
        let space = &phase.spaces.data;
        if index == self.burst.datagrams.len()
            || limits.credit == 0
            || !space.sent_journal.has_capacity()
        {
            return Poll::Ready(Ok(0));
        }
        let Ok(keys) = space.keys.get() else {
            return Poll::Ready(Ok(0));
        };
        let mut ping = (self.burst.pns[Epoch::Data].is_empty()
            && self.burst.cc.need_send_ack_eliciting(Epoch::Data) > 0)
            .then_some(PingFrame);
        limits.probe_quota = if ping.is_some() { 1200 } else { 0 };
        limits.max_size = 1200;
        limits.min_size = if self.path.challenge().is_some() || self.path.response().is_some() {
            1200
        } else {
            0
        };
        if self.dcid.is_none() {
            self.path.send_waker.register(cx.waker());
            let cell = self
                .dcid_cell
                .get_or_init(|| phase.cid_registry.remote.apply_dcid());
            match cell.borrow_cid(self.path.send_waker.clone()) {
                Poll::Ready(Some(dcid)) => self.dcid = Some(dcid),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(QuicError::with_default_fty(
                        ErrorKind::NoViablePath,
                        "path CID retired",
                    )
                    .into()));
                }
                // Let an already collected long-header packet proceed without a Data CID.
                Poll::Pending => return Poll::Ready(Ok(0)),
            }
        }
        let header = OneRttHeader::new(Default::default(), **self.dcid.as_ref().unwrap());
        if limits.credit().min(limits.max_size()) < limits.min_size().max(header.size() + 24)
            || limits.send_quota() < limits.min_size()
        {
            return Poll::Ready(Ok(0));
        }
        let mut close = &phase.terminator;
        let mut ack = space.rcvd_journal.ack_package(
            self.burst
                .cc
                .need_ack(Epoch::Data)
                .filter(|(pn, _)| acked.is_none_or(|sent| *pn > sent)),
        );
        ack.exponent = phase.parameters.local::<u64>(ParameterId::AckDelayExponent) as u32;
        let mut validation = self.path.as_ref();
        let mut crypto = space.crypto.outgoing();
        let mut reliable = space.reliable_frames.clone();
        let mut streams = space.streams.clone();
        let mut heartbeat = (self.count() == 0).then(|| self.path.heartbeat.clone());
        let buffer = &mut self.burst.datagrams[index];
        buffer.clear();
        let (pn, key) = keys
            .reserve(|_| space.next_pn().map_err(Into::into))
            .map_err(packet_error)?;
        let packet = Packet::new(header, pn, buffer)?;
        let mut packet = SendingPacket {
            packet,
            keys: &key,
            limits,
        };
        match packet.assemble(cx, [&mut close], self.burst.frames) {
            Poll::Ready(Ok(n)) if n > 0 => {
                let (generation, _) = packet.seal()?;
                self.record(Epoch::Data, pn.0, acked);
                space.on_sealed(pn.0, generation, self.burst.frames.drain(..));
                return Poll::Ready(Ok(1));
            }
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            _ => {}
        }
        if packet.limits.max_size() == 0 {
            space.cancel(pn.0);
            return Poll::Ready(Ok(0));
        }
        let mut flow = std::task::ready!(phase.flow_ctrl.sender.poll_credit(
            cx,
            if packet.limits.send_quota() >= packet.limits.max_size() {
                space.streams.fresh_bytes().min(1200)
            } else {
                0
            }
        ))?;
        packet.limits.flow_ctrl = flow.available();
        match packet.assemble(
            cx,
            [
                &mut ack,
                &mut validation,
                &mut crypto,
                &mut reliable,
                &mut streams,
                &mut heartbeat,
                &mut ping,
            ],
            self.burst.frames,
        ) {
            Poll::Ready(Ok(n)) if n > 0 => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            _ => {
                space.cancel(pn.0);
                return Poll::Ready(Ok(0));
            }
        }
        let (generation, _) = packet.seal()?;
        flow.post_sent(flow.available() - limits.flow_ctrl);
        self.record(Epoch::Data, pn.0, acked);
        space.on_sealed(pn.0, generation, self.burst.frames.drain(..));
        Poll::Ready(Ok(1))
    }

    fn record(&mut self, epoch: Epoch, pn: u64, acked: &mut Option<u64>) {
        let mut packet = PendingPacket {
            index: self.count(),
            pn,
            content: PacketContent::default(),
            in_flight: in_flight(self.burst.frames),
            ack: None,
        };
        for frame in self.burst.frames.iter() {
            packet.content += PacketContent::from(frame.frame_type());
            if let Frame::Ack(ack) = frame {
                packet.ack = Some(ack.largest());
                *acked = packet.ack;
            }
        }
        self.burst.pns[epoch].push(packet);
    }
}
