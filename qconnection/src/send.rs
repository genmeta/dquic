pub mod packet;
mod task;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
pub use packet::{Packet, SendingPacket};
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    frame::{Frame, PingFrame},
    packet::{
        HeaderSize, LongHeaderBuilder, OneRttHeader,
        assemble::{Assemble, Constraints, Limit, Package},
        header::{GetType, io::WriteHeader},
    },
    param::ParameterId,
};
use qcongestion::{ArcCC, Transport as _};
use qprotocol::QuicProtocol;
use qtransport::{
    journal::ArcSendJournal,
    keys::ArcKeys,
    path::{AntiAmplifier, Path},
    space::Space,
};
pub(crate) use task::sending;

use crate::{ConnPhase, Error, MaturePhase, Paths};

pub const MAX_BURST_PACKETS: usize = 8;
pub type BurstPns = [Vec<(usize, u64)>; 3];

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
    datagrams: &'a mut [BytesMut],
    frames: &'a mut Vec<Frame>,
    pns: &'a mut BurstPns,
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

pub struct Collector<'a> {
    burst: Burst<'a>,
    paths: &'a Arc<Paths>,
    path: &'a Arc<Path>,
    dcid: ConnectionId,
}

impl<'a> Burst<'a> {
    pub fn collect(
        self,
        paths: &'a Arc<Paths>,
        path: &'a Arc<Path>,
        dcid: ConnectionId,
    ) -> Collector<'a> {
        Collector {
            burst: self,
            paths,
            path,
            dcid,
        }
    }
}

impl Future for Collector<'_> {
    type Output = Result<usize, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
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
        let shared_phase = this.paths.phase();
        let phase = shared_phase.poll_phase(cx);
        let selected = this.path.selected();
        match &*phase {
            ConnPhase::Initial(phase) => {
                if selected != Path::SUSPEND {
                    while count < this.burst.datagrams.len() && limits.credit > 0 {
                        let header =
                            LongHeaderBuilder::with_cid(phase.dcid(), phase.scid).initial(vec![]);
                        let crypto: &mut dyn for<'b> Package<&'b mut BytesMut> =
                            if selected == Path::MP_INITIAL {
                                &mut phase.initial.crypto.multipath()
                            } else {
                                &mut phase.initial.crypto.outgoing()
                            };
                        let n = this.collect_long(
                            cx,
                            &phase.initial,
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
            }
            ConnPhase::Handshake(phase) => {
                while count < this.burst.datagrams.len() && limits.credit > 0 {
                    let before = count;
                    let header =
                        LongHeaderBuilder::with_cid(phase.initial.dcid(), phase.initial.scid)
                            .initial(vec![]);
                    count += this.collect_long(
                        cx,
                        &phase.initial.initial,
                        header,
                        &mut phase.initial.initial.crypto.outgoing(),
                        &mut limits,
                        &mut acked[Epoch::Initial],
                    )?;
                    let header =
                        LongHeaderBuilder::with_cid(phase.initial.dcid(), phase.initial.scid)
                            .handshake();
                    count += this.collect_long(
                        cx,
                        &phase.handshake,
                        header,
                        &mut phase.handshake.crypto.outgoing(),
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
                        LongHeaderBuilder::with_cid(phase.peer_cid, phase.scid).initial(vec![]);
                    count += this.collect_long(
                        cx,
                        &phase.spaces.initial,
                        header,
                        &mut phase.spaces.initial.crypto.outgoing(),
                        &mut limits,
                        &mut acked[Epoch::Initial],
                    )?;
                    let header =
                        LongHeaderBuilder::with_cid(phase.peer_cid, phase.scid).handshake();
                    count += this.collect_long(
                        cx,
                        &phase.spaces.handshake,
                        header,
                        &mut phase.spaces.handshake.crypto.outgoing(),
                        &mut limits,
                        &mut acked[Epoch::Handshake],
                    )?;
                    count += ready!(this.collect_one_rtt(
                        cx,
                        phase,
                        &mut limits,
                        &mut acked[Epoch::Data]
                    ))?;
                    if count == before {
                        break;
                    }
                }
            }
        }
        if count == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(count))
        }
    }
}

impl Collector<'_> {
    fn count(&self) -> usize {
        self.burst.pns.iter().map(Vec::len).sum()
    }

    fn collect_long<H>(
        &mut self,
        cx: &mut Context<'_>,
        space: &Space<ArcKeys>,
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
        let pn = space.send_journal.next_pn().map_err(packet_error)?;
        let packet = Packet::new(header, pn, buffer)?;
        let mut packet = SendingPacket {
            packet,
            keys: &keys.sealing,
            limits,
        };
        match packet.assemble(
            cx,
            [&mut &self.paths.terminator(), &mut ack, crypto, &mut ping],
            self.burst.frames,
        ) {
            Poll::Ready(Ok(n)) if n > 0 => {
                packet.seal()?;
            }
            Poll::Ready(Err(error)) => return Err(error),
            _ => {
                space.send_journal.cancel(pn.0);
                return Ok(0);
            }
        }
        self.record(space.epoch, pn.0, &space.send_journal, acked);
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
            || !space.send_journal.has_capacity()
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
        let header = OneRttHeader::new(Default::default(), self.dcid);
        if limits.credit().min(limits.max_size()) < limits.min_size().max(header.size() + 24)
            || limits.send_quota() < limits.min_size()
        {
            return Poll::Ready(Ok(0));
        }
        let terminator = self.paths.terminator();
        let mut close = &terminator;
        let mut ack = space.rcvd_journal.ack_package(
            self.burst
                .cc
                .need_ack(Epoch::Data)
                .filter(|(pn, _)| acked.is_none_or(|sent| *pn > sent)),
        );
        ack.exponent = phase.parameters.local::<u64>(ParameterId::AckDelayExponent) as u32;
        let mut validation = self.path.as_ref();
        let mut crypto = space.crypto.outgoing();
        let mut reliable = phase.reliable_frames.clone();
        let mut streams = phase.streams.clone();
        let mut heartbeat = self.burst.pns[Epoch::Data]
            .is_empty()
            .then_some(&self.path.activity);
        let buffer = &mut self.burst.datagrams[index];
        buffer.clear();
        let (pn, key) = keys
            .reserve(|_| space.send_journal.next_pn())
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
                self.record(Epoch::Data, pn.0, &space.send_journal, acked);
                space.send_journal.set_generation(pn.0, generation);
                return Poll::Ready(Ok(1));
            }
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            _ => {}
        }
        if packet.limits.max_size() == 0 {
            space.send_journal.cancel(pn.0);
            return Poll::Ready(Ok(0));
        }
        let mut flow = std::task::ready!(phase.flow.sender.poll_credit(
            cx,
            if packet.limits.send_quota() >= packet.limits.max_size() {
                phase.streams.fresh_bytes().min(1200)
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
                space.send_journal.cancel(pn.0);
                return Poll::Ready(Ok(0));
            }
        }
        let (generation, _) = packet.seal()?;
        flow.post_sent(flow.available() - limits.flow_ctrl);
        self.record(Epoch::Data, pn.0, &space.send_journal, acked);
        space.send_journal.set_generation(pn.0, generation);
        Poll::Ready(Ok(1))
    }

    fn record(&mut self, epoch: Epoch, pn: u64, journal: &ArcSendJournal, acked: &mut Option<u64>) {
        let index = self.count();
        for frame in self.burst.frames.iter() {
            match frame {
                Frame::Ack(ack) => *acked = Some(ack.largest()),
                _ => {}
            }
        }
        journal.on_sent(pn, self.burst.frames.drain(..));
        self.burst.pns[epoch].push((index, pn));
    }
}

#[cfg(test)]
mod tests;
