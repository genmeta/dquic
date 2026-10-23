pub use qtransport::packet::assemble as packet;
pub(crate) mod task;
use std::{
    future::poll_fn,
    io::IoSlice,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
pub use packet::{Envelope, Packet};
use qbase::{
    Epoch,
    cid::{BorrowedCid, ConnectionId},
    error::{ErrorKind, QuicError},
    frame::{GuaranteedFrame, PingFrame},
    packet::{Package, assemble::Metadata},
    param::ParameterId,
};
use qcongestion::{CongestionController, Transport as _};
use qprotocol::QuicProtocol;
use qtransport::{
    path::Path,
    space::{Spaces, assemble::Constraints},
};
pub(crate) use task::sending;

use crate::{ArcReliableFrames, ConnPhase, Error, Paths};

pub const MAX_BURST_PACKETS: usize = 8;
/// Sealed packet metadata, indexed by datagram and epoch.
pub type BurstPackets = [[Option<Metadata>; 3]; MAX_BURST_PACKETS];

/// Owns collection and submission state until every pending packet is sent or cancelled.
pub struct Burst<'a, 'path> {
    paths: &'path Arc<Paths>,
    path: &'path Arc<Path>,
    pub(crate) datagrams: &'a mut [BytesMut],
    frames: &'a mut Vec<GuaranteedFrame>,
    pub(crate) packets: &'a mut BurstPackets,
    pub(crate) dcid: Option<BorrowedCid<ArcReliableFrames>>,
    spaces: Option<Spaces>,
}

impl<'a, 'path> Burst<'a, 'path> {
    pub fn new(
        paths: &'path Arc<Paths>,
        path: &'path Arc<Path>,
        datagrams: &'a mut [BytesMut],
        frames: &'a mut Vec<GuaranteedFrame>,
        packets: &'a mut BurstPackets,
    ) -> Self {
        Self {
            paths,
            path,
            datagrams,
            frames,
            packets,
            dcid: None,
            spaces: None,
        }
    }

    pub fn cancel(&mut self) {
        if let Some(spaces) = &self.spaces {
            for slots in self.packets.iter_mut() {
                for (epoch, space) in spaces.0.enumerate() {
                    if let Some(meta) = slots[epoch as usize].take() {
                        space.cancel(meta.pn, &mut std::iter::empty());
                    }
                }
            }
        }
        self.frames.clear();
        self.dcid.take();
    }

    pub async fn batch(&mut self) -> Result<(), Error> {
        let count = self.collect().await?;
        self.submit(count).await?;
        Ok(())
    }

    pub async fn submit(&mut self, count: usize) -> Result<(), Error> {
        let spaces = self.spaces.as_ref().expect("collected spaces");
        let path = self.path;
        let dcid = **self.dcid.as_ref().expect("collected CID");
        let idle = self.paths.idle();
        let deadlines = Epoch::EPOCHS.map(|epoch| {
            (
                path.cc.retransmit_and_expire_time(epoch).0,
                path.cc.pto_base(epoch) * 3,
            )
        });
        let datagrams: [_; MAX_BURST_PACKETS] = std::array::from_fn(|i| {
            IoSlice::new(self.datagrams.get(i).map_or(&[], |bytes| &bytes[..]))
        });
        let mut first = 0;
        while first < count {
            let mut sent_handshake = false;
            let sent = poll_fn(|cx| -> Poll<std::io::Result<usize>> {
                // ACK handling takes the same lock as submission and completion.
                let mut cc = path.cc.lock();
                let sent = ready!(QuicProtocol::global().poll_send(
                    cx,
                    path.pathway,
                    &datagrams[first..count]
                ))?;
                for index in first..first + sent {
                    let packets = Epoch::EPOCHS.map(|epoch| {
                        let meta = self.packets[index][epoch].take()?;
                        let space = spaces.0.get(epoch as u64).unwrap();
                        space.on_sent(
                            meta.pn,
                            meta.in_flight,
                            deadlines[epoch].0,
                            deadlines[epoch].1,
                        );
                        Some(meta)
                    });
                    sent_handshake |= packets[Epoch::Handshake].is_some();
                    path.on_sent(&mut cc, self.datagrams[index].len(), packets, &idle);
                }
                update_amplification_blocked(
                    &mut cc,
                    spaces,
                    dcid,
                    path.validation
                        .credit()
                        .map_or(0, |credit| credit.unwrap_or(usize::MAX)),
                    QuicProtocol::packet_overhead(path.pathway),
                );
                Poll::Ready(Ok(sent))
            })
            .await
            .map_err(no_viable_path)?;
            if sent_handshake {
                self.paths.on_handshake_sent();
            }
            if sent == 0 {
                return Err(no_viable_path("UDP submitted zero datagrams"));
            }
            first += sent;
        }
        self.dcid.take();
        Ok(())
    }
}

impl Burst<'_, '_> {
    pub async fn collect(&mut self) -> Result<usize, Error> {
        poll_fn(|cx| self.poll_collect(cx)).await
    }

    pub(crate) fn poll_collect(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, Error>> {
        let path = self.path;
        let cid = ready!(path.cid.borrow_cid(cx))
            .ok_or_else(|| no_viable_path("path CID binding retired"))?;
        let phase = self.paths.phase().poll_phase(cx).clone();
        self.spaces = Some(Spaces(self.paths.spaces.read_guard().clone()));
        let credit = match path.poll_credit(cx) {
            Poll::Ready(credit) => credit.map_err(no_viable_path)?,
            Poll::Pending => 0,
        };
        let overhead = QuicProtocol::packet_overhead(path.pathway);
        let send_quota = {
            let mut cc = path.cc.lock();
            // Update the budget before driving PTO, including when credit polling waits.
            update_amplification_blocked(
                &mut cc,
                self.spaces.as_ref().unwrap(),
                *cid,
                credit,
                overhead,
            );
            ready!(cc.poll_send_quota(cx)).map_err(no_viable_path)?
        };
        if credit == 0 {
            return Poll::Pending;
        }
        let mut limits = Constraints {
            send_quota,
            credit,
            probe_quota: Epoch::EPOCHS.map(|epoch| {
                if path.cc.need_send_ack_eliciting(epoch) > 0 {
                    1200
                } else {
                    0
                }
            }),
            flow_ctrl: 0,
            overhead,
        };
        let mut flow = if let ConnPhase::Mature(phase) = &phase {
            let requested = self
                .spaces
                .as_ref()
                .unwrap()
                .0
                .get(Epoch::Data as u64)
                .filter(|_| limits.send_quota >= 1200)
                .map_or(0, |data| data.fresh_bytes_up_to(limits.send_quota));
            Some(ready!(phase.flow_ctrl.sender.poll_credit(cx, requested)))
        } else {
            None
        };
        limits.flow_ctrl = flow.as_ref().map_or(0, |credit| credit.available());
        let (depth, exponent) = match &phase {
            ConnPhase::Initial(_) => (1, 0),
            ConnPhase::Handshake(_) => (2, 0),
            ConnPhase::Mature(phase) => (
                3,
                phase.parameters.local::<u64>(ParameterId::AckDelayExponent) as u32,
            ),
        };
        let result = self.collect_depth(cx, depth, *cid, &mut limits, exponent);
        if let Some(flow) = &mut flow {
            flow.post_sent(flow.available() - limits.flow_ctrl);
        }
        // On assembly errors a prefix can already be sealed. Keep its borrow
        // until cancel() recovers it; Pending has no sealed packets.
        if !result.is_pending() {
            self.dcid = Some(cid);
        }
        result
    }

    fn collect_depth(
        &mut self,
        cx: &mut Context<'_>,
        depth: usize,
        dcid: ConnectionId,
        limits: &mut Constraints,
        exponent: u32,
    ) -> Poll<Result<usize, Error>> {
        let path = self.path;
        let spaces = self.spaces.as_ref().unwrap();
        let mut acks = Epoch::EPOCHS.map(|epoch| {
            (
                epoch,
                spaces.0.get(epoch as u64).map(|space| {
                    let mut ack = space.rcvd_journal().ack_package(path.cc.need_ack(epoch));
                    if epoch == Epoch::Data {
                        ack.exponent = exponent;
                    }
                    ack
                }),
            )
        });
        let mut terminator = &self.paths.terminator;
        let mut heartbeat = path.heartbeat.clone();
        let mut validation = path.validation.clone();
        let dcids = std::array::from_fn(|epoch| (epoch < depth).then_some(dcid));
        let mut count = 0;
        for (buffer, packets) in self.datagrams.iter_mut().zip(self.packets.iter_mut()) {
            // A sealed packet consumes its epoch's PTO allowance, even without a PING.
            let mut probes = Epoch::EPOCHS
                .map(|epoch| (epoch, (limits.probe_quota[epoch] > 0).then_some(PingFrame)));
            let [a0, a1, a2] = &mut acks;
            let [p0, p1, p2] = &mut probes;
            let mut sources: [&mut dyn for<'b> Package<&'b mut [u8]>; 9] = [
                &mut terminator,
                a0,
                a1,
                a2,
                &mut validation,
                &mut heartbeat,
                p0,
                p1,
                p2,
            ];
            buffer.resize(1200, 0);
            let (size, _) = spaces.package(
                cx,
                dcids,
                &mut sources,
                buffer,
                limits,
                self.frames,
                packets,
            )?;
            buffer.truncate(size);
            if size == 0 {
                break;
            }
            count += 1;
        }
        if count == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(count))
        }
    }
}

fn update_amplification_blocked(
    cc: &mut CongestionController,
    spaces: &Spaces,
    dcid: ConnectionId,
    credit: usize,
    overhead: usize,
) {
    let epoch = cc.pto_epoch();
    let blocked = match credit {
        0 => true,
        usize::MAX => false,
        _ => epoch
            .and_then(|epoch| spaces.0.get(epoch as u64))
            .and_then(|space| space.probe_size(dcid))
            .is_some_and(|size| credit < size + overhead),
    };
    cc.set_amplification_blocked(blocked);
}

fn no_viable_path(error: impl std::fmt::Display) -> Error {
    QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string()).into()
}
