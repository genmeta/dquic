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
    role::Role,
};
use qcongestion::Transport as _;
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
                        space.on_sent(meta.pn, meta.in_flight, deadlines[epoch].0, deadlines[epoch].1);
                        Some(meta)
                    });
                    sent_handshake |= packets[Epoch::Handshake].is_some();
                    path.on_sent(&mut cc, self.datagrams[index].len(), packets, &idle);
                }
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
        let phase = self.paths.phase().poll_phase(cx).clone();
        let path = self.path;
        let mut limits = Constraints {
            send_quota: ready!(path.cc.poll_send_quota(cx)).map_err(no_viable_path)?,
            credit: ready!(path.anti_amplifier.poll_credit(cx))?,
            probe_quota: Epoch::EPOCHS.map(|epoch| {
                if path.cc.need_send_ack_eliciting(epoch) > 0 {
                    1200
                } else {
                    0
                }
            }),
            flow_ctrl: 0,
            overhead: QuicProtocol::packet_overhead(path.pathway),
        };
        if path.selected() == Path::SUSPEND {
            return Poll::Pending;
        }
        self.spaces = Some(self.paths.spaces.read().unwrap().snapshot());
        match phase {
            ConnPhase::Initial(phase) => self.collect_depth(
                cx,
                1,
                phase.dcid(),
                &mut limits,
                0,
                path.selected() == Path::MP_INITIAL && self.paths.role() == Role::Client,
            ),
            ConnPhase::Handshake(phase) => {
                self.collect_depth(cx, 2, phase.dcid, &mut limits, 0, false)
            }
            ConnPhase::Mature(phase) => {
                if self.dcid.is_none() {
                    path.send_waker.register(cx.waker());
                    let cell = path.dcid_cell.read().unwrap();
                    let Some(cell) = cell.as_ref() else {
                        return Poll::Pending;
                    };
                    self.dcid = Some(
                        ready!(cell.borrow_cid(path.send_waker.clone()))
                            .ok_or_else(|| no_viable_path("path CID retired"))?,
                    );
                }
                let requested = self
                    .spaces
                    .as_ref()
                    .unwrap()
                    .0
                    .get(Epoch::Data as u64)
                    .filter(|_| limits.send_quota >= 1200)
                    .map_or(0, |data| data.fresh_bytes_up_to(limits.send_quota));
                let mut flow = ready!(phase.flow_ctrl.sender.poll_credit(cx, requested));
                limits.flow_ctrl = flow.available();
                let result = self.collect_depth(
                    cx,
                    3,
                    **self.dcid.as_ref().unwrap(),
                    &mut limits,
                    phase.parameters.local::<u64>(ParameterId::AckDelayExponent) as u32,
                    false,
                );
                flow.post_sent(flow.available() - limits.flow_ctrl);
                if result.is_pending() {
                    self.dcid.take();
                }
                result
            }
        }
    }

    fn collect_depth(
        &mut self,
        cx: &mut Context<'_>,
        depth: usize,
        dcid: ConnectionId,
        limits: &mut Constraints,
        exponent: u32,
        multipath: bool,
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
        let mut validation = path.as_ref();
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
                multipath,
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

fn no_viable_path(error: impl std::fmt::Display) -> Error {
    QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string()).into()
}
