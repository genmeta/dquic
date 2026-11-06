pub use qtransport::packet::encrypt as packet;
pub(crate) mod task;
use std::{
    future::poll_fn,
    io::{Cursor, IoSlice},
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
pub use packet::Packet;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    frame::{GuaranteedFrame, PingFrame},
    packet::{Package, PacketContent, assemble::Metadata},
};
use qcongestion::{CongestionController, Transport as _};
use qprotocol::QuicProtocol;
use qtransport::{path::Path, space::Spaces};
use smallvec::SmallVec;
pub(crate) use task::sending;

use crate::{Error, Paths};

pub const MAX_BURST_PACKETS: usize = 8;
/// Sealed packet metadata for each datagram.
pub type BurstPackets = [SmallVec<[Metadata; 1]>; MAX_BURST_PACKETS];

/// Owns collection and submission state until every pending packet is sent or cancelled.
pub struct Burst<'a, 'path> {
    paths: &'path Arc<Paths>,
    path: &'path Arc<Path>,
    pub(crate) datagrams: &'a mut [BytesMut],
    frames: &'a mut Vec<GuaranteedFrame>,
    pub(crate) packets: &'a mut BurstPackets,
    pub(crate) dcid: Option<ConnectionId>,
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
        Self { paths, path, datagrams, frames, packets, dcid: None, spaces: None }
    }

    pub fn cancel(&mut self) {
        if let Some(spaces) = &self.spaces {
            for packets in self.packets.iter_mut() {
                for meta in packets.drain(..) {
                    let space = spaces.0.get(meta.epoch() as u64).unwrap();
                    space.cancel(meta.pn, &mut std::iter::empty());
                }
            }
        }
        self.frames.clear();
        self.refresh_cid();
    }

    pub async fn batch(&mut self) -> Result<(), Error> {
        let mut first = true;
        loop {
            let count = poll_fn(|cx| match self.poll_collect(cx) {
                Poll::Pending if !first => Poll::Ready(Ok(0)),
                result => result,
            })
            .await?;
            if count == 0 {
                return Ok(());
            }
            self.submit(count).await?;
            first = false;
        }
    }

    pub async fn submit(&mut self, count: usize) -> Result<(), Error> {
        let spaces = self.spaces.as_ref().expect("collected spaces");
        let path = self.path;
        let dcid = self.dcid.expect("collected CID");
        let idle = self.paths.idle();
        let deadlines = Epoch::EPOCHS.map(|epoch| (path.cc.retransmit_and_expire_time(epoch).0, path.cc.pto_base(epoch) * 3));
        let datagrams: [_; MAX_BURST_PACKETS] =
            std::array::from_fn(|i| IoSlice::new(self.datagrams.get(i).map_or(&[], |bytes| &bytes[..])));
        let mut first = 0;
        while first < count {
            let mut sent_handshake = false;
            let sent = poll_fn(|cx| -> Poll<std::io::Result<Option<usize>>> {
                // ACK handling takes the same lock as submission and completion.
                let mut cc = path.cc.lock();
                // Retirement also cancels a batch already waiting for UDP writability.
                path.validation.credit().map_err(std::io::Error::other)?;
                if !path.is_active()
                    && self.packets[first..count].iter().flatten().any(|meta| meta.content == PacketContent::EffectivePayload)
                {
                    return Poll::Ready(Ok(None));
                }
                let sent = ready!(QuicProtocol::global().poll_send(cx, path.pathway, &datagrams[first..count]))?;
                for index in first..first + sent {
                    let mut packets = [None; 3];
                    for meta in self.packets[index].drain(..) {
                        let epoch = meta.epoch();
                        let space = spaces.0.get(epoch as u64).unwrap();
                        space.on_sent(meta.pn, meta.in_flight, deadlines[epoch].0, deadlines[epoch].1);
                        sent_handshake |= epoch == Epoch::Handshake;
                        packets[epoch] = Some(meta);
                    }
                    path.on_sent(&mut cc, self.datagrams[index].len(), packets, &idle);
                }
                update_amplification_blocked(
                    &mut cc,
                    spaces,
                    dcid,
                    path.validation.credit().map_or(0, |credit| credit.unwrap_or(usize::MAX)),
                    QuicProtocol::packet_overhead(path.pathway),
                );
                Poll::Ready(Ok(Some(sent)))
            })
            .await
            .map_err(no_viable_path)?;
            let Some(sent) = sent else {
                self.cancel();
                return Ok(());
            };
            if sent_handshake {
                self.paths.progress.on_handshake_sent();
            }
            if sent == 0 {
                return Err(no_viable_path("UDP submitted zero datagrams"));
            }
            first += sent;
        }
        self.refresh_cid();
        Ok(())
    }
}

impl Burst<'_, '_> {
    pub async fn collect(&mut self) -> Result<usize, Error> {
        poll_fn(|cx| self.poll_collect(cx)).await
    }

    pub(crate) fn poll_collect(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, Error>> {
        let path = self.path;
        path.send_waker.register(cx.waker());
        if path.validation.is_cancelled() {
            return Poll::Ready(Err(no_viable_path("path CID binding retired")));
        }
        let cid = ready!(path.dcid.poll_borrow(cx)).ok_or_else(|| no_viable_path("path CID binding retired"))?;
        self.dcid = Some(cid);
        let result = self.poll_collect_with_cid(cx, cid);
        if result.is_pending() {
            self.refresh_cid();
        }
        result
    }

    fn poll_collect_with_cid(&mut self, cx: &mut Context<'_>, cid: ConnectionId) -> Poll<Result<usize, Error>> {
        let path = self.path;
        self.spaces = Some(Spaces(self.paths.spaces.read_guard().clone()));
        let credit = match path.validation.poll_credit(cx) {
            Poll::Ready(credit) => credit.map_err(no_viable_path)?.unwrap_or(usize::MAX),
            Poll::Pending => 0,
        };
        let overhead = QuicProtocol::packet_overhead(path.pathway);
        let send_quota = {
            let mut cc = path.cc.lock();
            // Update the budget before driving PTO, including when credit polling waits.
            update_amplification_blocked(&mut cc, self.spaces.as_ref().unwrap(), cid, credit, overhead);
            if credit == 0 {
                ready!(cc.poll_send_quota(cx)).map_err(no_viable_path)?;
                drop(cc);
                path.cc.cancel(cx.waker());
                return Poll::Pending;
            }
            ready!(cc.poll_send_quota(cx)).map_err(no_viable_path)?
        };
        self.collect_spaces(cx, cid, send_quota, credit).map(Ok)
    }

    fn collect_spaces(&mut self, cx: &mut Context<'_>, dcid: ConnectionId, mut send_quota: usize, mut credit: usize) -> Poll<usize> {
        let path = self.path;
        let spaces = self.spaces.as_ref().unwrap();
        let packet_content = if path.is_active() {
            PacketContent::EffectivePayload
        } else {
            PacketContent::JustPing
        };
        let mut acks = Epoch::EPOCHS
            .map(|epoch| (epoch, spaces.0.get(epoch as u64).map(|space| space.rcvd_journal().ack_package(path.cc.need_ack(epoch)))));
        let mut terminator = &self.paths.terminator;
        let mut heartbeat = path.heartbeat.clone();
        let mut validation = path.validation.clone();
        let mut probes = Epoch::EPOCHS.map(|epoch| {
            (epoch, (packet_content == PacketContent::EffectivePayload && path.cc.need_send_ack_eliciting(epoch) > 0).then_some(PingFrame))
        });
        let overhead = QuicProtocol::packet_overhead(path.pathway);
        let mut count = 0;
        for (buffer, packets) in self.datagrams.iter_mut().zip(self.packets.iter_mut()) {
            let quota = if send_quota == 0 {
                1200
            } else {
                send_quota.saturating_sub(overhead)
            };
            let length = 1200.min(credit.saturating_sub(overhead)).min(quota);
            buffer.resize(length, 0);
            let [a0, a1, a2] = &mut acks;
            let [p0, p1, p2] = &mut probes;
            let mut sources: [&mut dyn for<'b> Package<&'b mut [u8]>; 9] =
                [&mut terminator, a0, a1, a2, &mut validation, &mut heartbeat, p0, p1, p2];
            let external = if packet_content == PacketContent::EffectivePayload {
                &mut sources[..]
            } else {
                &mut sources[1..]
            };
            let (size, collected) =
                spaces.poll_dump(cx, &path.cc, dcid, &mut Cursor::new(buffer.as_mut()), packet_content, self.frames, external);
            *packets = collected;
            buffer.truncate(size);
            if size == 0 {
                break;
            }
            credit -= size + overhead;
            let in_flight: usize = packets.iter().filter(|meta| meta.in_flight).map(|meta| meta.pktlen).sum();
            if in_flight > 0 {
                send_quota = send_quota.saturating_sub(in_flight + overhead);
            }
            count += 1;
            if send_quota == 0 {
                break;
            }
        }
        if count == 0 {
            Poll::Pending
        } else {
            Poll::Ready(count)
        }
    }
}

impl Burst<'_, '_> {
    fn refresh_cid(&mut self) {
        if self.dcid.take().is_some() {
            self.path.dcid.refresh();
        }
    }
}

impl Drop for Burst<'_, '_> {
    fn drop(&mut self) {
        self.refresh_cid();
    }
}

fn update_amplification_blocked(cc: &mut CongestionController, spaces: &Spaces, dcid: ConnectionId, credit: usize, overhead: usize) {
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
