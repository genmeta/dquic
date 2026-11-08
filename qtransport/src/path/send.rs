use std::{
    future::poll_fn,
    io::IoSlice,
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    frame::GuaranteedFrame,
    packet::{Package, PacketContent, assemble::Metadata},
    time::timer::ArcIdleTimer,
};
use qcongestion::{CongestionController, Transport as _};
use qprotocol::QuicProtocol;
use smallvec::SmallVec;
use tokio::time::Instant;

use super::Path;
use crate::{Error, space::ArcSpaces};

/// A UDP datagram and the QUIC packets awaiting submission within it.
#[derive(Default)]
pub struct Datagram {
    pub(crate) bytes: BytesMut,
    pub(crate) packets: SmallVec<[Metadata; 1]>,
}

impl Path {
    fn poll_collect(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        datagrams: &mut [Datagram],
        frames: &mut Vec<GuaranteedFrame>,
    ) -> Poll<Result<usize, Error>> {
        let mut credit = match self.validation.poll_credit(cx) {
            Poll::Ready(credit) => {
                credit.map_err(|error| QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string()))?.unwrap_or(usize::MAX)
            }
            Poll::Pending => 0,
        };
        let overhead = QuicProtocol::packet_overhead(self.pathway);
        // Update the budget before driving PTO, including when credit polling waits.
        update_amplification_blocked(&mut self.cc.lock(), &self.spaces, dcid, credit, overhead);
        self.cc.prepare_burst_budget(cx).map_err(|error| QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string()))?;
        if credit == 0 {
            self.cc.cancel(cx.waker());
            return Poll::Pending;
        }
        let packet_content = if self.is_active() {
            PacketContent::EffectivePayload
        } else {
            PacketContent::JustPing
        };
        let mut acks: SmallVec<[_; 3]> =
            self.spaces.iter().map(|space| (space.epoch(), space.rcvd_journal().ack_package(self.cc.need_ack(space.epoch())))).collect();
        let mut terminator = &self.terminator;
        let mut heartbeat = self.heartbeat.clone();
        let mut validation = self.validation.clone();
        let mut sources: SmallVec<[_; 6]> = acks.iter_mut().map(|ack| ack as &mut dyn for<'b> Package<&'b mut [u8]>).collect();
        sources.extend([&mut terminator as &mut dyn for<'b> Package<&'b mut [u8]>, &mut validation, &mut heartbeat]);
        let mut count = 0;
        for datagram in datagrams {
            let buffer = &mut datagram.bytes;
            let length = 1200.min(credit.saturating_sub(overhead));
            buffer.resize(length, 0);
            let (size, packets) =
                self.spaces.poll_dump(cx, &self.cc, overhead, dcid, buffer.as_mut(), packet_content, frames, &mut sources);
            datagram.packets.extend(packets);
            buffer.truncate(size);
            if size == 0 {
                break;
            }
            credit -= size + overhead;
            count += 1;
            if self.cc.send_quota() == 0 {
                break;
            }
        }
        if count == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(count))
        }
    }

    /// Wait for at least one datagram. Call [`Self::refresh`] after submission or cancellation.
    pub async fn collect(&self, datagrams: &mut [Datagram], frames: &mut Vec<GuaranteedFrame>) -> Result<(usize, ConnectionId), Error> {
        poll_fn(|cx| {
            self.send_waker.register(cx.waker());
            if self.validation.is_cancelled() {
                return Poll::Ready(Err(QuicError::with_default_fty(ErrorKind::NoViablePath, "path CID binding retired").into()));
            }
            let dcid = ready!(self.dcid.poll_borrow(cx))
                .ok_or_else(|| QuicError::with_default_fty(ErrorKind::NoViablePath, "path CID binding retired"))?;
            let result = self.poll_collect(cx, dcid, datagrams, frames);
            if result.is_pending() {
                self.dcid.refresh();
            }
            result.map(|result| result.map(|count| (count, dcid)))
        })
        .await
    }

    /// Submit the datagrams and account each successful prefix under the CC lock.
    pub(crate) async fn send(&self, datagrams: &mut [Datagram], dcid: ConnectionId, idle_timer: &ArcIdleTimer) -> Result<(), Error> {
        let overhead = QuicProtocol::packet_overhead(self.pathway);
        let deadlines = Epoch::EPOCHS.map(|epoch| (self.cc.retransmit_and_expire_time(epoch).0, self.cc.pto_base(epoch) * 3));
        let mut first = 0;
        while first < datagrams.len() {
            let mut sent_handshake = false;
            let sent = poll_fn(|cx| -> Poll<std::io::Result<Option<usize>>> {
                // ACK handling takes the same lock as submission and completion.
                let mut cc = self.cc.lock();
                self.validation.credit().map_err(std::io::Error::other)?;
                if !self.is_active()
                    && datagrams[first..]
                        .iter()
                        .flat_map(|datagram| &datagram.packets)
                        .any(|meta| meta.content == PacketContent::EffectivePayload)
                {
                    return Poll::Ready(Ok(None));
                }
                let sent = {
                    let buffers: SmallVec<[_; 8]> = datagrams[first..].iter().map(|datagram| IoSlice::new(&datagram.bytes)).collect();
                    ready!(QuicProtocol::global().poll_send(cx, self.pathway, &buffers))?
                };
                for datagram in &mut datagrams[first..first + sent] {
                    let mut packets = [None; 3];
                    for meta in datagram.packets.drain(..) {
                        let epoch = meta.epoch();
                        if let Some(space) = self.spaces.get(epoch) {
                            space.on_sent(meta.pn, meta.in_flight, deadlines[epoch].0, deadlines[epoch].1);
                        }
                        sent_handshake |= epoch == Epoch::Handshake;
                        packets[epoch] = Some(meta);
                    }
                    let _ = idle_timer.on_sent_at(Instant::now());
                    self.on_sent(&mut cc, datagram.bytes.len(), packets);
                }
                update_amplification_blocked(
                    &mut cc,
                    &self.spaces,
                    dcid,
                    self.validation.credit().map_or(0, |credit| credit.unwrap_or(usize::MAX)),
                    overhead,
                );
                Poll::Ready(Ok(Some(sent)))
            })
            .await
            .map_err(|error| QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string()))?;
            let Some(sent) = sent else { return Ok(()) };
            if sent_handshake {
                self.progress.on_handshake_sent();
            }
            if sent == 0 {
                return Err(QuicError::with_default_fty(ErrorKind::NoViablePath, "UDP submitted zero datagrams").into());
            }
            first += sent;
        }
        Ok(())
    }

    /// Recover unsubmitted packets in live spaces, then reuse buffers and release the CID.
    pub fn refresh(&self, datagrams: &mut [Datagram], frames: &mut Vec<GuaranteedFrame>) {
        for datagram in datagrams {
            for meta in datagram.packets.drain(..) {
                if let Some(space) = self.spaces.get(meta.epoch()) {
                    space.cancel(meta.pn, &mut std::iter::empty());
                }
            }
            datagram.bytes.clear();
        }
        frames.clear();
        self.cc.on_burst_completed();
        self.dcid.refresh();
    }
}

/// Refresh the amplification budget while holding the path's CC lock.
fn update_amplification_blocked(cc: &mut CongestionController, spaces: &ArcSpaces, dcid: ConnectionId, credit: usize, overhead: usize) {
    let epoch = cc.pto_epoch();
    let blocked = match credit {
        0 => true,
        usize::MAX => false,
        _ => {
            epoch.and_then(|epoch| spaces.get(epoch)).and_then(|space| space.probe_size(dcid)).is_some_and(|size| credit < size + overhead)
        }
    };
    cc.set_amplification_blocked(blocked);
}
