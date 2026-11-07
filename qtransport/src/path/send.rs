use std::{
    future::poll_fn,
    io::Cursor,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    frame::{GuaranteedFrame, PingFrame},
    packet::{Package, PacketContent, assemble::Metadata},
};
use qcongestion::{CongestionController, Transport as _};
use qprotocol::QuicProtocol;
use smallvec::SmallVec;

use super::Path;
use crate::{
    Error,
    space::{ArcSpaces, Encapsulate},
};

/// A UDP datagram and the QUIC packets awaiting submission within it.
#[derive(Default)]
pub struct Datagram {
    pub bytes: BytesMut,
    pub packets: SmallVec<[(Arc<dyn Encapsulate>, Metadata); 1]>,
}

impl Path {
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

    /// Recover only unsubmitted packets, then reuse the buffers and release the CID.
    pub fn refresh(&self, datagrams: &mut [Datagram], frames: &mut Vec<GuaranteedFrame>) {
        for datagram in datagrams {
            for (space, meta) in datagram.packets.drain(..) {
                space.cancel(meta.pn, &mut std::iter::empty());
            }
            datagram.bytes.clear();
        }
        frames.clear();
        self.dcid.refresh();
    }

    fn poll_collect(
        &self,
        cx: &mut Context<'_>,
        dcid: ConnectionId,
        datagrams: &mut [Datagram],
        frames: &mut Vec<GuaranteedFrame>,
    ) -> Poll<Result<usize, Error>> {
        // Read later epochs first so concurrent prefix retirement cannot leave a hole.
        let handles: SmallVec<[_; 3]> = Epoch::EPOCHS.into_iter().rev().filter_map(|epoch| self.spaces.get(epoch)).collect();
        let spaces = ArcSpaces::default();
        match handles.last().map(|space| space.epoch()) {
            Some(Epoch::Handshake) => spaces.retire(Epoch::Initial),
            Some(Epoch::Data) => spaces.retire(Epoch::Handshake),
            _ => {}
        }
        for space in handles.into_iter().rev() {
            spaces.add(space);
        }
        let mut credit = match self.validation.poll_credit(cx) {
            Poll::Ready(credit) => {
                credit.map_err(|error| QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string()))?.unwrap_or(usize::MAX)
            }
            Poll::Pending => 0,
        };
        let overhead = QuicProtocol::packet_overhead(self.pathway);
        let mut send_quota = {
            let mut cc = self.cc.lock();
            // Update the budget before driving PTO, including when credit polling waits.
            update_amplification_blocked(&mut cc, &spaces, dcid, credit, overhead);
            if credit == 0 {
                ready!(cc.poll_send_quota(cx)).map_err(|error| QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string()))?;
                drop(cc);
                self.cc.cancel(cx.waker());
                return Poll::Pending;
            }
            ready!(cc.poll_send_quota(cx)).map_err(|error| QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string()))?
        };
        let packet_content = if self.is_active() {
            PacketContent::EffectivePayload
        } else {
            PacketContent::JustPing
        };
        let handles = Epoch::EPOCHS.map(|epoch| spaces.get(epoch));
        let mut acks = Epoch::EPOCHS
            .map(|epoch| (epoch, handles[epoch].as_ref().map(|space| space.rcvd_journal().ack_package(self.cc.need_ack(epoch)))));
        let mut terminator = &self.terminator;
        let mut heartbeat = self.heartbeat.clone();
        let mut validation = self.validation.clone();
        let mut probes = Epoch::EPOCHS.map(|epoch| {
            (epoch, (packet_content == PacketContent::EffectivePayload && self.cc.need_send_ack_eliciting(epoch) > 0).then_some(PingFrame))
        });
        let mut count = 0;
        for datagram in datagrams {
            let buffer = &mut datagram.bytes;
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
                spaces.poll_dump(cx, &self.cc, dcid, &mut Cursor::new(buffer.as_mut()), packet_content, frames, external);
            let in_flight: usize = collected.iter().filter(|meta| meta.in_flight).map(|meta| meta.pktlen).sum();
            datagram.packets.extend(collected.into_iter().map(|meta| (spaces.get(meta.epoch()).unwrap(), meta)));
            buffer.truncate(size);
            if size == 0 {
                break;
            }
            credit -= size + overhead;
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
            Poll::Ready(Ok(count))
        }
    }
}

/// Refresh the amplification budget while holding the path's CC lock.
pub fn update_amplification_blocked(cc: &mut CongestionController, spaces: &ArcSpaces, dcid: ConnectionId, credit: usize, overhead: usize) {
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
