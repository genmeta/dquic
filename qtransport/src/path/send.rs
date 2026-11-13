use std::{
    future::poll_fn,
    io::{self, IoSlice},
    task::{Context, Poll, Waker, ready},
};

use bytes::BytesMut;
use qbase::{
    Epoch,
    cid::ConnectionId,
    frame::GuaranteedFrame,
    packet::{Package, PacketContent, assemble::Metadata},
    time::timer::ArcIdleTimer,
};
use qcongestion::Transport as _;
use qprotocol::QuicProtocol;
use smallvec::SmallVec;
use tokio::time::Instant;

use super::Path;

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
    ) -> Poll<io::Result<usize>> {
        let mut credit = match self.validation.poll_credit(cx) {
            Poll::Ready(credit) => credit.map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))?,
            Poll::Pending => {
                self.cc.cancel();
                return Poll::Pending;
            }
        };
        let overhead = QuicProtocol::datagram_overhead(self.pathway);
        self.cc.prepare_burst_budget(cx)?;
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
            let length = credit.map_or(1200, |credit| 1200.min(credit.saturating_sub(overhead)));
            buffer.resize(length, 0);
            let (size, packets) =
                self.spaces.poll_dump(cx, &self.cc, overhead, dcid, buffer.as_mut(), packet_content, frames, &mut sources);
            datagram.packets.extend(packets);
            buffer.truncate(size);
            if size == 0 {
                break;
            }
            if let Some(credit) = &mut credit {
                *credit -= size + overhead;
            }
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
    pub async fn collect(&self, datagrams: &mut [Datagram], frames: &mut Vec<GuaranteedFrame>) -> io::Result<(usize, ConnectionId)> {
        poll_fn(|cx| {
            self.send_waker.register(cx.waker());
            let waker = Waker::from(self.send_waker.clone());
            let cx = &mut Context::from_waker(&waker);
            let result = (|| {
                if self.validation.is_cancelled() {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "path retired")));
                }
                let dcid = ready!(self.dcid.poll_borrow(cx))
                    .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "path CID binding retired"))?;
                let result = self.poll_collect(cx, dcid, datagrams, frames);
                if result.is_pending() {
                    self.dcid.refresh();
                }
                result.map(|result| result.map(|count| (count, dcid)))
            })();
            if result.is_ready() {
                self.cc.cancel();
            }
            self.send_waker.refresh(result.is_ready());
            result
        })
        .await
    }

    /// Register submitted packets under the CC lock, then debit validation credit.
    pub(crate) async fn send(&self, datagrams: &mut [Datagram], idle_timer: &ArcIdleTimer) -> io::Result<()> {
        let overhead = QuicProtocol::datagram_overhead(self.pathway);
        let deadlines = Epoch::EPOCHS.map(|epoch| (self.cc.retransmit_and_expire_time(epoch).0, self.cc.pto_base(epoch) * 3));
        let mut first = 0;
        while first < datagrams.len() {
            let mut sent_handshake = false;
            let sent = poll_fn(|cx| -> Poll<io::Result<Option<usize>>> {
                let mut waiter = self.io_waker.lock().unwrap();
                *waiter = None;
                // ACK handling takes the same lock as submission and completion.
                let mut cc = self.cc.lock();
                self.validation.credit().map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))?;
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
                    match QuicProtocol::global().poll_send(cx, self.pathway, &buffers) {
                        Poll::Ready(sent) => sent?,
                        Poll::Pending => {
                            *waiter = Some(cx.waker().clone());
                            return Poll::Pending;
                        }
                    }
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
                    self.on_sent(&mut cc, packets);
                }
                Poll::Ready(Ok(Some(sent)))
            })
            .await?;
            let Some(sent) = sent else { return Ok(()) };
            // Validation callbacks can acquire CC now that submission has released it.
            self.validation.on_sent(datagrams[first..first + sent].iter().map(|datagram| datagram.bytes.len() + overhead).sum());
            if sent_handshake {
                self.progress.on_handshake_sent();
            }
            if sent == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "UDP submitted zero datagrams"));
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
        self.cc.refresh_budget();
        self.dcid.refresh();
    }
}
