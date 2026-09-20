//! Per-path, multi-space packet assembly and batched UDP submission.
pub mod constraints;
pub mod records;
pub mod write;

use std::{
    collections::VecDeque,
    io::{self, IoSlice},
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::BytesMut;
use constraints::{AntiAmplifier, Constraints};
use qbase::{
    Epoch,
    error::{ErrorKind, QuicError},
    flow::ArcSendControler,
    frame::AckFrame,
    net::{
        route::Pathway,
        tx::{ArcSendWaker, Signals},
    },
    packet::{
        GetType, HandshakeHeader, HeaderSize, InitialHeader, OneRttHeader, Package, Type,
        ZeroRttHeader, header::io::WriteHeader,
    },
    param::ParameterId,
    varint::{VARINT_MAX, VarInt},
};
use qcongestion::{ArcCC, Transport as _};
use qprotocol::protocol::quic::QuicProtocol;
use records::ArcSendJournal;
use write::{Packet, PacketError, PacketWriter, PendingPacket};

use crate::{Error, GuaranteedFrame, ReliableFrames, keys::OneRttKeys, path::Path};

pub struct Sender {
    protocol: Arc<QuicProtocol>,
    pub pathway: Pathway,
    pub congestion: ArcCC,
    pub flow: ArcSendControler<ReliableFrames>,
    anti_amplifier: Arc<AntiAmplifier>,
    send_waker: ArcSendWaker,
    buffers: Vec<BytesMut>,
    frames: Vec<GuaranteedFrame>,
    pending: VecDeque<PendingPacket>,
    signals: Signals,
}

impl Sender {
    pub fn new(
        protocol: Arc<QuicProtocol>,
        pathway: Pathway,
        congestion: ArcCC,
        flow: ArcSendControler<ReliableFrames>,
        anti_amplifier: Arc<AntiAmplifier>,
        send_waker: ArcSendWaker,
    ) -> Self {
        Self {
            protocol,
            pathway,
            congestion,
            flow,
            anti_amplifier,
            send_waker,
            buffers: Vec::new(),
            frames: Vec::new(),
            pending: VecDeque::new(),
            signals: Signals::all(),
        }
    }

    /// Already assembled intents can be excluded from the next packet in this burst.
    pub fn pending(&self) -> impl Iterator<Item = &PendingPacket> {
        self.pending.iter()
    }

    pub fn assemble_initial_packet<const N: usize>(
        &mut self,
        keys: &qtls::DirectionalKeys,
        header: InitialHeader,
        journal: &ArcSendJournal,
        constraints: &Constraints,
        sources: [&mut dyn for<'a> Package<PacketWriter<'a>>; N],
    ) -> Result<Option<PendingPacket>, Error> {
        self.assemble(
            header,
            keys.packet.tag_len(),
            journal,
            constraints,
            sources,
            |packet, records| {
                let (pn, encoded) = journal.record_pending(None, records)?;
                finish_sealing(packet.seal_long(keys, pn, encoded), pn, journal, records)
            },
        )
    }

    pub fn assemble_handshake_packet<const N: usize>(
        &mut self,
        keys: &qtls::DirectionalKeys,
        header: HandshakeHeader,
        journal: &ArcSendJournal,
        constraints: &Constraints,
        sources: [&mut dyn for<'a> Package<PacketWriter<'a>>; N],
    ) -> Result<Option<PendingPacket>, Error> {
        self.assemble(
            header,
            keys.packet.tag_len(),
            journal,
            constraints,
            sources,
            |packet, records| {
                let (pn, encoded) = journal.record_pending(None, records)?;
                finish_sealing(packet.seal_long(keys, pn, encoded), pn, journal, records)
            },
        )
    }

    pub fn assemble_0rtt_packet<const N: usize>(
        &mut self,
        keys: &qtls::DirectionalKeys,
        header: ZeroRttHeader,
        journal: &ArcSendJournal,
        constraints: &Constraints,
        sources: [&mut dyn for<'a> Package<PacketWriter<'a>>; N],
    ) -> Result<Option<PendingPacket>, Error> {
        self.assemble(
            header,
            keys.packet.tag_len(),
            journal,
            constraints,
            sources,
            |packet, records| {
                let (pn, encoded) = journal.record_pending(None, records)?;
                finish_sealing(packet.seal_long(keys, pn, encoded), pn, journal, records)
            },
        )
    }

    pub fn assemble_1rtt_packet<const N: usize>(
        &mut self,
        keys: &OneRttKeys,
        header: OneRttHeader,
        journal: &ArcSendJournal,
        constraints: &Constraints,
        sources: [&mut dyn for<'a> Package<PacketWriter<'a>>; N],
    ) -> Result<Option<PendingPacket>, Error> {
        self.assemble(
            header,
            keys.tag_len(),
            journal,
            constraints,
            sources,
            |packet, records| {
                let ((pn, encoded), key) =
                    keys.reserve(|generation| journal.record_pending(generation, records))?;
                finish_sealing(packet.seal(&key, pn, encoded), pn, journal, records)
            },
        )
    }

    fn assemble<H: HeaderSize + GetType, const N: usize>(
        &mut self,
        header: H,
        tag_len: usize,
        journal: &ArcSendJournal,
        constraints: &Constraints,
        sources: [&mut dyn for<'a> Package<PacketWriter<'a>>; N],
        seal: impl FnOnce(Packet, &mut Vec<GuaranteedFrame>) -> Result<PendingPacket, PacketError>,
    ) -> Result<Option<PendingPacket>, Error>
    where
        for<'b> &'b mut [u8]: WriteHeader<H>,
    {
        if !journal.has_capacity() {
            self.signals |= Signals::TRANSPORT;
            return Ok(None);
        }
        let packet_type = header.get_type();
        let epoch = write::epoch(packet_type);
        let overhead = QuicProtocol::packet_overhead(self.pathway);
        let probes = self.congestion.need_send_ack_eliciting(epoch);
        let reserved_probes = self
            .pending
            .iter()
            .filter(|p| p.epoch() == epoch && p.content.is_ack_eliciting())
            .count();
        let constraints = Constraints {
            capacity: constraints.capacity.saturating_sub(overhead),
            congestion: constraints
                .congestion
                .max(if reserved_probes < probes { 1200 } else { 0 })
                .saturating_sub(overhead),
            anti_amplification: constraints.anti_amplification.saturating_sub(overhead),
        };
        let length_size = if matches!(packet_type, Type::Long(_)) {
            2
        } else {
            0
        };
        if constraints.capacity.min(constraints.anti_amplification)
            <= header.size() + length_size + 4 + tag_len
        {
            self.signals |= Signals::CREDIT;
            return Ok(None);
        }
        let mut buffer = self.buffers.pop().unwrap_or_default();
        buffer.resize(constraints.capacity, 0);
        let mut packet = Packet::new(buffer, header, tag_len).map_err(packet_error)?;
        let result = packet
            .assemble_pending(
                &constraints,
                &mut self.frames,
                sources,
                self.pending.make_contiguous(),
            )
            .and_then(|_| {
                if epoch == Epoch::Initial || packet.has_path_frames() {
                    packet.pad_to(1200 - overhead, &constraints)?;
                }
                Ok(())
            });
        if let Err(error) = result {
            for frame in self.frames.drain(..) {
                journal.recover(&frame);
            }
            self.buffers.push(packet.into_buffer());
            return match error {
                PacketError::Blocked(signals) => {
                    self.signals |= signals;
                    Ok(None)
                }
                error => Err(packet_error(error)),
            };
        }
        match seal(packet, &mut self.frames) {
            Ok(packet) => Ok(Some(packet)),
            Err(error) => {
                for frame in self.frames.drain(..) {
                    journal.recover(&frame);
                }
                match error {
                    PacketError::Blocked(signals) => {
                        self.signals |= signals;
                        Ok(None)
                    }
                    error => Err(packet_error(error)),
                }
            }
        }
    }

    /// Assemble a bounded burst. The closure captures ready space components and
    /// skips missing keys synchronously; None means all eligible sources were tried.
    pub fn burst(
        &mut self,
        mut assemble: impl FnMut(&mut Self, &Constraints) -> Result<Option<PendingPacket>, Error>,
    ) -> Result<usize, Error> {
        if !self.pending.is_empty() {
            return Ok(self.pending.len());
        }
        self.signals = Signals::TRANSPORT | Signals::KEYS | Signals::PATH_VALIDATE | Signals::PING;
        let mut constraints = Constraints {
            capacity: 1200,
            congestion: self.congestion.send_quota().unwrap_or_else(|signals| {
                self.signals |= signals;
                0
            }),
            anti_amplification: self.anti_amplifier.balance(),
        };
        while self.pending.len() < QuicProtocol::MAX_DATAGRAMS {
            let Some(packet) = assemble(self, &constraints)? else {
                break;
            };
            let wire_len = packet.bytes().len() + QuicProtocol::packet_overhead(self.pathway);
            constraints.anti_amplification =
                constraints.anti_amplification.saturating_sub(wire_len);
            if packet.in_flight {
                constraints.congestion = constraints.congestion.saturating_sub(wire_len);
            }
            self.pending.push_back(packet);
        }
        Ok(self.pending.len())
    }

    /// Confirm the accepted prefix before running callbacks for submitted packets.
    pub fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        allowed: impl Fn(Type) -> bool,
        on_sent: impl FnMut(&PendingPacket),
    ) -> Poll<Result<usize, Error>> {
        let protocol = self.protocol.clone();
        self.poll_send_with(
            cx,
            |cx, pathway, packets| protocol.poll_send(cx, pathway, packets),
            allowed,
            on_sent,
        )
    }

    pub(crate) fn poll_send_with(
        &mut self,
        cx: &mut Context<'_>,
        mut submit: impl FnMut(&mut Context<'_>, Pathway, &[IoSlice<'_>]) -> Poll<io::Result<usize>>,
        allowed: impl Fn(Type) -> bool,
        mut on_sent: impl FnMut(&PendingPacket),
    ) -> Poll<Result<usize, Error>> {
        for _ in 0..self.pending.len() {
            let packet = self.pending.pop_front().unwrap();
            if allowed(packet.packet_type) {
                self.pending.push_back(packet);
            } else {
                self.buffers.push(packet.into_buffer());
            }
        }
        if self.pending.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut credit = self.anti_amplifier.balance();
        let mut congestion = self.congestion.send_quota().unwrap_or(0);
        let mut probes = Epoch::EPOCHS.map(|epoch| self.congestion.need_send_ack_eliciting(epoch));
        let mut count = 0;
        for packet in &self.pending {
            let length = packet.bytes().len() + QuicProtocol::packet_overhead(self.pathway);
            if length > credit
                || (packet.in_flight
                    && length > congestion
                    && !(packet.content.is_ack_eliciting() && probes[packet.epoch()] > 0))
            {
                break;
            }
            credit -= length;
            if packet.in_flight {
                congestion = congestion.saturating_sub(length);
            }
            if packet.content.is_ack_eliciting() {
                probes[packet.epoch()] = probes[packet.epoch()].saturating_sub(1);
            }
            count += 1;
        }
        if count == 0 {
            self.signals |= Signals::CREDIT | Signals::CONGESTION;
            return Poll::Ready(Ok(0));
        }
        // Stack-backed iovecs; no per-burst allocation for the submission view.
        let mut packets = [IoSlice::new(&[]); QuicProtocol::MAX_DATAGRAMS];
        for (slot, packet) in packets.iter_mut().zip(self.pending.iter()).take(count) {
            *slot = IoSlice::new(packet.bytes());
        }
        let journals = Epoch::EPOCHS.map(|epoch| {
            self.pending
                .iter()
                .take(count)
                .find(|packet| packet.epoch() == epoch)
                .and_then(|packet| packet.journal.clone())
        });
        let deadlines = Epoch::EPOCHS.map(|epoch| {
            let (delay, _) = self.congestion.retransmit_and_expire_time(epoch);
            (delay, self.congestion.pto_base(epoch) * 3)
        });
        let submitted = {
            // CC -> journals, in epoch order. ACK and loss feedback use the same order.
            let mut congestion = self.congestion.lock();
            let mut records = journals
                .each_ref()
                .map(|journal| journal.as_ref().map(ArcSendJournal::lock_guard));
            let result = submit(cx, self.pathway, &packets[..count]);
            if let Poll::Ready(Ok(sent)) = &result {
                assert!(*sent <= count);
                for packet in self.pending.iter_mut().take(*sent) {
                    let epoch = packet.epoch();
                    let length = packet.bytes().len() + QuicProtocol::packet_overhead(self.pathway);
                    let (delay, retention) = deadlines[epoch];
                    records[epoch].as_mut().unwrap().mark_sent(
                        packet.pn,
                        packet.in_flight,
                        delay,
                        retention,
                    );
                    packet.journal = None;
                    self.anti_amplifier.on_sent(length);
                    congestion.on_pkt_sent(
                        epoch,
                        packet.pn,
                        packet.content.is_ack_eliciting(),
                        length,
                        packet.in_flight,
                        packet.largest_acked,
                    );
                }
            }
            result
        };
        let sent = match submitted {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(0)) => {
                self.cancel_pending();
                return Poll::Ready(Err(QuicError::with_default_fty(
                    ErrorKind::NoViablePath,
                    "UDP submitted zero datagrams",
                )
                .into()));
            }
            Poll::Ready(Ok(sent)) => sent,
            Poll::Ready(Err(error)) => {
                self.cancel_pending();
                return Poll::Ready(Err(QuicError::with_default_fty(
                    ErrorKind::NoViablePath,
                    error.to_string(),
                )
                .into()));
            }
        };
        // Callbacks may stop spaces or retire paths; no component guard remains held.
        for _ in 0..sent {
            let packet = self.pending.pop_front().unwrap();
            on_sent(&packet);
            self.buffers.push(packet.into_buffer());
        }
        Poll::Ready(Ok(sent))
    }

    pub fn cancel_pending(&mut self) {
        while let Some(packet) = self.pending.pop_front() {
            self.buffers.push(packet.into_buffer());
        }
    }

    /// Wait for the conditions that blocked the last burst, without waking on unrelated credit.
    pub async fn wait(&self) {
        self.send_waker.wait_for(self.signals).await;
    }

    /// The caller's closures capture the spaces, keys and source components.
    pub async fn run(
        &mut self,
        mut assemble: impl FnMut(&mut Self, &Constraints) -> Result<Option<PendingPacket>, Error>,
        active: impl Fn() -> bool,
        allowed: impl Fn(Type) -> bool,
        mut on_sent: impl FnMut(&PendingPacket),
    ) -> Result<(), Error> {
        while active() {
            self.congestion.do_tick().map_err(|error| {
                QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string())
            })?;
            if self.burst(&mut assemble)? != 0 {
                let wake = self.send_waker.clone();
                let signals = self.signals;
                let sent = tokio::select! {
                    result = std::future::poll_fn(|cx| self.poll_send(cx, &allowed, &mut on_sent)) => result?,
                    _ = wake.wait_for(signals) => continue,
                    _ = tokio::time::sleep(Duration::from_millis(10)) => continue,
                };
                if sent != 0 {
                    tokio::task::yield_now().await;
                    continue;
                }
            }
            tokio::select! {
                _ = self.wait() => {},
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
        self.cancel_pending();
        Ok(())
    }
}

/// Attach submission cleanup only after sealing succeeds; undo a failed reservation here.
pub(crate) fn finish_sealing(
    result: Result<PendingPacket, PacketError>,
    pn: u64,
    journal: &ArcSendJournal,
    records: &mut Vec<GuaranteedFrame>,
) -> Result<PendingPacket, PacketError> {
    match result {
        Ok(mut packet) => {
            packet.journal = Some(journal.clone());
            Ok(packet)
        }
        Err(error) => {
            journal.cancel_pending(pn, records);
            Err(error)
        }
    }
}

fn packet_error(error: PacketError) -> Error {
    match error {
        PacketError::Connection(error) => error,
        error => QuicError::with_default_fty(ErrorKind::Internal, error.to_string()).into(),
    }
}

/// Data ACK pipe target. Capture the original components before Transport is created.
/// Lock the receiving path CC before the journal, so ACK observes committed sends.
/// Report acknowledged generations to the receive task's ready OneRttKeys.
pub fn acknowledge(
    data: &crate::space::Space<crate::keys::ArcOneRttKeys>,
    streams: &qrecovery::streams::DataStreams<crate::ReliableFrames>,
    parameters: &crate::ArcParameters,
    ack: &AckFrame,
    received_on: &Arc<Path>,
    on_ack: impl Fn(u64),
) -> Result<(), Error> {
    let acknowledged = {
        let mut congestion = received_on.cc.lock();
        let exponent: u64 = parameters.remote(ParameterId::AckDelayExponent).unwrap();
        let delay = ack
            .delay()
            .checked_shl(exponent as u32)
            .unwrap_or(VARINT_MAX)
            .min(VARINT_MAX);
        let acknowledged = data.send_journal.acknowledge(ack, |frame| match frame {
            GuaranteedFrame::Crypto(frame) => data.crypto.outgoing().on_data_acked(frame),
            GuaranteedFrame::Stream(frame) => streams.on_data_acked(*frame),
            GuaranteedFrame::Reliable(qbase::frame::ReliableFrame::StreamCtl(
                qbase::frame::StreamCtlFrame::ResetStream(frame),
            )) => streams.on_reset_acked(*frame),
            _ => {}
        })?;
        let ack = AckFrame::new(
            VarInt::from_u64(ack.largest()).unwrap(),
            VarInt::from_u64(delay).unwrap(),
            VarInt::from_u64(ack.first_range()).unwrap(),
            ack.ranges().clone(),
            ack.ecn(),
        );
        congestion.on_ack_rcvd(Epoch::Data, &ack, tokio::time::Instant::now());
        acknowledged
    };
    for generation in acknowledged {
        on_ack(generation);
    }
    received_on
        .send_waker
        .wake_by(Signals::CONGESTION | Signals::TRANSPORT);
    Ok(())
}

#[cfg(test)]
mod tests;
