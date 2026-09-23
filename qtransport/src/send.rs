//! Per-path, multi-space packet assembly and batched UDP submission.
pub mod constraints;
pub mod records;
pub mod write;

use std::{
    collections::VecDeque,
    io::{self, IoSlice},
    sync::Arc,
    task::{Context, Poll},
};

use bytes::BytesMut;
use constraints::{AntiAmplifier, Constraints};
use qbase::{
    Epoch,
    datagram::{GetDatagramType, WriteDatagramType},
    error::{ErrorKind, QuicError},
    frame::AckFrame,
    net::{
        AddrFamily,
        route::{Pathway, WritePathway},
        tx::Signals,
    },
    packet::{GetType, HeaderSize, OneRttHeader, Package, Type, header::io::WriteHeader},
    param::ParameterId,
    varint::{VARINT_MAX, VarInt},
};
use qcongestion::{ArcCC, Transport as _};
use qprotocol::protocol::quic::QuicProtocol;
use records::ArcSendJournal;
use write::{Packet, PacketError, PacketWriter, PendingPacket};

use crate::{Error, GuaranteedFrame, keys::OneRttKeys, path::Path};

/// Maximum number of datagrams prepared in one sending iteration.
pub const MAX_BURST_PACKETS: usize = 8;

#[expect(
    clippy::too_many_arguments,
    reason = "batch storage belongs to the sending task"
)]
pub fn assemble_long_packet<H: HeaderSize + GetType, const N: usize>(
    pathway: Pathway,
    congestion: &ArcCC,
    buffers: &mut Vec<BytesMut>,
    send_frames: &mut Vec<GuaranteedFrame>,
    pns: &mut VecDeque<PendingPacket>,
    signals: &mut Signals,
    keys: &qtls::DirectionalKeys,
    header: H,
    journal: &ArcSendJournal,
    constraints: &Constraints,
    sources: [&mut dyn for<'a> Package<PacketWriter<'a>>; N],
) -> Result<Option<PendingPacket>, Error>
where
    for<'b> &'b mut [u8]: WriteHeader<H>,
{
    assemble(
        pathway,
        congestion,
        buffers,
        send_frames,
        pns,
        signals,
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

#[expect(
    clippy::too_many_arguments,
    reason = "batch storage belongs to the sending task"
)]
pub fn assemble_1rtt_packet<const N: usize>(
    pathway: Pathway,
    congestion: &ArcCC,
    buffers: &mut Vec<BytesMut>,
    send_frames: &mut Vec<GuaranteedFrame>,
    pns: &mut VecDeque<PendingPacket>,
    signals: &mut Signals,
    keys: &OneRttKeys,
    header: OneRttHeader,
    journal: &ArcSendJournal,
    constraints: &Constraints,
    sources: [&mut dyn for<'a> Package<PacketWriter<'a>>; N],
) -> Result<Option<PendingPacket>, Error> {
    assemble(
        pathway,
        congestion,
        buffers,
        send_frames,
        pns,
        signals,
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

#[expect(
    clippy::too_many_arguments,
    reason = "batch storage belongs to the sending task"
)]
fn assemble<H: HeaderSize + GetType, const N: usize>(
    pathway: Pathway,
    congestion: &ArcCC,
    buffers: &mut Vec<BytesMut>,
    send_frames: &mut Vec<GuaranteedFrame>,
    pns: &mut VecDeque<PendingPacket>,
    signals: &mut Signals,
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
        *signals |= Signals::TRANSPORT;
        return Ok(None);
    }
    let packet_type = header.get_type();
    let epoch = write::epoch(packet_type);
    let overhead = QuicProtocol::packet_overhead(pathway);
    let probes = congestion.need_send_ack_eliciting(epoch);
    let reserved_probes = pns
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
        *signals |= Signals::CREDIT;
        return Ok(None);
    }
    let mut buffer = buffers.pop().unwrap_or_default();
    buffer.resize(constraints.capacity, 0);
    let mut packet = Packet::new(buffer, header, tag_len).map_err(packet_error)?;
    let result = packet
        .assemble_pending(&constraints, send_frames, sources, pns.make_contiguous())
        .and_then(|_| {
            if epoch == Epoch::Initial || packet.has_path_frames() {
                packet.pad_to(1200 - overhead, &constraints)?;
            }
            Ok(())
        });
    if let Err(error) = result {
        for frame in send_frames.drain(..) {
            journal.recover(&frame);
        }
        buffers.push(packet.into_buffer());
        return match error {
            PacketError::Blocked(blocked) => {
                *signals |= blocked;
                Ok(None)
            }
            error => Err(packet_error(error)),
        };
    }
    match seal(packet, send_frames) {
        Ok(mut packet) => {
            if overhead != 0 {
                let source = pathway.local();
                let destination = pathway.remote();
                if source.family() != destination.family() {
                    return Err(QuicError::with_default_fty(
                        ErrorKind::NoViablePath,
                        "incompatible Pathway address families",
                    )
                    .into());
                }
                let length = packet.datagram.msg.len();
                packet.datagram.msg.resize(length + overhead, 0);
                packet.datagram.msg.copy_within(..length, overhead);
                let mut header = &mut packet.datagram.msg[..overhead];
                header.put_datagram_type(&pathway.get_datagram_type());
                header.put_pathway(&pathway);
                packet.datagram.raw_offset = overhead;
            }
            Ok(Some(packet))
        }
        Err(error) => {
            for frame in send_frames.drain(..) {
                journal.recover(&frame);
            }
            match error {
                PacketError::Blocked(blocked) => {
                    *signals |= blocked;
                    Ok(None)
                }
                error => Err(packet_error(error)),
            }
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "batch storage belongs to the sending task"
)]
pub fn poll_send_with(
    pathway: Pathway,
    congestion: &ArcCC,
    anti_amplifier: &AntiAmplifier,
    buffers: &mut Vec<BytesMut>,
    pns: &mut VecDeque<PendingPacket>,
    signals: &mut Signals,
    cx: &mut Context<'_>,
    packets: &mut Vec<IoSlice<'static>>,
    mut submit: impl FnMut(&mut Context<'_>, Pathway, &[IoSlice<'_>]) -> Poll<io::Result<usize>>,
    allowed: impl Fn(Type) -> bool,
    mut on_sent: impl FnMut(&PendingPacket),
) -> Poll<Result<usize, Error>> {
    for _ in 0..pns.len() {
        let packet = pns.pop_front().unwrap();
        if allowed(packet.packet_type) {
            pns.push_back(packet);
        } else {
            buffers.push(packet.into_buffer());
        }
    }
    if pns.is_empty() {
        return Poll::Ready(Ok(0));
    }
    let mut credit = anti_amplifier.balance();
    let mut quota = congestion.send_quota().unwrap_or(0);
    let mut probes = Epoch::EPOCHS.map(|epoch| congestion.need_send_ack_eliciting(epoch));
    let mut count = 0;
    for packet in pns.iter() {
        let length = packet.bytes().len() + QuicProtocol::packet_overhead(pathway);
        if length > credit
            || (packet.in_flight
                && length > quota
                && !(packet.content.is_ack_eliciting() && probes[packet.epoch()] > 0))
        {
            break;
        }
        credit -= length;
        if packet.in_flight {
            quota = quota.saturating_sub(length);
        }
        if packet.content.is_ack_eliciting() {
            probes[packet.epoch()] = probes[packet.epoch()].saturating_sub(1);
        }
        count += 1;
    }
    if count == 0 {
        *signals |= Signals::CREDIT | Signals::CONGESTION;
        return Poll::Ready(Ok(0));
    }
    // The vector is empty between submissions. Consuming its empty iterator
    // reuses its allocation while giving the views this submission's lifetime.
    let mut datagrams: Vec<IoSlice<'_>> = std::mem::take(packets)
        .into_iter()
        .map(|_| unreachable!())
        .collect();
    datagrams.extend(
        pns.iter()
            .take(count)
            .map(|packet| IoSlice::new(&packet.datagram.msg)),
    );
    let journals = Epoch::EPOCHS.map(|epoch| {
        pns.iter()
            .take(count)
            .find(|packet| packet.epoch() == epoch)
            .and_then(|packet| packet.journal.clone())
    });
    let deadlines = Epoch::EPOCHS.map(|epoch| {
        let (delay, _) = congestion.retransmit_and_expire_time(epoch);
        (delay, congestion.pto_base(epoch) * 3)
    });
    let submitted = {
        // CC -> journals, in epoch order. ACK and loss feedback use the same order.
        let mut congestion = congestion.lock();
        let mut records = journals
            .each_ref()
            .map(|journal| journal.as_ref().map(ArcSendJournal::lock_guard));
        let result = submit(cx, pathway, &datagrams);
        datagrams.clear();
        *packets = datagrams.into_iter().map(|_| unreachable!()).collect();
        if let Poll::Ready(Ok(sent)) = &result {
            assert!(*sent <= count);
            for packet in pns.iter_mut().take(*sent) {
                let epoch = packet.epoch();
                let length = packet.bytes().len() + QuicProtocol::packet_overhead(pathway);
                let (delay, retention) = deadlines[epoch];
                records[epoch].as_mut().unwrap().mark_sent(
                    packet.pn,
                    packet.in_flight,
                    delay,
                    retention,
                );
                packet.journal = None;
                anti_amplifier.on_sent(length);
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
            buffers.extend(pns.drain(..).map(PendingPacket::into_buffer));
            return Poll::Ready(Err(QuicError::with_default_fty(
                ErrorKind::NoViablePath,
                "UDP submitted zero datagrams",
            )
            .into()));
        }
        Poll::Ready(Ok(sent)) => sent,
        Poll::Ready(Err(error)) => {
            buffers.extend(pns.drain(..).map(PendingPacket::into_buffer));
            return Poll::Ready(Err(QuicError::with_default_fty(
                ErrorKind::NoViablePath,
                error.to_string(),
            )
            .into()));
        }
    };
    // Callbacks may stop spaces or retire paths; no component guard remains held.
    for _ in 0..sent {
        let packet = pns.pop_front().unwrap();
        on_sent(&packet);
        buffers.push(packet.into_buffer());
    }
    Poll::Ready(Ok(sent))
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
        let exponent: u64 = parameters.remote(ParameterId::AckDelayExponent);
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

#[cfg(test)]
pub(crate) mod fixture;
