//! Historical packet fixtures for receive/recovery regression tests.
//! Production assembly and submission live in qconnection::send.
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
    },
    packet::{GetType, HeaderSize, OneRttHeader, Package, Type, header::io::WriteHeader},
    varint::VarInt,
};
use qcongestion::{ArcCC, Transport as _};
use qprotocol::protocol::quic::QuicProtocol;
use records::ArcSentJournal;
use write::{Packet, PacketError, PendingPacket};

use crate::{
    Error, GuaranteedFrame,
    keys::OneRttKeys,
    path::Path,
    space::{DataSpace, Recover},
};

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
    keys: &qtls::DirectionalKeys,
    header: H,
    journal: &ArcSentJournal,
    recovery: &Option<Arc<DataSpace>>,
    constraints: &Constraints,
    sources: [&mut dyn for<'a> Package<&'a mut [u8]>; N],
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
        header,
        keys.packet.tag_len(),
        journal,
        recovery,
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
    keys: &OneRttKeys,
    header: OneRttHeader,
    journal: &ArcSentJournal,
    recovery: &Option<Arc<DataSpace>>,
    constraints: &Constraints,
    sources: [&mut dyn for<'a> Package<&'a mut [u8]>; N],
) -> Result<Option<PendingPacket>, Error> {
    assemble(
        pathway,
        congestion,
        buffers,
        send_frames,
        pns,
        header,
        keys.tag_len(),
        journal,
        recovery,
        constraints,
        sources,
        |packet, records| {
            let ((pn, encoded), key) = records::reserve(keys, journal, records)?;
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
    header: H,
    tag_len: usize,
    journal: &ArcSentJournal,
    recovery: &Option<Arc<DataSpace>>,
    constraints: &Constraints,
    sources: [&mut dyn for<'a> Package<&'a mut [u8]>; N],
    seal: impl FnOnce(Packet, &mut Vec<GuaranteedFrame>) -> Result<PendingPacket, PacketError>,
) -> Result<Option<PendingPacket>, Error>
where
    for<'b> &'b mut [u8]: WriteHeader<H>,
{
    if !journal.has_capacity() {
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
    let flow_ctrl = &constraints.flow_ctrl;
    let constraints = Constraints {
        flow_ctrl: std::cell::Cell::new(flow_ctrl.get()),
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
        return Ok(None);
    }
    let mut buffer = buffers.pop().unwrap_or_default();
    buffer.resize(constraints.capacity, 0);
    let mut packet = Packet::new(buffer, header, tag_len).map_err(packet_error)?;
    let result = packet
        .assemble(&constraints, send_frames, sources)
        .and_then(|_| {
            if epoch == Epoch::Initial || packet.has_path_frames() {
                packet.pad_to(1200 - overhead, &constraints)?;
            }
            Ok(())
        });
    flow_ctrl.set(constraints.flow_ctrl.get());
    if let Err(error) = result {
        for frame in send_frames.drain(..) {
            if let Some(data) = recovery {
                data.recover(&frame);
            }
        }
        buffers.push(packet.into_buffer());
        return match error {
            PacketError::Blocked(_) => Ok(None),
            error => Err(packet_error(error)),
        };
    }
    match seal(packet, send_frames) {
        Ok(mut packet) => {
            packet.recovery = recovery.clone();
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
                if let Some(data) = recovery {
                    data.recover(&frame);
                }
            }
            match error {
                PacketError::Blocked(_) => Ok(None),
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
    let mut quota = congestion.send_quota();
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
            .map(|journal| journal.as_ref().map(ArcSentJournal::lock_guard));
        let result = submit(cx, pathway, &datagrams);
        datagrams.clear();
        *packets = datagrams.into_iter().map(|_| unreachable!()).collect();
        if let Poll::Ready(Ok(sent)) = &result {
            assert!(*sent <= count);
            for packet in pns.iter_mut().take(*sent) {
                let epoch = packet.epoch();
                let length = packet.bytes().len() + QuicProtocol::packet_overhead(pathway);
                let (delay, retention) = deadlines[epoch];
                records[epoch].as_mut().unwrap().on_sent(
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
    journal: &ArcSentJournal,
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

pub use crate::recv::acknowledge;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod fixture;
