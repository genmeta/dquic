//! Receive engines are functions. Their closures capture already connected component pipes.
use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use qbase::{
    Epoch,
    error::ErrorKind,
    frame::{Frame, FrameReader},
    packet::{DataHeader, DataPacket, GetType, PacketContent, long, number::take_pn_len},
    varint::VARINT_MAX,
};
use qcongestion::Transport as _;
use qrecovery::journal::ArcRcvdJournal;
use tokio::sync::mpsc;

use crate::{Error, keys::ReceiveKeys, path::Path, space::Space};

pub fn open_packet(
    packet: DataPacket,
    keys: &impl ReceiveKeys,
    journal: &ArcRcvdJournal,
    pto: Duration,
) -> Result<Option<(u64, FrameReader)>, Error> {
    keys.open(packet, journal, pto)
}

pub(crate) fn open_with(
    mut packet: DataPacket,
    header_key: &qtls::HeaderProtectionKey,
    journal: &ArcRcvdJournal,
    mut decrypt: impl FnMut(u64, u8, &[u8], &mut [u8]) -> Result<Option<usize>, Error>,
) -> Result<Option<(u64, FrameReader)>, Error> {
    let kind = packet.get_type();
    let sample_start = packet.offset.saturating_add(4);
    if packet.offset == 0
        || sample_start.saturating_add(header_key.sample_len()) > packet.bytes.len()
    {
        return Ok(None);
    }
    let (header_pn, sample) = packet.bytes.split_at_mut(sample_start);
    let (prefix, pn_bytes) = header_pn.split_at_mut(packet.offset);
    if header_key
        .unprotect(&sample[..header_key.sample_len()], &mut prefix[0], pn_bytes)
        .is_err()
    {
        return Ok(None);
    }
    let first = packet.bytes[0];
    let pn_len = (first & 3) + 1;
    let (_, encoded) = take_pn_len(pn_len)(&packet.bytes[packet.offset..])
        .map_err(|_| crate::error(ErrorKind::Internal, "invalid packet-number layout"))?;
    let Ok(pn) = journal.decode_pn(encoded) else {
        return Ok(None);
    };
    if pn > VARINT_MAX {
        return Ok(None);
    }
    let body_offset = packet.offset + pn_len as usize;
    let (header, body) = packet.bytes.split_at_mut(body_offset);
    let Some(plain_len) = decrypt(pn, first, header, body)? else {
        return Ok(None);
    };
    let reserved = if matches!(packet.header, DataHeader::Short(_)) {
        0x18
    } else {
        0x0c
    };
    if first & reserved != 0 {
        return Err(crate::error(
            ErrorKind::ProtocolViolation,
            "nonzero authenticated reserved bits",
        ));
    }
    let payload = packet
        .bytes
        .freeze()
        .slice(body_offset..body_offset + plain_len);
    if payload.is_empty() {
        return Err(crate::error(
            ErrorKind::ProtocolViolation,
            "empty packet payload",
        ));
    }
    Ok(Some((pn, FrameReader::new(payload, kind))))
}

/// Dispatch must synchronously accept ownership or return a terminal error. A full
/// reliable pipe is an error, never an ACK followed by silent frame loss.
/// on_processed executes before CRYPTO can wake the TLS driver.
pub fn receive_packet<K>(
    pn: u64,
    frames: FrameReader,
    space: &Space<K>,
    path: &Arc<Path>,
    mut dispatch: impl FnMut(Epoch, Frame<Bytes>, &Arc<Path>) -> Result<(), Error>,
    mut on_processed: impl FnMut(Epoch, &Arc<Path>) -> Result<(), Error>,
) -> Result<PacketContent, Error> {
    let mut decoded = Vec::new();
    let mut content = PacketContent::default();
    for frame in frames {
        let (frame, kind) =
            frame.map_err(|error| crate::error(ErrorKind::FrameEncoding, error.to_string()))?;
        content += PacketContent::from(kind);
        if matches!(frame, Frame::Padding(_)) {
            continue;
        }
        if let Frame::Crypto(frame, bytes) = &frame
            && frame.offset().saturating_add(bytes.len() as u64) > VARINT_MAX
        {
            return Err(crate::error(
                ErrorKind::FrameEncoding,
                "CRYPTO range exceeds maximum offset",
            ));
        }
        decoded.push(frame);
    }
    on_processed(space.epoch, path)?;
    // CLOSE reaches the control owner even when ordinary component pipes are full.
    if let Some(frame) = decoded
        .iter()
        .find(|frame| matches!(frame, Frame::Close(_)))
    {
        dispatch(space.epoch, frame.clone(), path)?;
        return Ok(PacketContent::default());
    }
    for frame in decoded {
        dispatch(space.epoch, frame, path)?;
    }
    let pto = path.cc.get_pto(space.epoch);
    space
        .rcvd_packets
        .on_rcvd_pn(pn, content.is_ack_eliciting(), pto);
    path.cc
        .on_pkt_rcvd(space.epoch, pn, content.is_ack_eliciting());
    path.send_waker.wake_by(qbase::net::tx::Signals::TRANSPORT);
    Ok(content)
}

/// Run exactly once per space. The external driver cancels this future on close,
/// retaining its own CID inbox and Closing/Draining receive branch.
pub async fn run_receive<K: ReceiveKeys>(
    mut packets: mpsc::Receiver<(DataPacket, Arc<Path>)>,
    space: Arc<Space<K>>,
    mut dispatch: impl FnMut(Epoch, Frame<Bytes>, &Arc<Path>) -> Result<(), Error>,
    mut on_processed: impl FnMut(Epoch, &Arc<Path>) -> Result<(), Error>,
    mut on_error: impl FnMut(Error),
) {
    while let Some((packet, path)) = packets.recv().await {
        let epoch = match packet.header {
            DataHeader::Long(long::DataHeader::Initial(_)) => Epoch::Initial,
            DataHeader::Long(long::DataHeader::Handshake(_)) => Epoch::Handshake,
            DataHeader::Short(_) => Epoch::Data,
            _ => continue,
        };
        if epoch != space.epoch {
            continue;
        }
        if !space.keys.ready().await || !space.control.receiving().await {
            break;
        }
        if !space.control.can_receive() {
            break;
        }
        let result = open_packet(
            packet,
            &space.keys,
            &space.rcvd_packets,
            path.cc.get_pto(epoch),
        )
        .and_then(|opened| {
            if let Some((pn, frames)) = opened
                && space.control.can_receive()
            {
                receive_packet(pn, frames, &space, &path, &mut dispatch, &mut on_processed)?;
            }
            Ok(())
        });
        if let Err(error) = result {
            on_error(error);
            break;
        }
    }
}
