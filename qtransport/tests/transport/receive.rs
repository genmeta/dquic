//! Packet receive wiring for transport component tests.
use std::sync::Arc;

use bytes::Bytes;
use qbase::{
    Epoch,
    frame::{Frame, FrameReader},
    net::route::{Link, Pathway},
    packet::{GetType, PacketContent},
};
use qcongestion::Transport as _;
use qrecovery::journal::ArcRcvdJournal;

use crate::{
    Error,
    keys::ArcKeys,
    packet::{CipherPacket, PlainPacket, channel::PacketReceiver},
    path::Path,
};

#[allow(clippy::too_many_arguments)]
pub(super) async fn receive_packets<H, M>(
    mut packets: PacketReceiver<H>,
    epoch: Epoch,
    keys: ArcKeys<M>,
    journal: ArcRcvdJournal,
    mut admit_path: impl FnMut(Pathway, Link) -> Option<Arc<Path>>,
    mut open: impl FnMut(&M, CipherPacket<H>, Pathway) -> Result<Option<PlainPacket<H>>, Error>,
    mut inspect: impl FnMut(Epoch, &Arc<Path>) -> Result<(), Error>,
    mut dispatch: impl FnMut(&M, Epoch, Frame<Bytes>, &Arc<Path>, Link) -> Result<(), Error>,
    mut on_error: impl FnMut(Error),
) where
    H: GetType,
    M: Clone,
{
    let mut parsed_frames = Vec::with_capacity(8);
    while let Some((packet, pathway, link)) = packets.recv().await {
        parsed_frames.clear();
        let received_bytes = packet.payload_len();
        let Ok(keys) = keys.get() else {
            break;
        };
        let result = open(&keys, packet, pathway).and_then(|opened| {
            if let Some(packet) = opened {
                let pn = packet.pn();
                let frames = FrameReader::new(packet.body(), packet.get_type());
                let mut content = PacketContent::default();
                for frame in frames {
                    let (frame, fty) = frame?;
                    content += PacketContent::from(fty);
                    if matches!(frame, Frame::Padding(_)) {
                        continue;
                    }
                    parsed_frames.push(frame);
                }
                let Some(path) = admit_path(pathway, link) else {
                    return Ok(());
                };
                path.on_datagram_received(received_bytes);
                inspect(epoch, &path)?;
                // CLOSE reaches the control owner even when ordinary component pipes are full.
                if let Some(frame) = parsed_frames
                    .iter()
                    .find(|frame| matches!(frame, Frame::Close(_)))
                {
                    dispatch(&keys, epoch, frame.clone(), &path, link)?;
                    return Ok(());
                }
                for frame in parsed_frames.drain(..) {
                    dispatch(&keys, epoch, frame, &path, link)?;
                }
                let pto = path.cc.get_pto(epoch);
                journal.on_rcvd_pn(pn, content.is_ack_eliciting(), pto);
                path.cc.on_pkt_rcvd(epoch, pn, content.is_ack_eliciting());
                path.send_waker.wake_all();
            }
            Ok(())
        });
        if let Err(error) = result {
            on_error(error);
        }
    }
}
