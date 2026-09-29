//! Receive engines are functions. Their closures capture already connected component pipes.
use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use qbase::{
    Epoch,
    cid::Registry,
    error::{ErrorKind, QuicError},
    flow::FlowController,
    frame::{
        AckFrame, ConnectionCloseFrame, Frame, FrameReader, GetFrameType, NewConnectionIdFrame,
        NewTokenFrame, RetireConnectionIdFrame, io::ReceiveFrame,
    },
    net::route::{Link, Pathway},
    packet::{GetType, PacketContent},
    param::ParameterId,
    varint::{VARINT_MAX, VarInt},
};
use qcongestion::Transport as _;
use qrecovery::{crypto::CryptoStream, journal::ArcRcvdJournal};

use crate::{
    ArcParameters, ArcReliableFrames, Error,
    keys::ArcKeys,
    packet::{CipherPacket, PlainPacket, channel::PacketReceiver},
    path::Path,
    space::DataSpace,
};

/// Connect existing components once. No task, registry or extra frame buffer is created here.
/// Handshake ACK/HANDSHAKE_DONE and negotiated extensions belong to the external driver.
/// Data dispatch supplies an ACK callback capturing its already acquired OneRttKeys.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn frame_dispatcher<LOCAL, REMOTE>(
    data: Arc<DataSpace>,
    parameters: ArcParameters,
    flow: FlowController<ArcReliableFrames>,
    crypto: [CryptoStream; 3],
    cid_registry: Registry<LOCAL, REMOTE>,
    tokens: impl ReceiveFrame<NewTokenFrame> + Send + Sync,
    on_close: impl Fn(Epoch, ConnectionCloseFrame, &Arc<Path>) -> Result<(), Error> + Send + Sync,
    on_other: impl Fn(Epoch, Frame<Bytes>, &Arc<Path>) -> Result<(), Error> + Send + Sync,
) -> impl Fn(Epoch, Frame<Bytes>, &Arc<Path>, &dyn Fn(u64)) -> Result<(), Error> + Send + Sync
where
    LOCAL: ReceiveFrame<RetireConnectionIdFrame> + Send + Sync,
    REMOTE: ReceiveFrame<NewConnectionIdFrame> + Send + Sync,
{
    move |epoch, frame, path, on_ack| {
        let kind = frame.frame_type();
        match frame {
            Frame::Padding(_) | Frame::Ping(_) => Ok(()),
            Frame::Ack(frame) if epoch == Epoch::Data => {
                acknowledge(&data, &parameters, &frame, path, on_ack)
            }
            Frame::Crypto(frame, bytes) => crypto[epoch].incoming().recv_frame((frame, bytes)),
            Frame::Stream(frame, bytes) => {
                let fresh = data.streams.recv_frame((frame, bytes))?;
                flow.recver.on_new_rcvd(kind, fresh).map(|_| ())
            }
            Frame::StreamCtl(frame) => {
                let fresh = data.streams.recv_frame(frame)?;
                flow.recver.on_new_rcvd(kind, fresh).map(|_| ())
            }
            Frame::MaxData(frame) => flow.sender.recv_frame(frame),
            Frame::DataBlocked(frame) => flow.recver.recv_frame(frame),
            Frame::NewConnectionId(frame) => cid_registry.remote.recv_frame(frame).map(|_| ()),
            Frame::RetireConnectionId(frame) => cid_registry.local.recv_frame(frame).map(|_| ()),
            Frame::NewToken(frame) => tokens.recv_frame(frame).map(|_| ()),
            Frame::PathChallenge(frame) => path.recv_frame(frame),
            Frame::Close(frame) => {
                let error = Error::from(frame.clone());
                data.crypto.on_error(&error);
                data.streams.on_conn_error(&error);
                flow.on_conn_error(&error);
                on_close(epoch, frame, path)
            }
            frame => on_other(epoch, frame, path),
        }
    }
}

/// Dispatch must synchronously accept ownership or return a terminal error. A full
/// reliable pipe is an error, never an ACK followed by silent frame loss.
/// inspect executes before CRYPTO can wake the TLS driver. Packet and CLOSE
/// notifications are unconditional; the owner handles connection state.
///
/// Keys are ready before this engine starts. Closing keeps it alive for CLOSE frames.
/// Retirement ends only this space; closing the inbox ends idle packet waits.
/// Dispatch receives the same ready material used to open the packet.
#[allow(clippy::too_many_arguments)]
pub async fn run_receive<H, M>(
    mut packets: PacketReceiver<H>,
    epoch: Epoch,
    keys: ArcKeys<M>,
    journal: ArcRcvdJournal,
    mut path_for: impl FnMut(Pathway, Link) -> Option<Arc<Path>>,
    mut open: impl FnMut(&M, CipherPacket<H>, Duration) -> Result<Option<PlainPacket<H>>, Error>,
    mut inspect: impl FnMut(Epoch, &Arc<Path>) -> Result<(), Error>,
    mut dispatch: impl FnMut(&M, Epoch, Frame<Bytes>, &Arc<Path>) -> Result<(), Error>,
    mut on_error: impl FnMut(Error),
) where
    H: GetType,
    M: Clone,
{
    let mut parsed_frames = Vec::with_capacity(8);
    while let Some((packet, pathway, link)) = packets.recv().await {
        let Some(path) = path_for(pathway, link) else {
            continue;
        };
        path.on_datagram_received(packet.payload_len());
        let Ok(keys) = keys.get() else {
            break;
        };
        let result = open(&keys, packet, path.cc.get_pto(epoch)).and_then(|opened| {
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
                inspect(epoch, &path)?;
                // CLOSE reaches the control owner even when ordinary component pipes are full.
                if let Some(frame) = parsed_frames
                    .iter()
                    .find(|frame| matches!(frame, Frame::Close(_)))
                {
                    dispatch(&keys, epoch, frame.clone(), &path)?;
                    return Ok(());
                }
                for frame in parsed_frames.drain(..) {
                    dispatch(&keys, epoch, frame, &path)?;
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

/// Data ACK pipe target. Capture the original components before Transport is created.
/// Lock the receiving path CC before the journal, so ACK observes committed sends.
/// Report the highest acknowledged generation to the receive task's ready OneRttKeys.
pub fn acknowledge(
    data: &DataSpace,
    parameters: &ArcParameters,
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
        let acknowledged = data.on_acked(ack)?;
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
    if let Some(generation) = acknowledged {
        on_ack(generation);
    }
    received_on.send_waker.wake_all();
    Ok(())
}
