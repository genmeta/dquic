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
use qrecovery::{crypto::CryptoStream, streams::DataStreams};

use crate::{
    ArcParameters, ArcReliableFrames, Error, GuaranteedFrame,
    keys::{ArcKeys, ArcOneRttKeys, OneRttKeys},
    packet::{
        CipherPacket, PlainPacket,
        channel::{PacketReceiver, RcvdPacket},
    },
    path::Path,
    space::Space,
};

/// Connect existing components once. No task, registry or extra frame buffer is created here.
/// Handshake ACK/HANDSHAKE_DONE and negotiated extensions belong to the external driver.
/// Data dispatch supplies an ACK callback capturing its already acquired OneRttKeys.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn frame_dispatcher<LOCAL, REMOTE>(
    data: Arc<Space<ArcOneRttKeys>>,
    parameters: ArcParameters,
    streams: DataStreams<ArcReliableFrames>,
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
                acknowledge(&data, &streams, &parameters, &frame, path, on_ack)
            }
            Frame::Crypto(frame, bytes) => crypto[epoch].incoming().recv_frame((frame, bytes)),
            Frame::Stream(frame, bytes) => {
                let fresh = streams.recv_frame((frame, bytes))?;
                flow.recver.on_new_rcvd(kind, fresh).map(|_| ())
            }
            Frame::StreamCtl(frame) => {
                let fresh = streams.recv_frame(frame)?;
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
                streams.on_conn_error(&error);
                flow.on_conn_error(&error);
                on_close(epoch, frame, path)
            }
            frame => on_other(epoch, frame, path),
        }
    }
}

/// One coroutine drives all receive spaces. A pending Handshake key does not block Initial/Data.
/// qconn owns spawning and queue closure, path creation, TLS progression and final route removal.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    rcvd_pkt: RcvdPacket,
    initial: Arc<Space<ArcKeys>>,
    handshake: Arc<Space<ArcKeys>>,
    data: Arc<Space<ArcOneRttKeys>>,
    is_closing: impl Fn() -> bool + Sync,
    path_for: impl Fn(Pathway, Link) -> Option<Arc<Path>> + Sync,
    dispatch: impl Fn(Epoch, Frame<Bytes>, &Arc<Path>, &dyn Fn(u64)) -> Result<(), Error>,
    on_processed: impl Fn(Epoch, &Arc<Path>) -> Result<(), Error>,
    on_error: impl Fn(Error),
) {
    let RcvdPacket {
        initial: initial_rx,
        handshake: handshake_rx,
        zero_rtt: _,
        one_rtt: one_rtt_rx,
    } = rcvd_pkt;
    tokio::join!(
        run_receive(
            initial_rx,
            initial.clone(),
            &path_for,
            |keys: &Arc<qtls::BidirectionalKeys>, packet, _| {
                packet
                    .decrypt_long_packet(&keys.opening, |pn| initial.rcvd_journal.decode_pn(pn))
                    .transpose()
                    .map_err(Into::into)
            },
            &is_closing,
            |_, epoch, frame, path| dispatch(epoch, frame, path, &|_| {}),
            &on_processed,
            &on_error
        ),
        run_receive(
            handshake_rx,
            handshake.clone(),
            &path_for,
            |keys: &Arc<qtls::BidirectionalKeys>, packet, _| {
                packet
                    .decrypt_long_packet(&keys.opening, |pn| handshake.rcvd_journal.decode_pn(pn))
                    .transpose()
                    .map_err(Into::into)
            },
            &is_closing,
            |_, epoch, frame, path| dispatch(epoch, frame, path, &|_| {}),
            &on_processed,
            &on_error
        ),
        run_receive(
            one_rtt_rx,
            data.clone(),
            &path_for,
            |keys: &OneRttKeys, packet, pto| {
                keys.open_packet(packet, |pn| data.rcvd_journal.decode_pn(pn), pto)
            },
            &is_closing,
            |keys, epoch, frame, path| {
                dispatch(epoch, frame, path, &|generation| keys.on_ack(generation))
            },
            &on_processed,
            &on_error
        ),
    );
}

/// Dispatch must synchronously accept ownership or return a terminal error. A full
/// reliable pipe is an error, never an ACK followed by silent frame loss.
/// on_processed executes before CRYPTO can wake the TLS driver. In Closing it
/// reports authenticated packets so the owner can schedule a rate-limited CLOSE reply.
pub fn receive_packet<K>(
    pn: u64,
    frames: FrameReader,
    space: &Space<K>,
    path: &Arc<Path>,
    is_closing: impl Fn() -> bool,
    mut dispatch: impl FnMut(Epoch, Frame<Bytes>, &Arc<Path>) -> Result<(), Error>,
    mut on_processed: impl FnMut(Epoch, &Arc<Path>) -> Result<(), Error>,
) -> Result<PacketContent, Error> {
    if is_closing() {
        on_processed(space.epoch, path)?;
        for frame in frames {
            let Ok((frame, _)) = frame else { break };
            if matches!(frame, Frame::Close(_)) {
                dispatch(space.epoch, frame, path)?;
                break;
            }
        }
        return Ok(PacketContent::default());
    }

    // TODO: 创建啥 Vec，开销就大了，后面要整改
    let mut decoded = Vec::new();
    let mut content = PacketContent::default();
    for frame in frames {
        let (frame, kind) = frame.map_err(|error| {
            QuicError::with_default_fty(ErrorKind::FrameEncoding, error.to_string())
        })?;
        content += PacketContent::from(kind);
        if matches!(frame, Frame::Padding(_)) {
            continue;
        }
        if let Frame::Crypto(frame, bytes) = &frame
            && frame.offset().saturating_add(bytes.len() as u64) > VARINT_MAX
        {
            return Err(QuicError::with_default_fty(
                ErrorKind::FrameEncoding,
                "CRYPTO range exceeds maximum offset",
            )
            .into());
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
        if is_closing() {
            return Ok(PacketContent::default());
        }
        dispatch(space.epoch, frame, path)?;
    }
    let pto = path.cc.get_pto(space.epoch);
    space
        .rcvd_journal
        .on_rcvd_pn(pn, content.is_ack_eliciting(), pto);
    path.cc
        .on_pkt_rcvd(space.epoch, pn, content.is_ack_eliciting());
    path.send_waker.wake_all();
    Ok(content)
}

/// Keys are ready before this engine starts. Closing keeps it alive for CLOSE frames.
/// Retirement ends only this space; closing the inbox ends idle packet waits.
/// Dispatch receives the same ready material used to open the packet.
#[allow(clippy::too_many_arguments)]
pub async fn run_receive<H, M>(
    mut packets: PacketReceiver<H>,
    space: Arc<Space<ArcKeys<M>>>,
    mut path_for: impl FnMut(Pathway, Link) -> Option<Arc<Path>>,
    mut open: impl FnMut(&M, CipherPacket<H>, Duration) -> Result<Option<PlainPacket<H>>, Error>,
    is_closing: impl Fn() -> bool,
    mut dispatch: impl FnMut(&M, Epoch, Frame<Bytes>, &Arc<Path>) -> Result<(), Error>,
    mut on_processed: impl FnMut(Epoch, &Arc<Path>) -> Result<(), Error>,
    mut on_error: impl FnMut(Error),
) where
    H: GetType,
    M: Clone,
{
    while let Some((packet, pathway, link)) = packets.recv().await {
        let Some(path) = path_for(pathway, link) else {
            continue;
        };
        path.on_datagram_received(packet.payload_len());
        let epoch = space.epoch;
        let Ok(keys) = space.keys.get() else {
            break;
        };
        let result = open(&keys, packet, path.cc.get_pto(epoch)).and_then(|opened| {
            if let Some(packet) = opened {
                let pn = packet.pn();
                let frames = FrameReader::new(packet.body(), packet.get_type());
                receive_packet(
                    pn,
                    frames,
                    &space,
                    &path,
                    &is_closing,
                    |epoch, frame, path| dispatch(&keys, epoch, frame, path),
                    &mut on_processed,
                )?;
            }
            Ok(())
        });
        if let Err(error) = result
            && !is_closing()
        {
            on_error(error);
        }
    }
}

/// Data ACK pipe target. Capture the original components before Transport is created.
/// Lock the receiving path CC before the journal, so ACK observes committed sends.
/// Report acknowledged generations to the receive task's ready OneRttKeys.
pub fn acknowledge(
    data: &Space<ArcOneRttKeys>,
    streams: &DataStreams<ArcReliableFrames>,
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
    received_on.send_waker.wake_all();
    Ok(())
}
