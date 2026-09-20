//! Receive engines are functions. Their closures capture already connected component pipes.
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use qbase::{
    Epoch,
    error::{ErrorKind, QuicError},
    flow::FlowController,
    frame::{
        ConnectionCloseFrame, Frame, FrameReader, GetFrameType, NewConnectionIdFrame,
        NewTokenFrame, RetireConnectionIdFrame, io::ReceiveFrame,
    },
    net::route::{Link, Pathway},
    packet::{DataHeader, DataPacket, Packet, PacketContent, long},
    varint::VARINT_MAX,
};
use qcongestion::Transport as _;
use qrecovery::{crypto::CryptoStream, streams::DataStreams};
use tokio::sync::mpsc;

use crate::{
    ArcParameters, Error, ReliableFrames,
    keys::{ArcKeys, ArcOneRttKeys, KeyRetired, OneRttKeys, OpenPacket},
    path::Path,
    router::{PACKET_QUEUE_CAPACITY, ReceivedPacket},
    space::Space,
};

/// Connect existing components once. No task, registry or extra frame buffer is created here.
/// Handshake ACK/HANDSHAKE_DONE and negotiated extensions belong to the external driver.
/// Data dispatch supplies an ACK callback capturing its already acquired OneRttKeys.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn frame_dispatcher(
    data: Arc<Space<ArcOneRttKeys>>,
    parameters: ArcParameters,
    streams: DataStreams<ReliableFrames>,
    flow: FlowController<ReliableFrames>,
    crypto: [CryptoStream; 3],
    local_cids: impl ReceiveFrame<RetireConnectionIdFrame> + Send + Sync,
    remote_cids: impl ReceiveFrame<NewConnectionIdFrame> + Send + Sync,
    tokens: impl ReceiveFrame<NewTokenFrame> + Send + Sync,
    closing: Arc<AtomicBool>,
    on_close: impl Fn(Epoch, ConnectionCloseFrame, &Arc<Path>) -> Result<(), Error> + Send + Sync,
    on_other: impl Fn(Epoch, Frame<Bytes>, &Arc<Path>) -> Result<(), Error> + Send + Sync,
) -> impl Fn(Epoch, Frame<Bytes>, &Arc<Path>, &dyn Fn(u64)) -> Result<(), Error> + Send + Sync {
    move |epoch, frame, path, on_ack| {
        let kind = frame.frame_type();
        match frame {
            Frame::Padding(_) | Frame::Ping(_) => Ok(()),
            Frame::Ack(frame) if epoch == Epoch::Data => {
                crate::send::acknowledge(&data, &streams, &parameters, &frame, path, on_ack)
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
            Frame::NewConnectionId(frame) => remote_cids.recv_frame(frame).map(|_| ()),
            Frame::RetireConnectionId(frame) => local_cids.recv_frame(frame).map(|_| ()),
            Frame::NewToken(frame) => tokens.recv_frame(frame).map(|_| ()),
            Frame::PathChallenge(frame) => path.recv_frame(frame),
            Frame::PathResponse(frame) => path.recv_frame(frame),
            Frame::Close(frame) => {
                closing.store(true, Ordering::Release);
                data.stop_sending();
                let error = Error::from(frame.clone());
                streams.on_conn_error(&error);
                flow.on_conn_error(&error);
                on_close(epoch, frame, path)
            }
            frame => on_other(epoch, frame, path),
        }
    }
}

/// Demultiplex without awaiting keys or downstream queue capacity.
pub async fn route_packets(
    mut inbox: mpsc::Receiver<ReceivedPacket>,
    entries: [mpsc::Sender<(DataPacket, Arc<Path>)>; 3],
    mut path_for: impl FnMut(Pathway, Link) -> Option<Arc<Path>>,
    mut on_unprotected: impl FnMut(Packet, Pathway, Link),
) {
    while let Some((packet, pathway, link, size)) = inbox.recv().await {
        let Some(path) = path_for(pathway, link) else {
            continue;
        };
        if size != 0 {
            path.on_datagram_received(size);
        }
        match packet {
            Packet::Data(packet) => {
                let epoch = match packet.header {
                    DataHeader::Long(long::DataHeader::Initial(_)) => Epoch::Initial,
                    DataHeader::Long(long::DataHeader::Handshake(_)) => Epoch::Handshake,
                    DataHeader::Short(_) => Epoch::Data,
                    // 0-RTT is not enabled by this transport.
                    _ => continue,
                };
                let _ = entries[epoch].try_send((packet, path));
            }
            packet => on_unprotected(packet, pathway, link),
        }
    }
}

/// One coroutine drives all receive spaces. A pending Handshake key does not block Initial/Data.
/// qconn owns spawning/cancellation, path creation, TLS progression and final route removal.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    inbox: mpsc::Receiver<ReceivedPacket>,
    initial: Arc<Space<ArcKeys>>,
    handshake: Arc<Space<ArcKeys>>,
    data: Arc<Space<ArcOneRttKeys>>,
    closing: Arc<AtomicBool>,
    path_for: impl FnMut(Pathway, Link) -> Option<Arc<Path>>,
    dispatch: impl Fn(Epoch, Frame<Bytes>, &Arc<Path>, &dyn Fn(u64)) -> Result<(), Error>,
    on_processed: impl Fn(Epoch, &Arc<Path>) -> Result<(), Error>,
    on_unprotected: impl FnMut(Packet, Pathway, Link),
    on_error: impl Fn(Error),
) {
    let (initial_entry, initial_packets) = mpsc::channel(PACKET_QUEUE_CAPACITY);
    let (handshake_entry, handshake_packets) = mpsc::channel(PACKET_QUEUE_CAPACITY);
    let (data_entry, data_packets) = mpsc::channel(PACKET_QUEUE_CAPACITY);
    tokio::join!(
        route_packets(
            inbox,
            [initial_entry, handshake_entry, data_entry],
            path_for,
            on_unprotected
        ),
        run_receive(
            initial_packets,
            initial.clone(),
            |keys, packet, pto| {
                keys.opening
                    .open(packet, |pn| initial.rcvd_journal.decode_pn(pn), pto)
            },
            closing.clone(),
            |_, epoch, frame, path| dispatch(epoch, frame, path, &|_| {}),
            &on_processed,
            &on_error
        ),
        run_receive(
            handshake_packets,
            handshake.clone(),
            |keys, packet, pto| {
                keys.opening
                    .open(packet, |pn| handshake.rcvd_journal.decode_pn(pn), pto)
            },
            closing.clone(),
            |_, epoch, frame, path| dispatch(epoch, frame, path, &|_| {}),
            &on_processed,
            &on_error
        ),
        run_receive(
            data_packets,
            data.clone(),
            |keys: &OneRttKeys, packet, pto| {
                keys.open(packet, |pn| data.rcvd_journal.decode_pn(pn), pto)
            },
            closing,
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
    closing: &AtomicBool,
    mut dispatch: impl FnMut(Epoch, Frame<Bytes>, &Arc<Path>) -> Result<(), Error>,
    mut on_processed: impl FnMut(Epoch, &Arc<Path>) -> Result<(), Error>,
) -> Result<PacketContent, Error> {
    if closing.load(Ordering::Acquire) {
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
        if closing.load(Ordering::Acquire) {
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
    path.send_waker.wake_by(qbase::net::tx::Signals::TRANSPORT);
    Ok(content)
}

/// One key waiter per space. Closing keeps this same engine alive for CLOSE frames.
/// Retirement ends only this space; qconn cancels the whole task after draining.
/// Dispatch receives the same ready material used to open the packet.
pub async fn run_receive<K, M>(
    mut packets: mpsc::Receiver<(DataPacket, Arc<Path>)>,
    space: Arc<Space<K>>,
    mut open: impl FnMut(&M, DataPacket, Duration) -> Result<Option<(u64, FrameReader)>, Error>,
    closing: Arc<AtomicBool>,
    mut dispatch: impl FnMut(&M, Epoch, Frame<Bytes>, &Arc<Path>) -> Result<(), Error>,
    mut on_processed: impl FnMut(Epoch, &Arc<Path>) -> Result<(), Error>,
    mut on_error: impl FnMut(Error),
) where
    K: Clone + Future<Output = Result<M, KeyRetired>>,
{
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
        if !space.can_receive() {
            break;
        }
        let Ok(keys) = space.keys.clone().await else {
            break;
        };
        if !space.can_receive() {
            break;
        }
        let result = open(&keys, packet, path.cc.get_pto(epoch)).and_then(|opened| {
            if let Some((pn, frames)) = opened
                && space.can_receive()
            {
                receive_packet(
                    pn,
                    frames,
                    &space,
                    &path,
                    &closing,
                    |epoch, frame, path| dispatch(&keys, epoch, frame, path),
                    &mut on_processed,
                )?;
            }
            Ok(())
        });
        if let Err(error) = result
            && !closing.swap(true, Ordering::AcqRel)
        {
            on_error(error);
        }
    }
}
