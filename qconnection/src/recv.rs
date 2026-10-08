//! Space nodes capture their pipes once; parameter completion only adds the Data node.
use std::sync::Arc;

use qbase::{
    Epoch,
    error::{ErrorKind, QuicError},
    frame::{Frame, FrameReader, GetFrameType, io::ReceiveFrame},
    net::route::Scopes,
    packet::{GetScid, GetType, OneRttHeader, PacketContent},
    role::Role,
    token::ArcTokenRegistry,
};
use qcongestion::Transport as _;
use qtransport::{
    keys::ArcKeys,
    packet::RcvdPacketHeader,
    path::Path,
    recv,
    space::{DataSpace, Space},
};
use qtraversal::punch::{ArcPuncher, ProbeEncoder};
use tokio::time::Instant;

use crate::{ArcHandshake, ArcParameters, ArcReliableFrames, CidRegistry, FlowController, Paths};

pub type PacketReceiver<H> = qtransport::packet::channel::PacketReceiver<H>;

pub(crate) async fn recv_ih_pkt_and_deliver_frames<H>(
    (mut packets, scopes): (PacketReceiver<H>, Option<Scopes>),
    space: Arc<Space<ArcKeys>>,
    paths: Arc<Paths>,
) where
    H: GetScid + GetType + RcvdPacketHeader,
{
    let epoch = space.epoch;
    let role = paths.role();
    let terminator = paths.phase().terminator();
    let idle = paths.idle();
    let mut initial_scid = None;
    let mut parsed_frames = Vec::with_capacity(8);
    while let Some((packet, pathway, _)) = tokio::select! {
        biased;
        _ = terminator.clone() => None,
        packet = packets.recv() => packet,
    } {
        parsed_frames.clear();
        let received_bytes = packet.payload_len();
        let Ok(keys) = space.keys.get() else {
            break;
        };
        if scopes.is_some_and(|scopes| !pathway.belongs_to(scopes)) {
            continue;
        }
        let result = (|| -> Result<(), crate::Error> {
            let scid = (epoch == Epoch::Initial).then(|| *packet.scid());
            let Some(packet) = packet
                .decrypt_long_packet(&keys.opening, |pn| space.rcvd_journal.decode_pn(pn))
                .transpose()?
            else {
                return Ok(());
            };
            if let Some(scid) = scid {
                if initial_scid.is_some_and(|cid| cid != scid) {
                    return Ok(());
                }
                initial_scid = Some(scid);
            }
            let pn = packet.pn();
            let mut content = PacketContent::default();
            for frame in FrameReader::new(packet.body(), packet.get_type()) {
                let (frame, fty) = frame?;
                content += PacketContent::from(fty);
                if !matches!(frame, Frame::Padding(_)) {
                    parsed_frames.push(frame);
                }
            }
            // Admit paths only after authentication and complete frame parsing.
            let path = paths.on_incoming_path(pathway);
            path.on_datagram_received(received_bytes);
            let now = Instant::now();
            terminator.on_rcvd_packet(now);
            let _ = idle.on_rcvd_at(now);
            let _ = path.heartbeat.on_rcvd_at(content, now);
            if let Some(dcid) = initial_scid {
                // This runs before CRYPTO delivery can wake the TLS consumer.
                paths.phase().set_dcid(dcid);
            }
            if role == Role::Client || epoch == Epoch::Handshake {
                paths.select_path(&path);
            }
            if epoch == Epoch::Handshake && path.selected() == Path::SELECTED {
                path.validate();
                paths.on_handshake_received();
            }
            for frame in parsed_frames.drain(..) {
                match frame {
                    Frame::Ping(_) => {}
                    Frame::Crypto(frame, bytes) => {
                        space.crypto.incoming().recv_frame((frame, bytes))?;
                    }
                    Frame::Ack(frame) => {
                        let mut cc = path.cc.lock();
                        let crypto_acked = space.on_acked(&frame)?;
                        cc.on_ack_rcvd(epoch, &frame, Instant::now());
                        drop(cc);
                        if role == Role::Server && epoch == Epoch::Initial && crypto_acked {
                            paths.select_path(&path);
                        }
                    }
                    Frame::Close(frame) => {
                        terminator.recv_conn_close_frame(frame.clone(), path.cc.pto_base(epoch));
                        return Ok(());
                    }
                    _ => {
                        return Err(QuicError::with_default_fty(
                            ErrorKind::ProtocolViolation,
                            "unexpected handshake frame",
                        )
                        .into());
                    }
                }
            }
            let pto = path.cc.get_pto(epoch);
            space
                .rcvd_journal
                .on_rcvd_pn(pn, content.is_ack_eliciting(), pto);
            path.cc.on_pkt_rcvd(epoch, pn, content.is_ack_eliciting());
            path.send_waker.wake_all();
            Ok(())
        })();
        if let Err(error) = result {
            terminator.close(error.into(), paths.closing_pto());
        }
    }
}

/// Receive Data packets and update the connection's paths, handshake and close state.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn receive_1rtt_pkt_and_deliver_frames(
    (mut packets, scopes): (PacketReceiver<OneRttHeader>, Option<Scopes>),
    data: Arc<DataSpace>,
    flow: FlowController,
    puncher: ArcPuncher<ArcReliableFrames, ProbeEncoder>,
    paths: Arc<Paths>,
    parameters: ArcParameters,
    cid_registry: CidRegistry,
    tokens: ArcTokenRegistry,
    handshake: ArcHandshake,
) {
    let terminator = paths.phase().terminator();
    let idle = paths.idle();
    let mut parsed_frames = Vec::with_capacity(8);
    while let Some((packet, pathway, link)) = tokio::select! {
        biased;
        _ = terminator.clone() => None,
        packet = packets.recv() => packet,
    } {
        parsed_frames.clear();
        let received_bytes = packet.payload_len();
        let Ok(keys) = data.keys.get() else {
            break;
        };
        if scopes.is_some_and(|scopes| !pathway.belongs_to(scopes)) {
            continue;
        }
        let result = (|| -> Result<(), crate::Error> {
            let Some(packet) = keys.open_packet(
                packet,
                |pn| data.rcvd_journal.decode_pn(pn),
                paths.pto_for(&pathway, Epoch::Data),
            )?
            else {
                return Ok(());
            };
            let pn = packet.pn();
            let mut content = PacketContent::default();
            for frame in FrameReader::new(packet.body(), packet.get_type()) {
                let (frame, fty) = frame?;
                content += PacketContent::from(fty);
                if !matches!(frame, Frame::Padding(_)) {
                    parsed_frames.push(frame);
                }
            }
            // Admit paths only after authentication and complete frame parsing.
            let path = paths.on_incoming_path(pathway);
            path.on_datagram_received(received_bytes);
            let now = Instant::now();
            terminator.on_rcvd_packet(now);
            let _ = idle.on_rcvd_at(now);
            let _ = path.heartbeat.on_rcvd_at(content, now);
            // Start validation only after authentication and path admission.
            paths.start_validation(&path);
            for frame in parsed_frames.drain(..) {
                let fty = frame.frame_type();
                match frame {
                    Frame::Ping(_) => {}
                    Frame::Ack(frame) => {
                        recv::acknowledge(&data, &parameters, &frame, &path, |generation| {
                            keys.on_ack(generation)
                        })?;
                    }
                    Frame::Crypto(frame, bytes) => {
                        data.crypto.incoming().recv_frame((frame, bytes))?;
                    }
                    Frame::Stream(frame, bytes) => {
                        let fresh = data.streams.recv_frame((frame, bytes))?;
                        flow.recver.on_new_rcvd(fty, fresh)?;
                    }
                    Frame::StreamCtl(frame) => {
                        let fresh = data.streams.recv_frame(frame)?;
                        flow.recver.on_new_rcvd(fty, fresh)?;
                    }
                    Frame::MaxData(frame) => flow.sender.recv_frame(frame)?,
                    Frame::DataBlocked(frame) => flow.recver.recv_frame(frame)?,
                    Frame::NewConnectionId(frame) => {
                        cid_registry.remote.recv_frame(frame)?;
                    }
                    Frame::RetireConnectionId(frame) => {
                        cid_registry.local.recv_frame(frame)?;
                    }
                    Frame::NewToken(frame) => {
                        tokens.recv_frame(frame)?;
                    }
                    Frame::PathChallenge(frame) => path.recv_frame(frame)?,
                    Frame::PathResponse(frame) => paths.on_path_response(&path, frame),
                    Frame::HandshakeDone(frame) => {
                        handshake.recv_frame(frame)?;
                    }
                    Frame::Close(frame) => {
                        terminator
                            .recv_conn_close_frame(frame.clone(), path.cc.pto_base(Epoch::Data));
                        return Ok(());
                    }
                    Frame::AddAddress(frame) => puncher.recv_add_address(frame),
                    Frame::RemoveAddress(frame) => {
                        // Unknown sequence numbers are ignored; do not truncate a
                        // wire VarInt into an existing 32-bit punch address ID.
                        if let Ok(seq) = u32::try_from(frame.seq_num.into_u64()) {
                            puncher.recv_remove_address(seq);
                        }
                    }
                    Frame::PunchMeNow(frame) => puncher.recv_punch_me_now(path.pathway, frame),
                    Frame::PunchHello(frame) => {
                        puncher.recv_punch_hello(path.pathway, link, frame);
                    }
                    Frame::PunchDone(frame) => puncher.recv_punch_done(link, frame),
                    _ => {
                        return Err(QuicError::with_default_fty(
                            ErrorKind::ProtocolViolation,
                            "unnegotiated frame",
                        )
                        .into());
                    }
                }
            }
            let pto = path.cc.get_pto(Epoch::Data);
            data.rcvd_journal
                .on_rcvd_pn(pn, content.is_ack_eliciting(), pto);
            path.cc
                .on_pkt_rcvd(Epoch::Data, pn, content.is_ack_eliciting());
            path.send_waker.wake_all();
            Ok(())
        })();
        if let Err(error) = result {
            terminator.close(error.into(), paths.closing_pto());
        }
    }
}

/// Drive connection deadlines alongside its growing future, once per connection.
/// Recovery runs until termination.
pub async fn tick(paths: Arc<Paths>) {
    let phase = paths.phase();
    let terminator = phase.terminator();
    loop {
        let now = Instant::now();
        let snapshot = phase.get();
        for space in snapshot.spaces().read().unwrap().0.iter() {
            space.on_tick(now);
        }
        tokio::select! {
            biased;
            _ = terminator.clone() => break,
            _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {},
        }
    }
}
