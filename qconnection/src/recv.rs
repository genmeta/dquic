//! Space nodes capture their pipes once; parameter completion only adds the Data node.
use std::sync::Arc;

use qbase::{
    Epoch,
    error::{ErrorKind, QuicError},
    frame::{Frame, FrameReader, io::ReceiveFrame},
    net::route::Scopes,
    packet::{GetPacketNumberLength, GetScid, GetType, LongSpecificBits, OneRttHeader, PacketContent, ShortSpecificBits},
    role::Role,
    token::ArcTokenRegistry,
};
use qcongestion::Transport as _;
use qtransport::{
    keys::{ArcKeys, Open, PacketError, open},
    packet::{CipherPacket, LogPacketHeader, PlainPacket},
    recv,
    space::{DataSpace, Space},
};
use tokio::time::Instant;

use crate::{ArcHandshakeDone, Paths};

pub type PacketReceiver<H> = qtransport::packet::channel::PacketReceiver<H>;

fn drop_packet(header: impl LogPacketHeader, buffer: bytes::BytesMut, pn_offset: usize, pn: Option<u64>, error: impl ToString) {
    CipherPacket::new(header, buffer, pn_offset).drop_on_decryption_failure(pn, error);
}

fn key_error(error: PacketError) -> crate::Error {
    match error {
        PacketError::Connection(error) => error,
        error => QuicError::with_default_fty(ErrorKind::Internal, error.to_string()).into(),
    }
}

pub(crate) async fn recv_ih_pkt_and_deliver_frames<H>(
    (mut packets, scopes): (PacketReceiver<H>, Option<Scopes>),
    space: Arc<impl AsRef<Space<ArcKeys>> + Send + Sync>,
    paths: Arc<Paths>,
) where
    H: GetScid + GetType + LogPacketHeader,
{
    let space = space.as_ref().as_ref();
    let epoch = space.epoch;
    let role = paths.role();
    let terminator = paths.terminator.clone();
    let idle = paths.idle_timer();
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
            let (header, mut buffer, pn_offset) = packet.split();
            let encoded = match open::header(&keys.opening.header, &mut buffer, pn_offset) {
                Ok(pn) => pn,
                Err(error) => {
                    drop_packet(header, buffer, pn_offset, None, error);
                    return Ok(());
                }
            };
            let pn = match space.rcvd_journal.decode_pn(encoded) {
                Ok(pn) => pn,
                Err(error) => {
                    CipherPacket::new(header, buffer, pn_offset).drop_on_invalid(None, error);
                    return Ok(());
                }
            };
            let body_offset = pn_offset + encoded.size();
            let plain_len = match keys.opening.open(pn, &mut buffer, body_offset) {
                Ok(len) => len,
                Err(error) => {
                    if matches!(error, PacketError::AuthenticationFailed) {
                        paths.on_authentication_failed(keys.opening.integrity_limit());
                    }
                    drop_packet(header, buffer, pn_offset, Some(pn), error);
                    return Ok(());
                }
            };
            space.rcvd_journal.on_authenticated(pn);
            if let Err(error) = LongSpecificBits::from(buffer[0]).pn_len() {
                CipherPacket::new(header, buffer, pn_offset).drop_on_invalid(Some(pn), &error);
                return Err(QuicError::from(error).into());
            }
            if plain_len == 0 {
                return Err(QuicError::with_default_fty(ErrorKind::ProtocolViolation, "empty packet payload").into());
            }
            let packet = PlainPacket::new(header, pn, encoded, buffer.freeze(), pn_offset, plain_len);
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
            let path = paths.get_or_create_path(&pathway);
            path.validation.on_received(received_bytes);
            path.send_waker.wake_all();
            let now = Instant::now();
            terminator.on_rcvd_packet(now);
            let _ = idle.on_rcvd_at(now);
            let _ = path.heartbeat.on_rcvd_at(content, now);
            if let Some(dcid) = initial_scid {
                // This runs before CRYPTO delivery can wake the TLS consumer.
                paths.progress.on_initial_received(dcid);
            }
            // An Initial ACK proves receipt, but does not identify the path
            // carrying the server's TLS flight. Keep racing until CRYPTO arrives.
            let has_crypto_data = parsed_frames.iter().any(|frame| matches!(frame, Frame::Crypto(_, bytes) if !bytes.is_empty()));
            if epoch == Epoch::Handshake || (role == Role::Client && epoch == Epoch::Initial && has_crypto_data) {
                paths.progress.on_path_selected(&paths, &path);
            }
            if epoch == Epoch::Handshake {
                if path.validation.grant().is_ok() {
                    path.send_waker.wake_all();
                }
                paths.progress.on_handshake_received();
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
                            paths.progress.on_path_selected(&paths, &path);
                        }
                    }
                    Frame::Close(frame) => {
                        terminator.recv_conn_close_frame(frame.clone(), path.cc.pto_base(epoch));
                        return Ok(());
                    }
                    _ => {
                        return Err(QuicError::with_default_fty(ErrorKind::ProtocolViolation, "unexpected handshake frame").into());
                    }
                }
            }
            let pto = path.cc.get_pto(epoch);
            space.rcvd_journal.on_rcvd_pn(pn, content.is_ack_eliciting(), pto);
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
    paths: Arc<Paths>,
    tokens: ArcTokenRegistry,
    hs_done: ArcHandshakeDone,
) {
    let terminator = paths.terminator.clone();
    let idle = paths.idle_timer();
    let mut parsed_frames = Vec::with_capacity(8);
    while let Some((packet, pathway, link)) = tokio::select! {
        biased;
        _ = terminator.clone() => None,
        packet = packets.recv() => packet,
    } {
        parsed_frames.clear();
        let received_bytes = packet.payload_len();
        let keys = &data.keys;
        if scopes.is_some_and(|scopes| !pathway.belongs_to(scopes)) {
            continue;
        }
        let result = (|| -> Result<(), crate::Error> {
            let (header, mut buffer, pn_offset) = packet.split();
            let encoded = match open::header(keys.opening_header(), &mut buffer, pn_offset) {
                Ok(pn) => pn,
                Err(error) => {
                    drop_packet(header, buffer, pn_offset, None, error);
                    return Ok(());
                }
            };
            let pn = match data.rcvd_journal.decode_pn(encoded) {
                Ok(pn) => pn,
                Err(error) => {
                    CipherPacket::new(header, buffer, pn_offset).drop_on_invalid(None, error);
                    return Ok(());
                }
            };
            let specific_bits = ShortSpecificBits::from(buffer[0]);
            let Some(opening) = keys.opening_packet(pn, specific_bits.key_phase()).map_err(key_error)? else {
                drop_packet(header, buffer, pn_offset, Some(pn), "no acceptable opening generation");
                return Ok(());
            };
            let body_offset = pn_offset + encoded.size();
            let plain_len = match opening.open(pn, &mut buffer, body_offset) {
                Ok(len) => len,
                Err(error) => {
                    if matches!(error, PacketError::AuthenticationFailed) {
                        paths.on_authentication_failed(opening.integrity_limit());
                    }
                    drop_packet(header, buffer, pn_offset, Some(pn), error);
                    return Ok(());
                }
            };
            data.rcvd_journal.on_authenticated(pn);
            keys.on_opened(pn, &opening, paths.pto_for(&pathway, Epoch::Data)).map_err(key_error)?;
            if let Err(error) = specific_bits.pn_len() {
                CipherPacket::new(header, buffer, pn_offset).drop_on_invalid(Some(pn), &error);
                return Err(QuicError::from(error).into());
            }
            if plain_len == 0 {
                return Err(QuicError::with_default_fty(ErrorKind::ProtocolViolation, "empty packet payload").into());
            }
            let packet = PlainPacket::new(header, pn, encoded, buffer.freeze(), pn_offset, plain_len);
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
            let path = paths.get_or_create_path(&pathway);
            path.validation.on_received(received_bytes);
            path.send_waker.wake_all();
            let now = Instant::now();
            terminator.on_rcvd_packet(now);
            let _ = idle.on_rcvd_at(now);
            let _ = path.heartbeat.on_rcvd_at(content, now);
            for frame in parsed_frames.drain(..) {
                match frame {
                    Frame::Ping(_) => {}
                    Frame::Ack(frame) => {
                        recv::acknowledge(&data, &frame, &path, |generation| keys.on_ack(generation))?;
                    }
                    Frame::Crypto(frame, bytes) => {
                        data.crypto.incoming().recv_frame((frame, bytes))?;
                    }
                    Frame::Stream(frame, bytes) => {
                        data.streams.recv_frame((frame, bytes))?;
                    }
                    Frame::StreamCtl(frame) => {
                        data.streams.recv_frame(frame)?;
                    }
                    Frame::NewConnectionId(frame) => {
                        paths.cid_registry.remote.recv_frame(frame)?;
                    }
                    Frame::RetireConnectionId(frame) => {
                        paths.cid_registry.local.recv_frame(frame)?;
                    }
                    Frame::NewToken(frame) => {
                        tokens.recv_frame(frame)?;
                    }
                    Frame::PathChallenge(frame) => paths.validations.recv_frame((pathway, frame))?,
                    Frame::PathResponse(frame) => paths.validations.recv_frame((pathway, frame))?,
                    Frame::HandshakeDone(frame) => {
                        hs_done.recv_frame(frame)?;
                    }
                    Frame::Close(frame) => {
                        terminator.recv_conn_close_frame(frame.clone(), path.cc.pto_base(Epoch::Data));
                        return Ok(());
                    }
                    Frame::AddAddress(frame) => paths.puncher.recv_add_address(frame),
                    Frame::RemoveAddress(frame) => {
                        // Unknown sequence numbers are ignored; do not truncate a
                        // wire VarInt into an existing 32-bit punch address ID.
                        if let Ok(seq) = u32::try_from(frame.seq_num.into_u64()) {
                            paths.puncher.recv_remove_address(seq);
                        }
                    }
                    Frame::PunchMeNow(frame) => paths.puncher.recv_punch_me_now(path.pathway, frame),
                    Frame::PunchHello(frame) => {
                        paths.puncher.recv_punch_hello(path.pathway, link, frame);
                    }
                    Frame::PunchDone(frame) => paths.puncher.recv_punch_done(link, frame),
                    _ => {
                        return Err(QuicError::with_default_fty(ErrorKind::ProtocolViolation, "unnegotiated frame").into());
                    }
                }
            }
            let pto = path.cc.get_pto(Epoch::Data);
            data.rcvd_journal.on_rcvd_pn(pn, content.is_ack_eliciting(), pto);
            path.cc.on_pkt_rcvd(Epoch::Data, pn, content.is_ack_eliciting());
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
    let terminator = paths.terminator.clone();
    loop {
        let now = Instant::now();
        paths.spaces.on_tick(now);
        tokio::select! {
            biased;
            _ = terminator.clone() => break,
            _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {},
        }
    }
}
