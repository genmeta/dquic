pub(crate) mod constraints;
pub(crate) mod packet;

use std::{
    io::IoSlice,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use bytes::BytesMut;
use constraints::Constraints;
use packet::{HandshakePacket, InitialPacket, OneRttPacket, PacketError};
use qbase::{
    Epoch,
    error::{Error, ErrorKind, QuicError},
    frame::{ConnectionCloseFrame, PingFrame},
    net::tx::Signals,
    packet::{LongHeaderBuilder, OneRttHeader},
    role::Role,
};
use qcongestion::Transport as _;
use tokio::{sync::mpsc, time::Instant};

use crate::{
    control::{Command, Phase},
    path::{Event, Path},
    transport::Transport,
};

/// Exactly one sender owns each Path's socket completion and ACK queue. ACKs
/// arriving during send().await are processed after its journal/CC commit.
pub(crate) async fn send_loop(
    transport: Arc<Transport>,
    path: Arc<Path>,
    mut events: mpsc::Receiver<Event>,
) {
    let mut crypto = [None, None, None];
    let mut close_sent = false;
    let mut next_tick = Instant::now();
    let outcome: Result<(), Error> = async {
        loop {
            // A ready send signal can persist while AA/cwnd blocks assembly.
            // Always yield so that receives and retirement commands can progress.
            tokio::task::yield_now().await;
            while let Ok(event) = events.try_recv() {
                match event {
                    Event::Response(response) => path.on_response(response),
                    Event::Retire(epoch, done) => {
                        crypto[epoch as usize] = None;
                        path.cc.discard_epoch(epoch);
                        let _ = done.send(());
                    }
                    Event::Ack(epoch, ack) => {
                        if let Some((_, _, _, _, journal)) = transport.spaces.snapshot(epoch) {
                            let frames = {
                                let mut journal = journal.rotate();
                                journal.update_largest(&ack)?;
                                journal.on_packets_acked(&ack).collect::<Vec<_>>()
                            };
                            transport.spaces.acked(epoch, frames);
                            path.cc.on_ack_rcvd(epoch, &ack);
                            if epoch == Epoch::Handshake {
                                transport.control.handshake.received_handshake_ack();
                            }
                        }
                    }
                }
            }
            if transport.stop.is_cancelled() {
                return Ok(());
            }
            let phase = *transport.control.phase.borrow();
            let closing = transport.close.reason();
            let dormant = transport
                .paths
                .preferred()
                .is_some_and(|selected| selected != path.pathway);
            let validating = path.challenge.lock().unwrap().is_some();
            if path.amplification_credit() >= 1200 {
                path.status.release_anti_amplification_limit();
            } else {
                path.status.enter_anti_amplification_limit();
            }
            if closing.is_none() && (!dormant || validating) {
                if Instant::now() >= next_tick {
                    next_tick = Instant::now() + Duration::from_millis(10);
                    path.cc.do_tick().map_err(|error| {
                        QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string())
                    })?;
                }
                if path
                    .idle
                    .timed_out(Instant::now(), path.cc.pto_base(Epoch::Data))
                {
                    return Err(QuicError::with_default_fty(
                        ErrorKind::None,
                        "connection idle timeout",
                    )
                    .into());
                }
            }
            let mut progress = false;
            let enabled = transport.spaces.enabled.load(Ordering::Acquire);
            let epochs = if closing.is_some() {
                [Epoch::Data, Epoch::Handshake, Epoch::Initial]
            } else {
                [Epoch::Initial, Epoch::Handshake, Epoch::Data]
            };
            for epoch in epochs {
                if enabled & (1 << epoch as usize) == 0
                    || matches!(phase, Phase::Draining | Phase::Closed)
                {
                    continue;
                }
                if closing.is_some() && close_sent {
                    break;
                }
                if dormant && (epoch != Epoch::Data || phase != Phase::Active) {
                    continue;
                }
                if transport.control.role == Role::Server
                    && epoch != Epoch::Initial
                    && transport.paths.selected.get().is_none()
                {
                    continue;
                }
                let Some((header_key, packet_key, stream, received, journal)) =
                    transport.spaces.snapshot(epoch)
                else {
                    continue;
                };
                let mut ack = path
                    .cc
                    .need_ack(epoch)
                    .and_then(|(pn, time)| received.gen_ack_frame_util(pn, time, 400).ok());
                let probe = path.cc.need_send_ack_eliciting(epoch) != 0;
                let mut ping = probe.then_some(PingFrame);
                let quota = path
                    .cc
                    .send_quota()
                    .unwrap_or(0)
                    .max(if probe { 1200 } else { 0 });
                let mut constraints = Constraints {
                    capacity: 1200,
                    congestion: quota,
                    anti_amplification: path.amplification_credit(),
                };
                let dcid = transport
                    .peer_cid
                    .get()
                    .copied()
                    .unwrap_or(transport.original_dcid);
                let mut close: Option<ConnectionCloseFrame> = closing.clone().map(|error| {
                    if epoch != Epoch::Data && matches!(error, Error::App(_)) {
                        Error::Quic(QuicError::with_default_fty(
                            ErrorKind::Application,
                            "application closed during handshake",
                        ))
                        .into()
                    } else {
                        error.into()
                    }
                });
                let source =
                    crypto[epoch as usize].get_or_insert_with(|| stream.outgoing().package(epoch));
                let mut challenge = {
                    let state = path.challenge.lock().unwrap();
                    match *state {
                        Some((_, due, 3..)) if Instant::now() >= due => {
                            return Err(QuicError::with_default_fty(
                                ErrorKind::NoViablePath,
                                "path validation timed out",
                            )
                            .into());
                        }
                        Some((frame, due, _)) if epoch == Epoch::Data && Instant::now() >= due => {
                            Some(frame)
                        }
                        _ => None,
                    }
                };
                let pending = {
                    let mut reservation = journal.new_packet();
                    let pn = reservation.pn().0;
                    macro_rules! assemble {
                        ($packet:ty, $header:expr, $sources:expr) => {{
                            let mut packet = <$packet>::new(
                                BytesMut::zeroed(1200),
                                $header,
                                header_key,
                                packet_key,
                                pn,
                                false,
                            )
                            .map_err(|error| crate::internal(error.to_string()))?;
                            let assembled = if closing.is_some() {
                                packet.assemble(&mut constraints, [&mut close])
                            } else {
                                packet.assemble(&mut constraints, $sources)
                            };
                            match assembled {
                                Err(PacketError::Blocked(_)) => None,
                                Err(error) => return Err(crate::internal(error.to_string())),
                                Ok(content) => {
                                    if epoch == Epoch::Initial
                                        && (transport.control.role == Role::Client
                                            || content.is_ack_eliciting())
                                    {
                                        if packet.pad_to(1200, &mut constraints).is_err() {
                                            transport
                                                .spaces
                                                .requeue(epoch, packet.abort(&mut constraints));
                                            None
                                        } else {
                                            Some(packet)
                                        }
                                    } else if packet.frames().iter().any(|frame| {
                                        matches!(
                                            frame,
                                            qbase::frame::Frame::PathChallenge(_)
                                                | qbase::frame::Frame::PathResponse(_)
                                        )
                                    }) {
                                        if packet.pad_to(1200, &mut constraints).is_err() {
                                            transport
                                                .spaces
                                                .requeue(epoch, packet.abort(&mut constraints));
                                            None
                                        } else {
                                            Some(packet)
                                        }
                                    } else {
                                        Some(packet)
                                    }
                                }
                            }
                            .map(|mut packet| {
                                for frame in packet.frames() {
                                    reservation.record_frame(frame.clone());
                                }
                                reservation.record_trivial();
                                reservation.build_pending();
                                packet.seal()
                            })
                            .transpose()
                        }};
                    }
                    let sealed = match epoch {
                        Epoch::Initial => assemble!(
                            InitialPacket,
                            LongHeaderBuilder::with_cid(dcid, transport.local_cid).initial(vec![]),
                            [&mut ack, source, &mut ping]
                        ),
                        Epoch::Handshake => assemble!(
                            HandshakePacket,
                            LongHeaderBuilder::with_cid(dcid, transport.local_cid).handshake(),
                            [&mut ack, source, &mut ping]
                        ),
                        Epoch::Data => {
                            let mut reliable = transport.reliable.clone();
                            let mut response = path.responses.lock().unwrap().front().copied();
                            if dormant
                                || (transport.control.role == Role::Server
                                    && !path.validated.load(Ordering::Acquire))
                            {
                                assemble!(
                                    OneRttPacket,
                                    OneRttHeader::new(Default::default(), dcid),
                                    [&mut ack, &mut response, &mut challenge, &mut ping]
                                )
                            } else if let Some(data) = transport.data.get() {
                                let mut streams =
                                    data.streams.package(data.flow.sender.clone(), false);
                                assemble!(
                                    OneRttPacket,
                                    OneRttHeader::new(Default::default(), dcid),
                                    [
                                        &mut ack,
                                        source,
                                        &mut response,
                                        &mut challenge,
                                        &mut reliable,
                                        &mut streams,
                                        &mut ping
                                    ]
                                )
                            } else {
                                assemble!(
                                    OneRttPacket,
                                    OneRttHeader::new(Default::default(), dcid),
                                    [&mut ack, source, &mut response, &mut reliable, &mut ping]
                                )
                            }
                        }
                    };
                    match sealed {
                        Ok(pending) => pending,
                        Err(error) => {
                            transport.spaces.requeue(epoch, journal.cancel_pending(pn));
                            return Err(crate::internal(error.to_string()));
                        }
                    }
                };
                let Some(pending) = pending else { continue };
                debug_assert_eq!(pending.epoch, epoch);
                if transport.spaces.enabled.load(Ordering::Acquire) & (1 << epoch as usize) == 0 {
                    let pn = pending.pn;
                    pending.abort(&mut constraints);
                    transport.spaces.requeue(epoch, journal.cancel_pending(pn));
                    continue;
                }
                let packet = [IoSlice::new(&pending.bytes)];
                let sent = tokio::select! {
                    _ = transport.stop.cancelled() => {
                        transport.spaces.requeue(epoch, journal.cancel_pending(pending.pn));
                        return Ok(())
                    }
                    result = transport.protocol.send(path.pathway, &packet) => result,
                };
                if let Err(error) = sent {
                    transport
                        .spaces
                        .requeue(epoch, journal.cancel_pending(pending.pn));
                    return Err(QuicError::with_default_fty(
                        ErrorKind::NoViablePath,
                        error.to_string(),
                    )
                    .into());
                }
                let (retransmit, expire) = path.cc.retransmit_and_expire_time(epoch);
                assert!(
                    journal.mark_sent(pending.pn, retransmit, expire),
                    "pending packet must be committed once"
                );
                path.sent
                    .fetch_add(pending.bytes.len() as u64, Ordering::AcqRel);
                path.cc.on_pkt_sent(
                    epoch,
                    pending.pn,
                    pending.content.is_ack_eliciting(),
                    pending.bytes.len(),
                    pending.in_flight,
                    pending.ack,
                );
                path.idle.on_sent(pending.content);
                for frame in &pending.frames {
                    if let qbase::frame::Frame::PathChallenge(sent) = frame {
                        let mut challenge = path.challenge.lock().unwrap();
                        if let Some((frame, due, count)) = challenge.as_mut() {
                            if frame == sent {
                                *count += 1;
                                *due = Instant::now()
                                    + path
                                        .cc
                                        .pto_base(Epoch::Data)
                                        .max(Duration::from_millis(100))
                                        * 3;
                            }
                        }
                    }
                    if let qbase::frame::Frame::PathResponse(response) = frame {
                        let mut responses = path.responses.lock().unwrap();
                        if responses.front() == Some(response) {
                            responses.pop_front();
                        }
                    }
                }
                if epoch == Epoch::Handshake
                    && transport.control.role == Role::Client
                    && transport.spaces.enabled.fetch_and(!1, Ordering::AcqRel) & 1 != 0
                {
                    transport
                        .control
                        .commands
                        .send(Command::HandshakeSent)
                        .await
                        .map_err(|_| crate::internal("receive task stopped"))?;
                }
                progress = true;
                if closing.is_some() {
                    close_sent = true;
                    break;
                }
            }
            if progress {
                tokio::task::yield_now().await;
                continue;
            }
            // Reserve before waiting so a queued ACK/retirement cannot be missed.
            tokio::select! {
                _ = transport.stop.cancelled() => return Ok(()),
                _ = path.wake.wait_for(Signals::all()) => {},
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
    }
    .await;
    if let Err(error) = outcome {
        if error.kind() != ErrorKind::NoViablePath {
            transport.close.request(error);
            return;
        }
        path.failed.store(true, Ordering::Release);
        path.cc.on_path_lost();
        transport.wakers.wake_all_by(Signals::TRANSPORT);
        if !transport
            .paths
            .snapshot()
            .iter()
            .any(|path| !path.failed.load(Ordering::Acquire))
        {
            transport.close.request(error);
        }
    }
}
