//! Each path owns one sending loop and reuses its batch storage.
use std::{
    collections::VecDeque,
    future::poll_fn,
    io::IoSlice,
    sync::{Arc, OnceLock},
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    frame::{AckFrame, PingFrame},
    net::tx::Signals,
    packet::{LongHeaderBuilder, OneRttHeader, Type},
    param::ParameterId,
    role::Role,
    varint::VarInt,
};
use qcongestion::Transport as _;
use qprotocol::QuicProtocol;
use qtransport::{
    GuaranteedFrame,
    path::{Path, PathState},
    send::{
        self,
        constraints::Constraints,
        write::{self, PendingPacket},
    },
    space::Space,
};

use crate::{
    ConnPhase, Error, Paths,
    terminate::{ArcTerminator, State},
};

fn ack_frame<K>(space: &Space<K>, path: &Path, exponent: u32) -> Option<AckFrame> {
    path.cc
        .need_ack(space.epoch)
        .and_then(|(pn, time)| space.rcvd_journal.gen_ack_frame_util(pn, time, 400).ok())
        .map(|ack| {
            AckFrame::new(
                VarInt::from_u64(ack.largest()).unwrap(),
                VarInt::from_u64(ack.delay() >> exponent).unwrap(),
                VarInt::from_u64(ack.first_range()).unwrap(),
                ack.ranges().clone(),
                ack.ecn(),
            )
        })
}

#[expect(
    clippy::too_many_arguments,
    reason = "storage is owned by the sending task"
)]
fn assemble_packet(
    phase: &ConnPhase,
    buffers: &mut Vec<BytesMut>,
    send_frames: &mut Vec<GuaranteedFrame>,
    pns: &mut VecDeque<PendingPacket>,
    signals: &mut Signals,
    constraints: &Constraints,
    next: &mut usize,
    path: &Path,
    preferred: bool,
    close: Option<&ArcTerminator>,
) -> Result<Option<PendingPacket>, Error> {
    let (initial, handshake, data, scid, exponent) = match phase {
        ConnPhase::Initial(phase) => (Some(phase.initial.as_ref()), None, None, phase.scid, 0),
        ConnPhase::Handshake(phase) => (
            Some(phase.initial.initial.as_ref()),
            Some(phase.handshake.as_ref()),
            None,
            phase.initial.scid,
            0,
        ),
        ConnPhase::Mature(phase) => (
            Some(phase.spaces.initial.as_ref()),
            Some(phase.spaces.handshake.as_ref()),
            Some(phase.spaces.data.as_ref()),
            phase.scid,
            phase.parameters.local::<u64>(ParameterId::AckDelayExponent) as u32,
        ),
    };

    for _ in 0..3 {
        let epoch = Epoch::EPOCHS[*next];
        *next = (*next + 1) % 3;
        if epoch != Epoch::Data && !preferred && close.is_none() {
            continue;
        }
        let mut source =
            (close.is_none() && preferred && (epoch != Epoch::Data || path.is_validated()))
                .then_some(phase);
        let mut close = close;
        let mut response = (close.is_none() && epoch == Epoch::Data)
            .then(|| path.response())
            .flatten();
        let mut challenge = (close.is_none() && epoch == Epoch::Data)
            .then(|| path.challenge())
            .flatten();
        let mut ping = (close.is_none()
            && (path.cc.need_send_ack_eliciting(epoch) != 0
                || (epoch == Epoch::Data
                    && path.activity.keep_alive_due(tokio::time::Instant::now()))))
        .then_some(PingFrame);
        let packet = if epoch == Epoch::Data {
            let Some(space) = data else { continue };
            let Ok(Some(keys)) = space.keys.try_get() else {
                continue;
            };
            let mut ack = close
                .is_none()
                .then(|| ack_frame(space, path, exponent))
                .flatten();
            send::assemble_1rtt_packet(
                path.pathway,
                &path.cc,
                buffers,
                send_frames,
                pns,
                signals,
                &keys,
                OneRttHeader::new(Default::default(), path.dcid()),
                &space.send_journal,
                constraints,
                [
                    &mut ack,
                    &mut source,
                    &mut close,
                    &mut response,
                    &mut challenge,
                    &mut ping,
                ],
            )?
        } else {
            let Some(space) = [initial, handshake][epoch as usize] else {
                continue;
            };
            let Ok(Some(keys)) = space.keys.try_get() else {
                continue;
            };
            let mut ack = close.is_none().then(|| ack_frame(space, path, 0)).flatten();
            let header = LongHeaderBuilder::with_cid(path.dcid(), scid);
            if epoch == Epoch::Initial {
                let mut multipath =
                    (source.is_some() && !path.is_selected()).then(|| space.crypto.multipath());
                if multipath.is_some() {
                    source = None;
                }
                send::assemble_long_packet(
                    path.pathway,
                    &path.cc,
                    buffers,
                    send_frames,
                    pns,
                    signals,
                    &keys.sealing,
                    header.initial(vec![]),
                    &space.send_journal,
                    constraints,
                    [&mut ack, &mut source, &mut multipath, &mut close, &mut ping],
                )?
            } else {
                send::assemble_long_packet(
                    path.pathway,
                    &path.cc,
                    buffers,
                    send_frames,
                    pns,
                    signals,
                    &keys.sealing,
                    header.handshake(),
                    &space.send_journal,
                    constraints,
                    [&mut ack, &mut source, &mut close, &mut ping],
                )?
            }
        };
        if packet.is_some() {
            return Ok(packet);
        }
    }
    Ok(None)
}

pub(crate) async fn sending(paths: Arc<Paths>, path: Arc<Path>) {
    let phase = paths.phase();
    let feedback = paths.feedback();
    let terminator = paths.terminator();
    let role = paths.role();
    let wakers = phase.send_wakers();
    let mut packets: Vec<IoSlice<'static>> = Vec::with_capacity(send::MAX_BURST_PACKETS);
    let mut buffers = (0..send::MAX_BURST_PACKETS)
        .map(|_| BytesMut::with_capacity(1200))
        .collect::<Vec<_>>();
    let mut pns = VecDeque::with_capacity(send::MAX_BURST_PACKETS);
    let mut send_frames = Vec::with_capacity(256);
    let mut signals = Signals::all();
    let cid = OnceLock::new();
    let mut borrowed_cid = None;
    let mut closing = false;
    let outcome: Result<(), Error> = async {
        loop {
            if path.state() == PathState::Retired {
                break;
            }
            let terminating = match terminator.lock_guard().state {
                State::Normal => false,
                State::Closing { .. } | State::Draining { .. } => true,
                State::Terminated => break,
            };
            if terminating && !closing {
                buffers.extend(pns.drain(..).map(PendingPacket::into_buffer));
                closing = true;
            }
            if !terminating {
                path.cc.do_tick().map_err(|error| {
                    QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string())
                })?;
            }
            let mut blocked = Signals::empty();
            {
                // No phase guard is held across a socket wait or a source wakeup.
                let phase = phase.lock_guard();
                if !path.is_selected() && path.dcid() == ConnectionId::default() {
                    let dcid = match &*phase {
                        ConnPhase::Initial(phase) => phase.odcid,
                        ConnPhase::Handshake(phase) => phase.initial.odcid,
                        ConnPhase::Mature(phase) => phase.peer_cid,
                    };
                    path.set_dcid(dcid);
                }
                let (initial, handshake) = match &*phase {
                    ConnPhase::Initial(phase) => (Some(phase.initial.as_ref()), None),
                    ConnPhase::Handshake(phase) => (
                        Some(phase.initial.initial.as_ref()),
                        Some(phase.handshake.as_ref()),
                    ),
                    ConnPhase::Mature(phase) => {
                        path.cc.set_ack_delays(
                            phase.parameters.local::<Duration>(ParameterId::MaxAckDelay),
                            phase
                                .parameters
                                .remote::<Duration>(ParameterId::MaxAckDelay),
                        );
                        feedback[Epoch::Data].start(phase.spaces.data.send_journal.clone());
                        if !terminating {
                            paths.start_validation(&path);
                            let cell = cid.get_or_init(|| {
                                if path.is_selected() {
                                    phase.initial_dcid.clone()
                                } else {
                                    phase.cid_registry.remote.apply_dcid()
                                }
                            });
                            if borrowed_cid.is_none() {
                                match cell.borrow_cid(path.send_waker.clone()) {
                                    Ok(Some(borrowed)) => {
                                        path.set_dcid(*borrowed);
                                        borrowed_cid = Some(borrowed);
                                    }
                                    Ok(None) => break,
                                    Err(signals) => blocked |= signals | Signals::KEYS,
                                }
                            }
                        }
                        (
                            Some(phase.spaces.initial.as_ref()),
                            Some(phase.spaces.handshake.as_ref()),
                        )
                    }
                };
                for space in [initial, handshake].into_iter().flatten() {
                    feedback[space.epoch].start(space.send_journal.clone());
                    if space.keys.try_get().is_err() {
                        feedback[space.epoch].retire();
                        path.cc.discard_epoch(space.epoch);
                    }
                }
                if let Some(space) = handshake {
                    match space.keys.try_get() {
                        Ok(Some(_)) => path.got_handshake_key(),
                        Err(_) => path.handshake_confirmed(),
                        Ok(None) => {}
                    }
                }
                if blocked.is_empty() && pns.is_empty() {
                    signals =
                        Signals::TRANSPORT | Signals::KEYS | Signals::PATH_VALIDATE | Signals::PING;
                    let mut constraints = Constraints {
                        capacity: 1200,
                        congestion: path.cc.send_quota().unwrap_or_else(|blocked| {
                            signals |= blocked;
                            0
                        }),
                        anti_amplification: path.anti_amplifier.balance(),
                    };
                    let mut next = 0;
                    while pns.len() < send::MAX_BURST_PACKETS {
                        let entries = paths.entries.lock().unwrap();
                        let preferred = entries
                            .values()
                            .find(|path| path.is_selected())
                            .or_else(|| entries.values().find(|path| path.is_validated()))
                            .is_none_or(|preferred| preferred.pathway == path.pathway);
                        let Some(packet) = assemble_packet(
                            &phase,
                            &mut buffers,
                            &mut send_frames,
                            &mut pns,
                            &mut signals,
                            &constraints,
                            &mut next,
                            &path,
                            preferred,
                            terminating.then_some(&terminator),
                        )?
                        else {
                            break;
                        };
                        drop(entries);
                        let length = packet.datagram.msg.len();
                        constraints.anti_amplification =
                            constraints.anti_amplification.saturating_sub(length);
                        if packet.in_flight {
                            constraints.congestion = constraints.congestion.saturating_sub(length);
                        }
                        pns.push_back(packet);
                    }
                }
            }
            if !blocked.is_empty() {
                path.send_waker.wait_for(blocked).await;
                continue;
            }
            let sent = poll_fn(|cx| {
                send::poll_send_with(
                    path.pathway,
                    &path.cc,
                    &path.anti_amplifier,
                    &mut buffers,
                    &mut pns,
                    &mut signals,
                    cx,
                    &mut packets,
                    |cx, pathway, packets| {
                        QuicProtocol::global().poll_send_datagrams(cx, pathway, packets)
                    },
                    |ty: Type| {
                        if matches!(terminator.lock_guard().state, State::Normal) == terminating {
                            return false;
                        }
                        if !terminating
                            && write::epoch(ty) != Epoch::Data
                            && paths.entries.lock().unwrap().values().any(|other| {
                                other.is_selected() && other.pathway != path.pathway
                            })
                        {
                            return false;
                        }
                        let phase = phase.lock_guard();
                        match (&*phase, write::epoch(ty)) {
                            (ConnPhase::Initial(phase), Epoch::Initial) => {
                                phase.initial.keys.try_get().is_ok()
                            }
                            (ConnPhase::Handshake(phase), Epoch::Initial) => {
                                phase.initial.initial.keys.try_get().is_ok()
                            }
                            (ConnPhase::Handshake(phase), Epoch::Handshake) => {
                                phase.handshake.keys.try_get().is_ok()
                            }
                            (ConnPhase::Mature(phase), Epoch::Initial) => {
                                phase.spaces.initial.keys.try_get().is_ok()
                            }
                            (ConnPhase::Mature(phase), Epoch::Handshake) => {
                                phase.spaces.handshake.keys.try_get().is_ok()
                            }
                            (ConnPhase::Mature(phase), Epoch::Data) => {
                                phase.spaces.data.keys.try_get().is_ok()
                            }
                            _ => false,
                        }
                    },
                    |packet| {
                        path.on_packet_sent(packet);
                        path.activity.on_sent(packet.content);
                        if role == Role::Client && packet.epoch() == Epoch::Handshake {
                            match &*phase.lock_guard() {
                                ConnPhase::Handshake(phase) => phase.initial.initial.retire(),
                                ConnPhase::Mature(phase) => phase.spaces.initial.retire(),
                                _ => {}
                            }
                        }
                    },
                )
            })
            .await?;
            if pns.is_empty() {
                borrowed_cid.take();
            }
            if sent == 0 {
                if matches!(terminator.lock_guard().state, State::Draining { .. }) {
                    break;
                }
                path.send_waker.wait_for(signals).await;
            } else {
                tokio::task::yield_now().await;
            }
        }
        Ok(())
    }
    .await;
    buffers.extend(pns.drain(..).map(PendingPacket::into_buffer));
    borrowed_cid.take();
    if let Some(cid) = cid.get() {
        cid.retire();
    }
    paths.remove(&path);
    wakers.remove_if(&path.pathway, &path.send_waker);
    if let Err(error) = outcome
        && (error.kind() != ErrorKind::NoViablePath || paths.snapshot().is_empty())
    {
        paths.on_error(error);
    }
}

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};
    use qbase::{
        frame::{Frame, FrameReader},
        net::{addr::EndpointAddr, route::Pathway},
        packet::{DataHeader, Packet, PacketReader, long},
        time::ArcConnIdle,
    };
    use qtransport::{keys::ArcKeys, packet::CipherPacket, space::ArcFeedback};
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::{HandshakePhase, InitialPhase};

    fn keys(server: bool) -> qtls::BidirectionalKeys {
        qtls::default_provider()
            .cipher_suites
            .iter()
            .find_map(|suite| suite.tls13().and_then(|suite| suite.quic_suite()))
            .unwrap()
            .keys(
                b"original",
                if server {
                    tls_backend::Side::Server
                } else {
                    tls_backend::Side::Client
                },
                tls_backend::quic::Version::V1,
            )
            .into()
    }

    #[tokio::test]
    async fn idle_sending_loop_waits_for_sources_and_exits_when_retired() {
        let phase = crate::ArcConnPhase::initial(InitialPhase::new(
            ConnectionId::from_slice(b"clientid"),
            ConnectionId::from_slice(b"original"),
            keys(false),
        ));
        let idle = ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
        let paths = Paths::new(Role::Client, phase.clone(), idle.clone());
        let pathway = Pathway::new(
            EndpointAddr::direct("127.0.0.1:30001".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:30002".parse().unwrap()),
        );
        let path = Arc::new(Path::new(
            pathway,
            Role::Client,
            idle.timer(),
            paths
                .feedback()
                .map(|feedback| Arc::new(feedback) as Arc<dyn qcongestion::Feedback>),
        ));
        path.client_handshaking();
        phase.send_wakers().replace(pathway, &path.send_waker);
        let watchdog = std::thread::spawn({
            let path = path.clone();
            move || {
                std::thread::sleep(Duration::from_millis(50));
                path.retire();
            }
        });
        let mut running = Box::pin(sending(paths, path));
        assert!(futures::poll!(&mut running).is_pending());
        watchdog.join().unwrap();
        running.await;
    }

    #[tokio::test]
    async fn burst_advances_large_initial_crypto_and_includes_handshake_without_replaying_prefix() {
        let initial = Arc::new(InitialPhase::new(
            ConnectionId::from_slice(b"clientid"),
            ConnectionId::from_slice(b"original"),
            keys(false),
        ));
        let message = vec![42; 7200];
        initial
            .initial
            .crypto
            .writer()
            .write_all(&message)
            .await
            .unwrap();
        let handshake = Arc::new(Space::<ArcKeys>::new(
            Epoch::Handshake,
            initial.initial.send_wakers.clone(),
            |_| {},
        ));
        handshake.keys.install(Arc::new(keys(false))).unwrap();
        handshake
            .crypto
            .writer()
            .write_all(b"handshake")
            .await
            .unwrap();
        let phase = ConnPhase::Handshake(Arc::new(HandshakePhase {
            initial: initial.clone(),
            handshake,
            terminator: initial.terminator.clone(),
        }));
        let pathway = Pathway::new(
            EndpointAddr::direct("127.0.0.1:30001".parse().unwrap()),
            EndpointAddr::direct("127.0.0.1:30002".parse().unwrap()),
        );
        let path = Path::new(
            pathway,
            Role::Client,
            ArcConnIdle::new(Duration::ZERO, Duration::ZERO, Duration::ZERO).timer(),
            std::array::from_fn(|_| {
                Arc::new(ArcFeedback::default()) as Arc<dyn qcongestion::Feedback>
            }),
        );
        path.client_handshaking();
        path.select();
        path.set_dcid(initial.odcid);
        let mut buffers = (0..send::MAX_BURST_PACKETS)
            .map(|_| BytesMut::with_capacity(1200))
            .collect();
        let mut pns = VecDeque::new();
        let mut frames = Vec::new();
        let mut signals = Signals::empty();
        let mut next = 0;
        let mut constraints = Constraints {
            capacity: 1200,
            congestion: path.cc.send_quota().unwrap(),
            anti_amplification: usize::MAX,
        };
        while pns.len() < send::MAX_BURST_PACKETS {
            let Some(packet) = assemble_packet(
                &phase,
                &mut buffers,
                &mut frames,
                &mut pns,
                &mut signals,
                &constraints,
                &mut next,
                &path,
                true,
                None,
            )
            .unwrap() else {
                break;
            };
            if packet.in_flight {
                constraints.congestion = constraints
                    .congestion
                    .saturating_sub(packet.datagram.msg.len());
            }
            pns.push_back(packet);
        }
        assert_eq!(pns.len(), send::MAX_BURST_PACKETS);
        assert!(
            pns.iter()
                .map(|packet| packet.datagram.msg.len())
                .sum::<usize>()
                > 8192
        );
        let epochs = pns.iter().map(PendingPacket::epoch).collect::<Vec<_>>();
        assert_eq!(&epochs[..2], &[Epoch::Initial, Epoch::Handshake]);
        let peer = keys(true);
        let mut recovered = Vec::new();
        for packet in pns.iter().filter(|packet| packet.epoch() == Epoch::Initial) {
            let Packet::Data(parsed) = PacketReader::new(BytesMut::from(packet.bytes()), 8)
                .next()
                .unwrap()
                .unwrap()
            else {
                panic!()
            };
            let DataHeader::Long(long::DataHeader::Initial(header)) = parsed.header else {
                panic!()
            };
            let opened = CipherPacket::new(header, parsed.bytes, parsed.offset)
                .decrypt_long_packet(&peer.opening, |_| Ok(packet.pn))
                .unwrap()
                .unwrap();
            for frame in FrameReader::new(opened.body(), packet.packet_type) {
                if let Frame::Crypto(frame, bytes) = frame.unwrap().0 {
                    assert_eq!(frame.offset(), recovered.len() as u64);
                    recovered.extend_from_slice(Bytes::as_ref(&bytes));
                }
            }
        }
        assert_eq!(recovered, message);

        // A fresh burst on the selected path must not make flighting CRYPTO sendable again.
        let _submitted = std::mem::take(&mut pns);
        assert!(
            assemble_packet(
                &phase,
                &mut buffers,
                &mut frames,
                &mut pns,
                &mut signals,
                &constraints,
                &mut next,
                &path,
                true,
                None,
            )
            .unwrap()
            .is_none()
        );
    }
}
