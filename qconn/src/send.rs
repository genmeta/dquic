//! Path tasks use shared sending material; phases never own paths.
use std::{
    future::poll_fn,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use qbase::{
    ArcReceiving, Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    frame::{AckFrame, PingFrame},
    net::{route::Pathway, tx::Signals},
    packet::{LongHeaderBuilder, OneRttHeader, Type, io::Repeat},
    param::ParameterId,
    role::Role,
    time::ArcConnIdle,
    varint::VarInt,
};
use qcongestion::{HandshakeStatus, Transport as _};
use qprotocol::QuicProtocol;
use qtransport::{
    keys::ArcKeys,
    path::{Path, PathState},
    send::{Burst, constraints::Constraints, write::PendingPacket},
    space::{ArcFeedback, Space},
};
use tokio::time::Instant;

use crate::{ArcConnPhase, ConnPhase, Error, MaturePhase, Paths, terminator::Terminator};

/// A connection's path registration closure. It starts the path's only send task directly.
pub type AddPath = Arc<dyn Fn(Pathway) -> Result<Arc<Path>, Error> + Send + Sync>;

#[allow(clippy::too_many_arguments)]
pub(crate) fn sender(
    paths: Arc<Paths>,
    selected: Arc<OnceLock<Pathway>>,
    peer_cid: Arc<OnceLock<ConnectionId>>,
    original_dcid: ConnectionId,
    status: Arc<HandshakeStatus>,
    feedback: [ArcFeedback; 3],
    authenticated: Arc<AtomicBool>,
    confirmed: Arc<AtomicBool>,
    terminator: Arc<Terminator>,
    sent_hs_packet: ArcReceiving<bool>,
    on_error: Arc<dyn Fn(Error) + Send + Sync>,
    idle: ArcConnIdle,
    role: Role,
) -> AddPath {
    let phase = paths.phase();
    Arc::new(move |pathway| {
        paths.get_or_try_insert_with(pathway, || {
            if terminator.closing.load(Ordering::Acquire)
                || terminator.terminated.load(Ordering::Acquire)
            {
                return Err(QuicError::with_default_fty(
                    ErrorKind::NoViablePath,
                    "connection is closing",
                )
                .into());
            }
            let snapshot = phase.get();
            let delay = match &snapshot {
                ConnPhase::Initial(_) | ConnPhase::Connecting(_) => Duration::from_millis(25),
                ConnPhase::Handshaking(sender) | ConnPhase::Mature(sender) => {
                    sender.parameters.remote(ParameterId::MaxAckDelay).unwrap()
                }
            };
            let path = Arc::new(Path::new(
                pathway,
                peer_cid.get().copied().unwrap_or(original_dcid),
                status.clone(),
                delay,
                idle.timer(),
                feedback
                    .each_ref()
                    .map(|f| Arc::new(f.clone()) as Arc<dyn qcongestion::Feedback>),
            ));
            if role == Role::Client {
                path.grant_amplification();
            }
            if confirmed.load(Ordering::Acquire) {
                path.start_validation();
            }
            snapshot
                .initial()
                .send_wakers
                .replace(pathway, &path.send_waker);
            tokio::spawn(send_path(
                phase.clone(),
                path.clone(),
                paths.clone(),
                selected.clone(),
                status.clone(),
                feedback.clone(),
                authenticated.clone(),
                confirmed.clone(),
                terminator.clone(),
                sent_hs_packet.clone(),
                on_error.clone(),
                role,
            ));
            Ok(path)
        })
    })
}

fn preferred(paths: &Paths, selected: &OnceLock<Pathway>, path: &Path) -> bool {
    selected
        .get()
        .and_then(|way| paths.get(way))
        .or_else(|| paths.snapshot().into_iter().find(|p| p.is_validated()))
        .is_none_or(|p| p.pathway == path.pathway)
}

pub(crate) fn confirm(
    paths: &Paths,
    selected: &OnceLock<Pathway>,
    status: &HandshakeStatus,
    confirmed: &AtomicBool,
    role: Role,
) {
    confirmed.store(true, Ordering::Release);
    status.handshake_confirmed();
    for path in paths.snapshot() {
        if selected.get() == Some(&path.pathway) {
            path.validate();
        } else if role == Role::Client {
            path.start_validation();
        }
        path.send_waker.wake_by(Signals::all());
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_path(
    phase: ArcConnPhase,
    path: Arc<Path>,
    paths: Arc<Paths>,
    selected: Arc<OnceLock<Pathway>>,
    status: Arc<HandshakeStatus>,
    feedback: [ArcFeedback; 3],
    authenticated: Arc<AtomicBool>,
    confirmed: Arc<AtomicBool>,
    terminator: Arc<Terminator>,
    sent_hs_packet: ArcReceiving<bool>,
    on_error: Arc<dyn Fn(Error) + Send + Sync>,
    role: Role,
) {
    let wakers = phase.get().initial().send_wakers.clone();
    let mut burst = Burst::new(
        QuicProtocol::global().clone(),
        path.pathway,
        path.cc.clone(),
        path.anti_amplifier.clone(),
        path.send_waker.clone(),
    );
    let cid = OnceLock::new();
    let mut borrowed_cid = None;
    let mut next_close = Instant::now();
    let mut close_serial = None;
    let mut closing = false;
    let mut negotiated = false;
    let mut retired = [false; 2];
    let outcome: Result<(), Error> = async {
        loop {
            if path.state() == PathState::Retired {
                break;
            }
            let snapshot = phase.get();
            if !negotiated && let Some(sender) = snapshot.material() {
                path.cc.set_ack_delays(
                    sender.parameters.local(ParameterId::MaxAckDelay).unwrap(),
                    sender
                        .parameters
                        .remote(ParameterId::MaxAckDelay)
                        .unwrap(),
                );
                negotiated = true;
            }
            if snapshot
                .handshake()
                .is_some_and(|space| space.keys.try_get().is_ok_and(|keys| keys.is_some()))
            {
                status.got_handshake_key();
            }
            for space in std::iter::once(snapshot.initial()).chain(snapshot.handshake()) {
                if space.keys.try_get().is_err() && !retired[space.epoch as usize] {
                    retired[space.epoch as usize] = true;
                    feedback[space.epoch].retire();
                    path.cc.discard_epoch(space.epoch);
                }
            }
            let sent = if terminator.closing.load(Ordering::Acquire) {
                if !closing {
                    burst.cancel_pending();
                    closing = true;
                }
                let serial = terminator.received.load(Ordering::Acquire);
                if burst.pending().next().is_some()
                    || (close_serial != Some(serial) && Instant::now() >= next_close)
                {
                    let sent = tokio::select! {
                        sent = crate::terminator::send_close(&terminator, &snapshot, &path, &mut burst) => sent?,
                        _ = path.send_waker.wait_for(Signals::all()) => 0,
                        _ = tokio::time::sleep(Duration::from_millis(10)) => 0,
                    };
                    if sent != 0 {
                        close_serial = Some(serial);
                        next_close = Instant::now() + path.cc.pto_base(Epoch::Data);
                    }
                    sent
                } else {
                    0
                }
            } else {
                path.cc.do_tick().map_err(|error| {
                    QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string())
                })?;
                if confirmed.load(Ordering::Acquire)
                    && let Some(material) = snapshot.material()
                {
                    let cell = cid.get_or_init(|| {
                        if selected.get() == Some(&path.pathway) {
                            material.initial_dcid.clone()
                        } else {
                            material.remote_cids.apply_dcid()
                        }
                    });
                    if borrowed_cid.is_none() {
                        match cell.borrow_cid(path.send_waker.clone()) {
                            Ok(Some(borrowed)) => {
                                if path.dcid() != *borrowed {
                                    path.set_dcid(*borrowed);
                                }
                                borrowed_cid = Some(borrowed);
                            }
                            Ok(None) => break,
                            Err(signals) => {
                                path.send_waker.wait_for(signals | Signals::KEYS).await;
                                continue;
                            }
                        }
                    }
                }
                let preferred = preferred(&paths, &selected, &path);
                burst.burst(|burst, constraints| {
                    for space in std::iter::once(snapshot.initial().as_ref())
                        .chain(snapshot.handshake().map(AsRef::as_ref))
                    {
                        if let Some(packet) = assemble_long(
                            space, snapshot.scid(), burst, &path, constraints, preferred,
                        )? {
                            return Ok(Some(packet));
                        }
                    }
                    match &snapshot {
                        ConnPhase::Handshaking(material) | ConnPhase::Mature(material) if authenticated.load(Ordering::Acquire) => {
                            assemble_1rtt(material, burst, &path, constraints, preferred)
                        }
                        _ => Ok(None),
                    }
                })?;
                tokio::select! {
                    result = poll_fn(|cx| burst.poll_send(
                        cx,
                        |ty| {
                            use qbase::packet::r#type::long::{Type as Long, Ver1};
                            if terminator.closing.load(Ordering::Acquire) {
                                return false;
                            }
                            match ty {
                                Type::Long(Long::V1(Ver1::INITIAL)) => snapshot.initial().keys.try_get().is_ok(),
                                Type::Long(Long::V1(Ver1::HANDSHAKE)) => snapshot.handshake().is_some_and(|space| space.keys.try_get().is_ok()),
                                Type::Short(_) => snapshot.material().is_some_and(|material| material.spaces.data.keys.try_get().is_ok()),
                                _ => false,
                            }
                        },
                        |packet| {
                            path.on_packet_sent(packet);
                            path.activity.on_sent(packet.content);
                            if role == Role::Client && packet.epoch() == Epoch::Handshake {
                                sent_hs_packet.set(true);
                            }
                        },
                    )) => result?,
                    _ = path.send_waker.wait_for(Signals::all()) => 0,
                    _ = tokio::time::sleep(Duration::from_millis(10)) => 0,
                }
            };
            if burst.pending().next().is_none() {
                borrowed_cid.take();
            }
            if sent != 0 {
                tokio::task::yield_now().await;
                continue;
            }
            tokio::select! {
                _ = burst.wait() => {},
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
        Ok(())
    }
    .await;
    burst.cancel_pending();
    borrowed_cid.take();
    if let Some(cid) = cid.get() {
        cid.retire();
    }
    paths.remove(&path);
    wakers.remove_if(&path.pathway, &path.send_waker);
    if let Err(error) = outcome
        && (error.kind() != ErrorKind::NoViablePath || paths.snapshot().is_empty())
    {
        on_error(error);
    }
}

fn assemble_long(
    space: &Space<ArcKeys>,
    scid: ConnectionId,
    burst: &mut Burst,
    path: &Path,
    constraints: &Constraints,
    preferred: bool,
) -> Result<Option<PendingPacket>, Error> {
    let Ok(Some(keys)) = space.keys.try_get() else {
        return Ok(None);
    };
    let mut ack = ack_frame(space, path, 0);
    let mut crypto = preferred.then(|| space.crypto.outgoing().package(space.epoch));
    let mut ping = (path.cc.need_send_ack_eliciting(space.epoch) != 0).then_some(PingFrame);
    let header = LongHeaderBuilder::with_cid(path.dcid(), scid);
    match space.epoch {
        Epoch::Initial => burst.assemble_initial_packet(
            &keys.sealing,
            header.initial(vec![]),
            &space.send_journal,
            constraints,
            [&mut ack, &mut crypto, &mut ping],
        ),
        Epoch::Handshake => burst.assemble_handshake_packet(
            &keys.sealing,
            header.handshake(),
            &space.send_journal,
            constraints,
            [&mut ack, &mut crypto, &mut ping],
        ),
        Epoch::Data => unreachable!(),
    }
}

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

fn assemble_1rtt(
    material: &MaturePhase,
    burst: &mut Burst,
    path: &Path,
    constraints: &Constraints,
    preferred: bool,
) -> Result<Option<PendingPacket>, Error> {
    let Ok(Some(keys)) = material.spaces.data.keys.try_get() else {
        return Ok(None);
    };
    let exponent = material
        .parameters
        .local::<u64>(ParameterId::AckDelayExponent)
        .unwrap() as u32;
    let mut ack = ack_frame(&material.spaces.data, path, exponent);
    let mut response = path.response();
    let mut challenge = path.challenge()?;
    let mut crypto = material.spaces.data.crypto.outgoing().package(Epoch::Data);
    let mut reliable = material.reliable_frames.clone();
    let mut streams = Repeat(
        material
            .streams
            .package(material.flow.sender.clone(), false),
    );
    let mut ping = (path.cc.need_send_ack_eliciting(Epoch::Data) != 0
        || path.activity.keep_alive_due(Instant::now()))
    .then_some(PingFrame);
    let header = OneRttHeader::new(Default::default(), path.dcid());
    if !path.is_validated() || !preferred {
        burst.assemble_1rtt_packet(
            &keys,
            header,
            &material.spaces.data.send_journal,
            constraints,
            [&mut ack, &mut response, &mut challenge, &mut ping],
        )
    } else {
        burst.assemble_1rtt_packet(
            &keys,
            header,
            &material.spaces.data.send_journal,
            constraints,
            [
                &mut ack,
                &mut crypto,
                &mut response,
                &mut challenge,
                &mut reliable,
                &mut ping,
                &mut streams,
            ],
        )
    }
}
