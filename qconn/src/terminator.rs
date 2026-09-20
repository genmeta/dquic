//! Close-only traffic keeps the existing path tasks and packet decoders alive.
use std::{
    future::poll_fn,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use qbase::{
    ArcReceiving, Epoch,
    error::{ErrorKind, QuicError},
    frame::ConnectionCloseFrame,
    packet::{LongHeaderBuilder, OneRttHeader},
};
use qcongestion::Transport as _;
use qtransport::{path::Path, send::Burst};
use tokio::time::Instant;

use crate::{ArcConnPhase, CloseReason, ConnPhase, Error, Paths};

#[derive(Default)]
pub(crate) struct Terminator {
    pub terminated: AtomicBool,
    pub closing: Arc<AtomicBool>,
    pub draining: AtomicBool,
    pub received: AtomicU64,
    pub peer_closed: ArcReceiving<()>,
    frame: OnceLock<Error>,
}

pub(crate) async fn send_close(
    terminator: &Terminator,
    phase: &ConnPhase,
    path: &Path,
    burst: &mut Burst,
) -> Result<usize, Error> {
    let initial = phase.initial();
    if terminator.draining.load(Ordering::Acquire) {
        burst.cancel_pending();
        return Ok(0);
    }
    let Some(error) = terminator.frame.get() else {
        return Ok(0);
    };
    let mut assembled = [false; 3];
    burst.burst(|burst, constraints| {
        for epoch in [Epoch::Data, Epoch::Handshake, Epoch::Initial] {
            if assembled[epoch] {
                continue;
            }
            assembled[epoch] = true;
            if epoch == Epoch::Data {
                if let Some(sender) = phase.material()
                    && let Ok(Some(keys)) = sender.spaces.data.keys.try_get()
                {
                    let mut frame = ConnectionCloseFrame::from(error.clone());
                    if let Some(packet) = burst.assemble_1rtt_packet(
                        &keys,
                        OneRttHeader::new(Default::default(), path.dcid()),
                        &sender.spaces.data.send_journal,
                        constraints,
                        [&mut frame],
                    )? {
                        return Ok(Some(packet));
                    }
                }
            } else {
                let Some(space) = (if epoch == Epoch::Initial {
                    Some(initial.as_ref())
                } else {
                    phase.handshake().map(AsRef::as_ref)
                }) else {
                    continue;
                };
                let Ok(Some(keys)) = space.keys.try_get() else {
                    continue;
                };
                let mut frame = ConnectionCloseFrame::from(match error {
                    Error::App(_) => QuicError::with_default_fty(ErrorKind::Application, "").into(),
                    error => error.clone(),
                });
                let header = LongHeaderBuilder::with_cid(path.dcid(), phase.scid());
                let packet = if epoch == Epoch::Initial {
                    burst.assemble_initial_packet(
                        &keys.sealing,
                        header.initial(vec![]),
                        &space.send_journal,
                        constraints,
                        [&mut frame],
                    )?
                } else {
                    burst.assemble_handshake_packet(
                        &keys.sealing,
                        header.handshake(),
                        &space.send_journal,
                        constraints,
                        [&mut frame],
                    )?
                };
                if packet.is_some() {
                    return Ok(packet);
                }
            }
        }
        Ok(None)
    })?;
    poll_fn(|cx| {
        burst.poll_send(
            cx,
            |_| {
                !terminator.terminated.load(Ordering::Acquire)
                    && !terminator.draining.load(Ordering::Acquire)
            },
            |packet| path.on_packet_sent(packet),
        )
    })
    .await
}

pub(crate) async fn finish(
    terminator: &Terminator,
    context: &ArcConnPhase,
    paths: &Paths,
    reason: &CloseReason,
    data_ready: Option<ArcReceiving<bool>>,
) {
    let snapshot = context.get();
    let initial = snapshot.initial();
    terminator.closing.store(true, Ordering::Release);
    let error: Error = match reason {
        CloseReason::App(error) => error.clone().into(),
        CloseReason::Internal(error) => error.clone().into(),
        CloseReason::Peer(frame) => frame.clone().into(),
    };
    initial.crypto.on_error(&error);
    if let Some(handshake) = snapshot.handshake() {
        handshake.crypto.on_error(&error);
    }
    if let Some(sender) = snapshot.material() {
        sender.spaces.data.crypto.on_error(&error);
        sender.streams.on_conn_error(&error);
        sender.flow.on_conn_error(&error);
    }
    if let Some(data_ready) = data_ready {
        data_ready.set(false); // A prepared Data node now starts in close-only mode.
    }
    let paths = paths.snapshot();
    let pto = paths
        .iter()
        .map(|path| path.cc.pto_base(Epoch::Data))
        .max()
        .unwrap_or(Duration::from_secs(1));
    for path in &paths {
        for epoch in [Epoch::Initial, Epoch::Handshake] {
            path.cc.discard_epoch(epoch);
        }
    }
    let deadline = Instant::now() + pto * 3;
    if matches!(reason, CloseReason::Peer(_)) {
        terminator.draining.store(true, Ordering::Release);
    } else {
        let _ = terminator.frame.set(error);
    }
    initial
        .send_wakers
        .wake_all_by(qbase::net::tx::Signals::all());
    if !terminator.draining.load(Ordering::Acquire) {
        tokio::select! {
            _ = terminator.peer_closed.clone() => { terminator.draining.store(true, Ordering::Release); },
            _ = tokio::time::sleep_until(deadline) => {},
        }
    }
    tokio::time::sleep_until(deadline).await;
    terminator.terminated.store(true, Ordering::Release);
    initial.retire();
    if let Some(handshake) = snapshot.handshake() {
        handshake.retire();
    }
    if let Some(sender) = snapshot.material() {
        sender.spaces.data.keys.retire();
    }
    for path in paths {
        path.retire();
    }
}
