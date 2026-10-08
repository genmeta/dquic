use std::{
    future::{Future, poll_fn},
    io::IoSlice,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Poll, Waker},
};

use bytes::BytesMut;
use qbase::{
    Epoch,
    error::{ErrorKind, QuicError},
    net::tx::UnregisterWaker,
};
use qcongestion::Transport as _;
use qprotocol::QuicProtocol;
use qtransport::path::Path;
use tokio::time::Instant;

use super::{BurstPns, MAX_BURST_PACKETS, burst};
use crate::{ConnPhase, Error, Paths};

pub(crate) async fn sending(paths: Arc<Paths>, path: Arc<Path>) {
    let dcid_cell = OnceLock::new();
    let mut datagrams =
        std::array::from_fn::<_, MAX_BURST_PACKETS, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::with_capacity(256);
    let mut pns: BurstPns = std::array::from_fn(|_| Vec::with_capacity(MAX_BURST_PACKETS));
    let phase = paths.phase();
    let idle = paths.idle();
    let terminator = phase.terminator();
    let overhead = QuicProtocol::packet_overhead(path.pathway);
    let sending = async {
        let mut retry_close = false;
        loop {
            let mut collector = burst(
                &path.cc,
                &path.anti_amplifier,
                &mut datagrams,
                &mut frames,
                &mut pns,
            )
            .collect(&paths, &path, &dcid_cell);
            let count = poll_fn(|cx| {
                let result = Pin::new(&mut collector).poll(cx);
                // Collector has released the phase lock before path activation.
                if dcid_cell.get().is_some() && path.selected() == Path::SELECTED {
                    paths.activate_paths(&path);
                }
                result
            })
            .await;
            let count = match count {
                Ok(count) => count,
                Err(error) if error.kind() != ErrorKind::NoViablePath => {
                    terminator.close(error.into(), paths.closing_pto());
                    if retry_close {
                        terminator.clone().await;
                        return Ok(());
                    }
                    retry_close = true;
                    drop(collector);
                    cancel_pending(&phase.get(), &mut pns);
                    frames.clear();
                    continue;
                }
                Err(error) => return Err(error),
            };
            let dcid = collector.dcid.take();
            drop(collector);
            let sending_phase = phase.get();
            let journals = match &sending_phase {
                ConnPhase::Initial(p) => [Some(&p.initial_space.sent_journal), None, None],
                ConnPhase::Handshake(p) => [
                    Some(&p.initial_space.sent_journal),
                    Some(&p.handshake_space.sent_journal),
                    None,
                ],
                ConnPhase::Mature(p) => [
                    Some(&p.spaces.initial.sent_journal),
                    Some(&p.spaces.handshake.sent_journal),
                    Some(&p.spaces.data.sent_journal),
                ],
            };
            let deadlines = Epoch::EPOCHS.map(|epoch| {
                (
                    path.cc.retransmit_and_expire_time(epoch).0,
                    path.cc.pto_base(epoch) * 3,
                )
            });
            let packets = datagrams.each_ref().map(|buffer| IoSlice::new(buffer));
            let mut first = 0;
            while first < count {
                let mut sent_handshake = false;
                let sent = QuicProtocol::global()
                    .send_with(path.pathway, &packets[first..count], |submit| {
                        let mut cc = path.cc.lock();
                        let result = submit();
                        if let Poll::Ready(Ok(sent)) = result {
                            for epoch in Epoch::EPOCHS {
                                if pns[epoch].is_empty() {
                                    continue;
                                }
                                let submitted = pns[epoch]
                                    .iter()
                                    .filter(|packet| packet.index < first + sent);
                                {
                                    let mut journal = journals[epoch]
                                        .expect("submitted packets have a space")
                                        .lock_guard();
                                    for packet in submitted.clone() {
                                        journal.on_sent(
                                            packet.pn,
                                            packet.in_flight,
                                            deadlines[epoch].0,
                                            deadlines[epoch].1,
                                        );
                                    }
                                }
                                for packet in submitted {
                                    sent_handshake |= epoch == Epoch::Handshake;
                                    let size = datagrams[packet.index].len() + overhead;
                                    path.anti_amplifier.on_sent(size);
                                    cc.on_pkt_sent(
                                        epoch,
                                        packet.pn,
                                        packet.content.is_ack_eliciting(),
                                        size,
                                        packet.in_flight,
                                        packet.ack,
                                    );
                                    let now = Instant::now();
                                    let _ = idle.on_sent_at(now);
                                    let _ = path.heartbeat.on_sent_at(packet.content, now);
                                }
                                pns[epoch].retain(|packet| packet.index >= first + sent);
                            }
                        }
                        result
                    })
                    .await
                    .map_err(|error| {
                        QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string())
                    })?;
                if sent_handshake {
                    paths.on_handshake_sent();
                }
                if sent == 0 {
                    return Err(QuicError::with_default_fty(
                        ErrorKind::NoViablePath,
                        "UDP submitted zero datagrams",
                    )
                    .into());
                }
                first += sent;
            }
            drop(dcid);
        }
    };
    let outcome: Result<(), Error> = tokio::select! {
        biased;
        _ = terminator.clone() => Ok(()),
        result = sending => result,
    };
    cancel_waiters(&paths, &path);
    cancel_pending(&phase.get(), &mut pns);
    // All burst loans have been released before retiring this path's CID.
    if let Some(dcid) = dcid_cell.into_inner() {
        dcid.retire();
    }
    paths.remove(&path);
    if let Err(error) = outcome
        && (error.kind() != ErrorKind::NoViablePath || paths.snapshot().is_empty())
    {
        terminator.close(error.into(), paths.closing_pto());
        terminator.await;
    }
}

fn cancel_pending(phase: &ConnPhase, pns: &mut BurstPns) {
    let (initial, handshake, data) = match phase {
        ConnPhase::Initial(p) => (&p.initial_space, None, None),
        ConnPhase::Handshake(p) => (&p.initial_space, Some(&p.handshake_space), None),
        ConnPhase::Mature(p) => (
            &p.spaces.initial,
            Some(&p.spaces.handshake),
            Some(&p.spaces.data),
        ),
    };
    for packet in pns[Epoch::Initial].drain(..) {
        initial.cancel(packet.pn);
    }
    if let Some(handshake) = handshake {
        for packet in pns[Epoch::Handshake].drain(..) {
            handshake.cancel(packet.pn);
        }
    }
    if let Some(data) = data {
        for packet in pns[Epoch::Data].drain(..) {
            data.cancel(packet.pn);
        }
    }
}

pub(crate) fn cancel_waiters(paths: &Paths, path: &Path) {
    for waker in path.send_waker.drain() {
        let waker = &waker;
        path.anti_amplifier.cancel(waker);
        let phase = paths.phase();
        let phase = phase.get();
        path.cc.cancel(waker);
        fn cancel_space(
            crypto: &qrecovery::crypto::CryptoStream,
            journal: &qrecovery::journal::ArcRcvdJournal,
            waker: &Waker,
        ) {
            crypto.outgoing().unregister(waker);
            journal.unregister(waker);
        }
        match &phase {
            ConnPhase::Initial(p) => {
                p.upgrade_wakers.unregister(waker);
                cancel_space(
                    &p.initial_space.crypto,
                    &p.initial_space.rcvd_journal,
                    waker,
                );
                p.reliable_frames.unregister(waker);
            }
            ConnPhase::Handshake(p) => {
                p.upgrade_wakers.unregister(waker);
                cancel_space(
                    &p.initial_space.crypto,
                    &p.initial_space.rcvd_journal,
                    waker,
                );
                cancel_space(
                    &p.handshake_space.crypto,
                    &p.handshake_space.rcvd_journal,
                    waker,
                );
                p.reliable_frames.unregister(waker);
            }
            ConnPhase::Mature(p) => {
                cancel_space(
                    &p.spaces.initial.crypto,
                    &p.spaces.initial.rcvd_journal,
                    waker,
                );
                cancel_space(
                    &p.spaces.handshake.crypto,
                    &p.spaces.handshake.rcvd_journal,
                    waker,
                );
                cancel_space(&p.spaces.data.crypto, &p.spaces.data.rcvd_journal, waker);
                p.spaces.data.reliable_frames.unregister(waker);
                p.spaces.data.streams.unregister(waker);
                p.flow_ctrl.sender.unregister(waker);
            }
        }
    }
}
