use std::{
    future::{Future, poll_fn},
    io::IoSlice,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::Poll,
};

use bytes::BytesMut;
use qbase::{
    Epoch,
    error::{ErrorKind, QuicError},
    net::tx::UnregisterWaker,
};
use qcongestion::Transport as _;
use qprotocol::QuicProtocol;
use qtransport::{path::Path, space::Spaces};
use tokio::time::Instant;

use super::{BurstPns, MAX_BURST_PACKETS, burst};
use crate::{ConnPhase, Error, Paths};

pub(crate) async fn sending(paths: Arc<Paths>, path: Arc<Path>) {
    let dcid_cell = OnceLock::new();
    let mut datagrams =
        std::array::from_fn::<_, MAX_BURST_PACKETS, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::with_capacity(256);
    let mut pns: BurstPns = [[None; 3]; MAX_BURST_PACKETS];
    let mut sending_spaces = None;
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
            let dcid = collector.dcid.take();
            sending_spaces = collector.spaces.take();
            drop(collector);
            let count = match count {
                Ok(count) => count,
                Err(error) if error.kind() != ErrorKind::NoViablePath => {
                    terminator.close(error.into(), paths.closing_pto());
                    if retry_close {
                        terminator.clone().await;
                        return Ok(());
                    }
                    retry_close = true;
                    cancel_pending(sending_spaces.as_ref(), &mut pns);
                    frames.clear();
                    continue;
                }
                Err(error) => return Err(error),
            };
            let spaces = sending_spaces.as_ref().expect("collected spaces");
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
                            for index in first..first + sent {
                                path.anti_amplifier
                                    .on_sent(datagrams[index].len() + overhead);
                                let overhead_epoch = Epoch::EPOCHS
                                    .into_iter()
                                    .find(|&epoch| {
                                        pns[index][epoch].is_some_and(|pn| {
                                            spaces
                                                .0
                                                .get(epoch as u64)
                                                .unwrap()
                                                .sent_journal()
                                                .lock_guard()
                                                .packet(pn)
                                                .unwrap()
                                                .in_flight
                                        })
                                    })
                                    .or_else(|| {
                                        Epoch::EPOCHS
                                            .into_iter()
                                            .find(|&epoch| pns[index][epoch].is_some())
                                    });
                                for epoch in Epoch::EPOCHS {
                                    let Some(pn) = pns[index][epoch].take() else {
                                        continue;
                                    };
                                    let mut journal = spaces
                                        .0
                                        .get(epoch as u64)
                                        .expect("submitted space")
                                        .sent_journal()
                                        .lock_guard();
                                    let packet = journal.packet(pn).expect("submission record");
                                    let (content, flight, ack, size) = (
                                        packet.content,
                                        packet.in_flight,
                                        packet.ack,
                                        packet.size
                                            + if Some(epoch) == overhead_epoch {
                                                overhead
                                            } else {
                                                0
                                            },
                                    );
                                    journal.on_sent(
                                        pn,
                                        flight,
                                        deadlines[epoch].0,
                                        deadlines[epoch].1,
                                    );
                                    drop(journal);
                                    cc.on_pkt_sent(
                                        epoch,
                                        pn,
                                        content.is_ack_eliciting(),
                                        size,
                                        flight,
                                        ack,
                                    );
                                    sent_handshake |= epoch == Epoch::Handshake;
                                    let now = Instant::now();
                                    let _ = idle.on_sent_at(now);
                                    let _ = path.heartbeat.on_sent_at(content, now);
                                }
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
    cancel_pending(sending_spaces.as_ref(), &mut pns);
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

fn cancel_pending(spaces: Option<&Spaces>, pns: &mut BurstPns) {
    let Some(spaces) = spaces else {
        return;
    };
    for slots in pns {
        for (epoch, space) in spaces.0.enumerate() {
            if let Some(pn) = slots[epoch as usize].take() {
                space.cancel(pn, &mut std::iter::empty());
            }
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
        for space in phase.spaces().read().unwrap().0.iter() {
            space.unregister(waker);
        }
        match &phase {
            ConnPhase::Initial(p) => {
                p.upgrade_wakers.unregister(waker);
                p.reliable_frames.unregister(waker);
            }
            ConnPhase::Handshake(p) => {
                p.upgrade_wakers.unregister(waker);
                p.reliable_frames.unregister(waker);
            }
            ConnPhase::Mature(p) => p.flow_ctrl.sender.unregister(waker),
        }
    }
}
