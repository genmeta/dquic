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
    packet::assemble::Package,
};
use qcongestion::Transport as _;
use qprotocol::QuicProtocol;
use qtransport::path::Path;

use super::{BurstPns, MAX_BURST_PACKETS, burst};
use crate::{ConnPhase, Error, Paths};

pub(crate) async fn sending(paths: Arc<Paths>, path: Arc<Path>) {
    let dcid_cell = OnceLock::new();
    let mut datagrams =
        std::array::from_fn::<_, MAX_BURST_PACKETS, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::with_capacity(256);
    let mut pns: BurstPns = std::array::from_fn(|_| Vec::with_capacity(MAX_BURST_PACKETS));
    let phase = paths.phase();
    let overhead = QuicProtocol::packet_overhead(path.pathway);
    let outcome: Result<(), Error> = async {
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
            .await?;
            let dcid = collector.dcid.take();
            drop(collector);
            let sending_phase = phase.get();
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
                                sending_phase.on_sent(
                                    epoch,
                                    submitted
                                        .clone()
                                        .map(|packet| (packet.pn, packet.in_flight)),
                                    deadlines[epoch].0,
                                    deadlines[epoch].1,
                                );
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
                                    path.activity.on_sent(packet.content);
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
    }
    .await;
    cancel_waiters(&paths, &path);
    let phase = phase.get();
    for epoch in Epoch::EPOCHS {
        for packet in pns[epoch].drain(..) {
            phase.cancel(epoch, packet.pn);
        }
    }
    // All burst loans have been released before retiring this path's CID.
    if let Some(dcid) = dcid_cell.into_inner() {
        dcid.retire();
    }
    paths.remove(&path);
    if let Err(error) = outcome
        && (error.kind() != ErrorKind::NoViablePath || paths.snapshot().is_empty())
    {
        paths.on_error(error);
    }
}

pub(super) fn cancel_waiters(paths: &Paths, path: &Path) {
    for waker in path.send_waker.drain() {
        let waker = &waker;
        path.activity.ignore(waker);
        path.anti_amplifier.cancel(waker);
        let phase = paths.phase();
        phase.cancel(waker);
        let mut terminator = &phase.terminator();
        let phase = phase.lock_guard();
        path.cc.cancel(waker);
        <&crate::terminate::ArcTerminator as Package<BytesMut>>::cancel(&mut terminator, waker);
        fn cancel_space(
            crypto: &qrecovery::crypto::CryptoStream,
            journal: &qrecovery::journal::ArcRcvdJournal,
            waker: &Waker,
        ) {
            <qrecovery::crypto::CryptoStreamOutgoing as Package<BytesMut>>::cancel(
                &mut crypto.outgoing(),
                waker,
            );
            <qrecovery::journal::ArcRcvdJournal as Package<BytesMut>>::cancel(
                &mut journal.clone(),
                waker,
            );
        }
        match &*phase {
            ConnPhase::Initial(p) => {
                cancel_space(
                    &p.initial_space.crypto,
                    &p.initial_space.rcvd_journal,
                    waker,
                );
                <crate::ArcReliableFrames as Package<BytesMut>>::cancel(
                    &mut p.reliable_frames.clone(),
                    waker,
                );
            }
            ConnPhase::Handshake(p) => {
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
                <crate::ArcReliableFrames as Package<BytesMut>>::cancel(
                    &mut p.reliable_frames.clone(),
                    waker,
                );
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
                <crate::ArcReliableFrames as Package<BytesMut>>::cancel(
                    &mut p.spaces.data.reliable_frames.clone(),
                    waker,
                );
                <crate::DataStreams as Package<BytesMut>>::cancel(
                    &mut p.spaces.data.streams.clone(),
                    waker,
                );
                p.flow_ctrl.sender.cancel(waker);
            }
        }
    }
}
