use std::{
    io::IoSlice,
    sync::Arc,
    task::{Poll, Waker},
};

use bytes::BytesMut;
use qbase::{
    Epoch,
    error::{ErrorKind, QuicError},
    frame::Frame,
    packet::assemble::{Package, in_flight},
};
use qcongestion::Transport as _;
use qprotocol::QuicProtocol;
use qtransport::{journal::ArcSendJournal, path::Path};

use super::{BurstPns, MAX_BURST_PACKETS, burst};
use crate::{ConnPhase, Error, Paths};

fn sending_journals(phase: &ConnPhase) -> [Option<ArcSendJournal>; 3] {
    match phase {
        ConnPhase::Initial(p) => [Some(p.initial.send_journal.clone()), None, None],
        ConnPhase::Handshake(p) => [
            Some(p.initial.send_journal.clone()),
            Some(p.handshake.send_journal.clone()),
            None,
        ],
        ConnPhase::Mature(p) => [
            Some(p.spaces.initial.send_journal.clone()),
            Some(p.spaces.handshake.send_journal.clone()),
            Some(p.spaces.data.send_journal.clone()),
        ],
    }
}

pub(crate) async fn sending(paths: Arc<Paths>, path: Arc<Path>) {
    let mut datagrams =
        std::array::from_fn::<_, MAX_BURST_PACKETS, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::with_capacity(256);
    let mut pns: BurstPns = std::array::from_fn(|_| Vec::with_capacity(MAX_BURST_PACKETS));
    let phase = paths.phase();
    let overhead = QuicProtocol::packet_overhead(path.pathway);
    let outcome: Result<(), Error> = async {
        loop {
            let count = burst(
                &path.cc,
                &path.anti_amplifier,
                &mut datagrams,
                &mut frames,
                &mut pns,
            )
            .collect(&paths, &path, phase.get().dcid())
            .await?;
            let journals = sending_journals(&phase.get());
            let deadlines = Epoch::EPOCHS.map(|epoch| {
                (
                    path.cc.retransmit_and_expire_time(epoch).0,
                    path.cc.pto_base(epoch) * 3,
                )
            });
            let packets = datagrams.each_ref().map(|buffer| IoSlice::new(buffer));
            let mut first = 0;
            while first < count {
                let sent = QuicProtocol::global()
                    .send_with(path.pathway, &packets[first..count], |submit| {
                        let mut cc = path.cc.lock();
                        let mut records = journals
                            .each_ref()
                            .map(|journal| journal.as_ref().map(ArcSendJournal::lock_guard));
                        let result = submit();
                        if let Poll::Ready(Ok(sent)) = result {
                            for epoch in Epoch::EPOCHS {
                                for &(index, pn) in
                                    pns[epoch].iter().filter(|(index, _)| *index < first + sent)
                                {
                                    let journal = records[epoch].as_mut().unwrap();
                                    let (mut content, mut inflight, mut ack) =
                                        (qbase::packet::PacketContent::default(), false, None);
                                    for frame in journal.frames(pn) {
                                        content += qbase::packet::PacketContent::from(
                                            qbase::frame::GetFrameType::frame_type(frame),
                                        );
                                        inflight |= in_flight(std::slice::from_ref(frame));
                                        if let Frame::Ack(frame) = frame {
                                            ack = Some(frame.largest());
                                        }
                                    }
                                    let size = datagrams[index].len() + overhead;
                                    journal.mark_sent(
                                        pn,
                                        inflight,
                                        deadlines[epoch].0,
                                        deadlines[epoch].1,
                                    );
                                    path.anti_amplifier.on_sent(size);
                                    cc.on_pkt_sent(
                                        epoch,
                                        pn,
                                        content.is_ack_eliciting(),
                                        size,
                                        inflight,
                                        ack,
                                    );
                                    path.activity.on_sent(content);
                                }
                                pns[epoch].retain(|(index, _)| *index >= first + sent);
                            }
                        }
                        result
                    })
                    .await
                    .map_err(|error| {
                        QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string())
                    })?;
                if sent == 0 {
                    return Err(QuicError::with_default_fty(
                        ErrorKind::NoViablePath,
                        "UDP submitted zero datagrams",
                    )
                    .into());
                }
                first += sent;
            }
        }
    }
    .await;
    cancel_waiters(&paths, &path);
    let journals = sending_journals(&phase.get());
    for epoch in Epoch::EPOCHS {
        if let Some(journal) = &journals[epoch] {
            for (_, pn) in pns[epoch].drain(..) {
                journal.cancel(pn);
            }
        }
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
        let phase = phase.lock_guard();
        path.cc.cancel(waker);
        let mut terminator = &paths.terminator();
        <&crate::terminate::ArcTerminator as Package<BytesMut>>::cancel(&mut terminator, waker);
        fn cancel_space<K>(space: &qtransport::space::Space<K>, waker: &Waker) {
            <qrecovery::crypto::CryptoStreamOutgoing as Package<BytesMut>>::cancel(
                &mut space.crypto.outgoing(),
                waker,
            );
            <qrecovery::journal::ArcRcvdJournal as Package<BytesMut>>::cancel(
                &mut space.rcvd_journal.clone(),
                waker,
            );
        }
        match &*phase {
            ConnPhase::Initial(p) => {
                cancel_space(&p.initial, waker);
                <crate::ArcReliableFrames as Package<BytesMut>>::cancel(
                    &mut p.reliable_frames.clone(),
                    waker,
                );
            }
            ConnPhase::Handshake(p) => {
                cancel_space(&p.initial, waker);
                cancel_space(&p.handshake, waker);
                <crate::ArcReliableFrames as Package<BytesMut>>::cancel(
                    &mut p.reliable_frames.clone(),
                    waker,
                );
            }
            ConnPhase::Mature(p) => {
                cancel_space(&p.spaces.initial, waker);
                cancel_space(&p.spaces.handshake, waker);
                cancel_space(&p.spaces.data, waker);
                <crate::ArcReliableFrames as Package<BytesMut>>::cancel(
                    &mut p.reliable_frames.clone(),
                    waker,
                );
                <crate::DataStreams as Package<BytesMut>>::cancel(&mut p.streams.clone(), waker);
                p.flow.sender.cancel(waker);
            }
        }
    }
}
