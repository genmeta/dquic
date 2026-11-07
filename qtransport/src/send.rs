use std::{
    future::poll_fn,
    io::IoSlice,
    sync::Arc,
    task::{Poll, ready},
};

pub use packet::Packet;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    net::tx::UnregisterWaker,
    packet::PacketContent,
    time::timer::ArcIdleTimer,
};
use qcongestion::Transport as _;
use qprotocol::QuicProtocol;
use smallvec::SmallVec;
use tokio::time::Instant;

pub use crate::packet::encrypt as packet;
pub(crate) use crate::path::Datagram;
use crate::{
    Error, Paths,
    path::{Path, update_amplification_blocked},
};

pub(crate) async fn sending(paths: Arc<Paths>, path: Arc<Path>) {
    let mut datagrams = std::array::from_fn::<_, 8, _>(|_| Datagram::default());
    let mut frames = Vec::with_capacity(256);
    let terminator = path.terminator.clone();
    let idle_timer = paths.idle_timer();
    let waker = poll_fn(|cx| Poll::Ready(cx.waker().clone())).await;
    let error = loop {
        let result = tokio::select! {
            biased;
            _ = terminator.clone() => break None,
            result = async {
                let (count, dcid) = path.collect(&mut datagrams, &mut frames).await?;
                send(&path, &mut datagrams[..count], dcid, &idle_timer).await
            } => result,
        };
        path.refresh(&mut datagrams, &mut frames);
        if let Err(error) = result {
            break Some(error);
        }
    };
    path.refresh(&mut datagrams, &mut frames);
    path.send_waker.register(&waker);
    cancel_waiters(&paths, &path);
    // A removed path may already have been replaced while its sender was exiting.
    let no_paths = {
        let mut entries = paths.entries.lock().unwrap();
        if entries.get(&path.pathway).is_some_and(|current| Arc::ptr_eq(current, &path)) {
            path.close();
            entries.remove(&path.pathway);
            paths.validations.remove(&path.pathway);
        }
        entries.is_empty()
    };
    // An idle upgrade can retain a handshake batch without another collect poll.
    path.dcid.refresh();
    if no_paths {
        terminator.close(
            error.unwrap_or_else(|| QuicError::with_default_fty(ErrorKind::NoViablePath, "all paths retired").into()).into(),
            paths.closing_pto(),
        );
        terminator.await;
    }
}

/// Submit the datagrams and account each successful prefix under the CC lock.
pub(crate) async fn send(path: &Path, datagrams: &mut [Datagram], dcid: ConnectionId, idle_timer: &ArcIdleTimer) -> Result<(), Error> {
    let overhead = QuicProtocol::packet_overhead(path.pathway);
    let deadlines = Epoch::EPOCHS.map(|epoch| (path.cc.retransmit_and_expire_time(epoch).0, path.cc.pto_base(epoch) * 3));
    let mut first = 0;
    while first < datagrams.len() {
        let mut sent_handshake = false;
        let sent = poll_fn(|cx| -> Poll<std::io::Result<Option<usize>>> {
            // ACK handling takes the same lock as submission and completion.
            let mut cc = path.cc.lock();
            path.validation.credit().map_err(std::io::Error::other)?;
            if !path.is_active()
                && datagrams[first..]
                    .iter()
                    .flat_map(|datagram| &datagram.packets)
                    .any(|(_, meta)| meta.content == PacketContent::EffectivePayload)
            {
                return Poll::Ready(Ok(None));
            }
            let sent = {
                let buffers: SmallVec<[_; 8]> = datagrams[first..].iter().map(|datagram| IoSlice::new(&datagram.bytes)).collect();
                ready!(QuicProtocol::global().poll_send(cx, path.pathway, &buffers))?
            };
            for datagram in &mut datagrams[first..first + sent] {
                let mut packets = [None; 3];
                for (space, meta) in datagram.packets.drain(..) {
                    let epoch = meta.epoch();
                    space.on_sent(meta.pn, meta.in_flight, deadlines[epoch].0, deadlines[epoch].1);
                    sent_handshake |= epoch == Epoch::Handshake;
                    packets[epoch] = Some(meta);
                }
                let _ = idle_timer.on_sent_at(Instant::now());
                path.on_sent(&mut cc, datagram.bytes.len(), packets);
            }
            update_amplification_blocked(
                &mut cc,
                &path.spaces,
                dcid,
                path.validation.credit().map_or(0, |credit| credit.unwrap_or(usize::MAX)),
                overhead,
            );
            Poll::Ready(Ok(Some(sent)))
        })
        .await
        .map_err(|error| QuicError::with_default_fty(ErrorKind::NoViablePath, error.to_string()))?;
        let Some(sent) = sent else { return Ok(()) };
        if sent_handshake {
            path.progress.on_handshake_sent();
        }
        if sent == 0 {
            return Err(QuicError::with_default_fty(ErrorKind::NoViablePath, "UDP submitted zero datagrams").into());
        }
        first += sent;
    }
    Ok(())
}

pub(crate) fn cancel_waiters(paths: &Paths, path: &Path) {
    for waker in path.send_waker.drain() {
        let waker = &waker;
        path.cc.cancel(waker);
        path.spaces.unregister(waker);
        paths.reliable_frames.unregister(waker);
    }
}
