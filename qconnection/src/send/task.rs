use std::sync::Arc;

use bytes::BytesMut;
use qbase::{error::ErrorKind, net::tx::UnregisterWaker};
use qtransport::path::Path;

use super::{Burst, MAX_BURST_PACKETS, no_viable_path};
use crate::{ConnPhase, Paths};

pub(crate) async fn sending(paths: Arc<Paths>, path: Arc<Path>) {
    let mut datagrams =
        std::array::from_fn::<_, MAX_BURST_PACKETS, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::with_capacity(256);
    let mut packets = [[None; 3]; MAX_BURST_PACKETS];
    let terminator = paths.terminator.clone();
    let mut burst = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut packets);
    let error = loop {
        let result = tokio::select! {
            biased;
            _ = terminator.clone() => break None,
            result = burst.batch() => result,
        };
        burst.cancel();
        if let Err(error) = result {
            if error.kind() == ErrorKind::NoViablePath {
                break Some(error);
            } else if !terminator.close(error.into(), paths.closing_pto()) {
                // Closed components are empty sources. A repeated error here means
                // packet assembly itself still fails; wait without spinning.
                terminator.clone().await;
                break None;
            }
        }
    };
    burst.cancel();
    cancel_waiters(&paths, &path);
    // A removed path may already have been replaced while its sender was exiting.
    let no_paths = {
        let mut entries = paths.entries.lock().unwrap();
        if entries
            .get(&path.pathway)
            .is_some_and(|current| Arc::ptr_eq(current, &path))
        {
            path.close();
            entries.remove(&path.pathway);
            paths.validations.remove(&path.pathway);
        }
        entries.is_empty()
    };
    if no_paths {
        terminator.close(
            error
                .unwrap_or_else(|| no_viable_path("all paths retired"))
                .into(),
            paths.closing_pto(),
        );
        terminator.await;
    }
}

pub(crate) fn cancel_waiters(paths: &Paths, path: &Path) {
    for waker in path.send_waker.drain() {
        let waker = &waker;
        let phase = paths.phase();
        let phase = phase.get();
        path.cc.cancel(waker);
        for space in paths.spaces.read_guard().iter() {
            space.unregister(waker);
        }
        paths.reliable_frames.unregister(waker);
        match &phase {
            ConnPhase::Initial(p) => {
                p.upgrade_wakers.unregister(waker);
            }
            ConnPhase::Handshake(p) => {
                p.upgrade_wakers.unregister(waker);
            }
            ConnPhase::Mature(p) => p.flow_ctrl.sender.unregister(waker),
        }
    }
}
