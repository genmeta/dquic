use std::{future::poll_fn, sync::Arc, task::Poll};

use bytes::BytesMut;
use qbase::net::tx::UnregisterWaker;
use qtransport::path::Path;

use super::{Burst, MAX_BURST_PACKETS, no_viable_path};
use crate::Paths;

pub(crate) async fn sending(paths: Arc<Paths>, path: Arc<Path>) {
    let mut datagrams = std::array::from_fn::<_, MAX_BURST_PACKETS, _>(|_| BytesMut::with_capacity(1200));
    let mut frames = Vec::with_capacity(256);
    let mut packets = std::array::from_fn(|_| Default::default());
    let terminator = paths.terminator.clone();
    let waker = poll_fn(|cx| Poll::Ready(cx.waker().clone())).await;
    let mut burst = Burst::new(&paths, &path, &mut datagrams, &mut frames, &mut packets);
    let error = loop {
        let result = tokio::select! {
            biased;
            _ = terminator.clone() => break None,
            result = burst.batch() => result,
        };
        burst.cancel();
        if let Err(error) = result {
            break Some(error);
        }
    };
    burst.cancel();
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
        terminator.close(error.unwrap_or_else(|| no_viable_path("all paths retired")).into(), paths.closing_pto());
        terminator.await;
    }
}

pub(crate) fn cancel_waiters(paths: &Paths, path: &Path) {
    for waker in path.send_waker.drain() {
        let waker = &waker;
        path.cc.cancel(waker);
        paths.spaces.unregister(waker);
        paths.reliable_frames.unregister(waker);
    }
}
