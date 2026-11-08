use std::{future::poll_fn, sync::Arc, task::Poll};

use qbase::{
    error::{ErrorKind, QuicError},
    net::tx::UnregisterWaker,
};

use super::{Datagram, Path, Paths};

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
                let (count, _) = path.collect(&mut datagrams, &mut frames).await?;
                path.send(&mut datagrams[..count], &idle_timer).await
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

pub(crate) fn cancel_waiters(paths: &Paths, path: &Path) {
    for waker in path.send_waker.drain() {
        let waker = &waker;
        path.cc.cancel(waker);
        path.spaces.unregister(waker);
        paths.reliable_frames.unregister(waker);
    }
}
