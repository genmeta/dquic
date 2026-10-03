//! A connection's lifetime, written in protocol order for each endpoint role.

use std::future::Future;

use qbase::Epoch;
use qcongestion::Transport as _;

pub(crate) mod client;
mod interceptor;
mod server;

pub use client::client_growing;
pub use interceptor::Interceptor;
use qtransport::terminate::ArcTerminator;
pub use server::server_growing;

use crate::{ConnPhase, Error, Paths};

/// Wait for a future's output or the connection's terminal error.
pub(crate) async fn any<T>(
    future: impl Future<Output = T>,
    terminator: ArcTerminator,
) -> Result<T, Error> {
    tokio::select! {
        biased;
        error = terminator => Err(error),
        result = future => Ok(result),
    }
}

async fn finish(paths: &Paths, trackers: &crate::ArcTrackers, error: Error) -> Error {
    let terminator = paths.phase().terminator();
    terminator.close(error.into(), paths.closing_pto());
    let error = terminator.await;
    paths.idle().cancel();
    let snapshot = paths.phase().get();
    let active_paths = paths.snapshot();
    for path in &active_paths {
        for epoch in [Epoch::Initial, Epoch::Handshake] {
            path.cc.discard_epoch(epoch);
        }
    }
    match &snapshot {
        ConnPhase::Initial(phase) => {
            phase.initial_space.retire();
        }
        ConnPhase::Handshake(phase) => {
            phase.initial_space.retire();
            phase.handshake_space.retire();
        }
        ConnPhase::Mature(phase) => {
            phase.spaces.initial.retire();
            phase.spaces.handshake.retire();
            phase.spaces.data.keys.retire();
        }
    }
    {
        let mut trackers = trackers.write().unwrap();
        let end = trackers.largest();
        trackers.drain_to(end).for_each(drop);
    }
    for path in active_paths {
        paths.remove(&path);
    }
    error
}
