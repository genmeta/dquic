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

use crate::{Error, Paths};

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

async fn finish(paths: &Paths, error: Error) -> Error {
    let terminator = paths.terminator.clone();
    terminator.close(error.into(), paths.closing_pto());
    let error = terminator.await;
    paths.idle().cancel();
    let active_paths = paths.snapshot();
    for path in &active_paths {
        for epoch in [Epoch::Initial, Epoch::Handshake] {
            path.cc.discard_epoch(epoch);
        }
    }
    {
        let mut spaces = paths.spaces.write_guard();
        while let Some((_, space)) = spaces.pop_front() {
            space.retire();
        }
    }
    {
        let mut loss_resender = paths.loss_resender.write_guard();
        let end = loss_resender.largest();
        loss_resender.drain_to(end).for_each(drop);
    }
    for path in active_paths {
        paths.remove(&path);
    }
    error
}
