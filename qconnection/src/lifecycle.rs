//! A connection's lifetime, written in protocol order for each endpoint role.

use std::{future::Future, time::Duration};

use qbase::{ArcReceiving, Epoch};
use qcongestion::Transport as _;

mod client;
mod interceptor;
mod server;

pub use client::client_growing;
pub use interceptor::Interceptor;
pub use server::server_growing;

use crate::{CloseReason, ConnPhase, Error, Paths};

/// Wait for a future's output or a connection close reason.
async fn any<T>(
    future: impl Future<Output = T>,
    mut closed: ArcReceiving<CloseReason>,
) -> Result<T, CloseReason> {
    tokio::select! {
        Ok(Some(reason)) = &mut closed => Err(reason),
        result = future => Ok(result),
    }
}

fn close_error(reason: &CloseReason) -> Error {
    match reason {
        CloseReason::App(error) => error.clone().into(),
        CloseReason::Peer(frame) => frame.clone().into(),
        CloseReason::Internal(error) => error.clone().into(),
    }
}

async fn finish(paths: &Paths, reason: &CloseReason) {
    let phase = paths.phase();
    let terminator = phase.terminator();
    let snapshot = phase.get();
    let error = close_error(reason);
    let active_paths = paths.snapshot();
    let pto = active_paths
        .iter()
        .map(|path| path.cc.pto_base(Epoch::Data))
        .max()
        .unwrap_or(Duration::from_secs(1));
    terminator.on_error(reason, pto * 3);

    match &snapshot {
        ConnPhase::Initial(phase) => phase.initial_space.crypto.on_error(&error),
        ConnPhase::Handshake(phase) => {
            phase.initial_space.crypto.on_error(&error);
            phase.handshake_space.crypto.on_error(&error);
        }
        ConnPhase::Mature(phase) => {
            phase.spaces.initial.crypto.on_error(&error);
            phase.spaces.handshake.crypto.on_error(&error);
            phase.spaces.data.crypto.on_error(&error);
            phase.spaces.data.streams.on_conn_error(&error);
            phase.flow_ctrl.on_conn_error(&error);
        }
    }
    for path in &active_paths {
        for epoch in [Epoch::Initial, Epoch::Handshake] {
            path.cc.discard_epoch(epoch);
        }
    }

    terminator.wait().await;
    match &snapshot {
        ConnPhase::Initial(phase) => phase.initial_space.retire(),
        ConnPhase::Handshake(phase) => {
            phase.initial_space.retire();
            phase.handshake_space.retire();
        }
        ConnPhase::Mature(phase) => {
            phase.retire_handshake_spaces();
            phase.spaces.data.keys.retire();
        }
    }
    {
        let trackers = snapshot.trackers();
        let mut trackers = trackers.write().unwrap();
        let end = trackers.largest();
        trackers.drain_to(end).for_each(drop);
    }
    for path in active_paths {
        paths.remove(&path);
    }
}

#[cfg(test)]
mod tests {
    use std::{future::pending, time::Duration};

    use qbase::error::{ErrorKind, QuicError};

    use super::*;

    #[tokio::test]
    async fn any_preserves_future_output() {
        let value = String::from("ready");
        let closed = ArcReceiving::default();
        assert_eq!(any(async { &value }, closed.clone()).await.unwrap(), &value);
        assert_eq!(
            any(async { Err::<(), _>("failed") }, closed).await.unwrap(),
            Err("failed"),
        );
    }

    #[tokio::test]
    async fn any_close_interrupts_a_pending_future() {
        let closed = ArcReceiving::default();
        let waiting = tokio::spawn(any(pending::<()>(), closed.clone()));
        tokio::task::yield_now().await;
        closed.set(CloseReason::Internal(QuicError::with_default_fty(
            ErrorKind::ConnectionRefused,
            "connection closed while waiting",
        )));

        let reason = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(matches!(reason, CloseReason::Internal(error)
            if error.kind() == ErrorKind::ConnectionRefused
                && error.reason() == "connection closed while waiting"));
    }
}
