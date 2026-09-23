//! A connection's lifetime, written in protocol order for each endpoint role.

use std::future::Future;

use qbase::ArcReceiving;

mod client;
mod interceptor;
mod server;

pub use client::client_growing;
pub use interceptor::Interceptor;
pub use server::server_growing;

use crate::{CloseReason, Error};

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
