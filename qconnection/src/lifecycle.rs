//! A connection's lifetime, written in protocol order for each endpoint role.

use std::future::Future;

pub(crate) mod client;
mod interceptor;
mod server;

pub use client::client_growing;
pub use interceptor::Interceptor;
use qtransport::terminate::ArcTerminator;
pub use server::server_growing;

use crate::Error;

/// Wait for a future's output or the connection's terminal error.
pub(crate) async fn any<T>(future: impl Future<Output = T>, terminator: ArcTerminator) -> Result<T, Error> {
    tokio::select! {
        biased;
        error = terminator => Err(error),
        result = future => Ok(result),
    }
}
