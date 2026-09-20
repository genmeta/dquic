//! A connection's lifetime, written in protocol order for each endpoint role.

mod client;
mod interceptor;
mod server;

pub use client::client_growing;
pub use interceptor::Interceptor;
pub use server::server_growing;

use crate::{CloseReason, Error};

fn close_error(reason: &CloseReason) -> Error {
    match reason {
        CloseReason::App(error) => error.clone().into(),
        CloseReason::Peer(frame) => frame.clone().into(),
        CloseReason::Internal(error) => error.clone().into(),
    }
}
