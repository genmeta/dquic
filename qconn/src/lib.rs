//! QUIC connection establishment and transport, independent of `qconnection`.
//!
//! See `design/qconn` for the ownership and protocol invariants. Incoming
//! connections are queued before allocating TLS or starting connection tasks.
//! This crate is still under implementation; `design/qconn/implementation.md`
//! records the supported connection flow and the remaining protocol work.

mod handshake;
mod router;

mod connection;
mod control;
mod data;
mod endpoint;
mod lifecycle;
mod listener;
mod network;
mod path;
mod recv;
mod send;
mod space;
mod tls;
mod transport;

pub use connection::ArcConnection;
pub use data::{StreamReader, StreamWriter};
pub use endpoint::{
    Accepted, Anonymous, Connected, Endpoint, External, Internal, LocalAuthority, Loopback,
    RemoteAuthority, Scope,
};

fn internal(reason: impl Into<std::borrow::Cow<'static, str>>) -> qbase::error::Error {
    qbase::error::QuicError::with_default_fty(qbase::error::ErrorKind::Internal, reason).into()
}
