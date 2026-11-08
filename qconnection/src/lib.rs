//! QUIC growth and staged packet wiring on qtls, qprotocol and qtransport.
//!
//! Both roles install the Initial space immediately, allowing the server to
//! acknowledge Initial fragments before it has received a complete ClientHello.

mod endpoint;
pub(crate) mod lifecycle;
pub mod tls;

pub use endpoint::{QuicEndpoint, Server, ServerRegistry};
pub use lifecycle::{Interceptor, client_growing, server_growing};
pub use qbase::{
    error::Error,
    net::route::{Scope, Scopes},
    param::ArcParameters,
};
pub use qtransport::{
    Accepted, ArcConnection, ArcDcid, ArcHandshakeDone, ArcLocalCids, ArcProgress, ArcPuncher, ArcReliableFrames, ArcRemoteCids, ArcResend,
    CidRegistry, CloseReason, Connected, DataStreams, Paths, recv, send,
};
pub use tls::TlsContext;
