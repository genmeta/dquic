//! QUIC growth and staged packet wiring on qtls, qprotocol and qtransport.
//!
//! [`ArcConnPhase`] starts with [`InitialPhase`]; every path burst reads its
//! current policy. Peer parameters construct [`MaturePhase`] and the complete
//! Data frame pipes. [`client_growing`] and [`server_growing`] each describe the
//! complete lifetime for one endpoint role.

mod endpoint;
mod lifecycle;
mod paths;
pub mod phase;
pub mod recv;
#[expect(
    dead_code,
    reason = "path senders are connected by external path setup"
)]
mod send;
mod signals;
#[expect(
    dead_code,
    reason = "termination is activated with external path senders"
)]
mod terminator;
pub mod tls;

pub use endpoint::{BelongsTo, QuicEndpoint, Scope, Scopes, Server, ServerRegistry};
pub use lifecycle::{Interceptor, client_growing, server_growing};
pub use paths::Paths;
pub use phase::{
    ArcConnPhase, ConnPhase, ConnectingPhase, HandshakingPhase, InitialPhase, MaturePhase,
};
pub use qbase::{error::Error, param::fixed::ArcParameters};
pub use qtransport::{ArcConnection, CloseReason, ReliableFrames};
pub use send::AddPath;
pub use signals::HandshakeSignals;
pub use tls::TlsContext;
pub type DataStreams = qrecovery::streams::DataStreams<ReliableFrames>;
pub type FlowController = qbase::flow::FlowController<ReliableFrames>;
pub type ArcLocalCids =
    qbase::cid::ArcLocalCids<qtransport::router::QuicRouterRegistry<ReliableFrames>>;
pub type Connected = (
    Option<qtls::LocalAuthority>,
    qtls::RemoteAuthority,
    ArcConnection,
);
pub type Accepted = (
    Option<qtls::RemoteAuthority>,
    qtls::LocalAuthority,
    ArcConnection,
);
