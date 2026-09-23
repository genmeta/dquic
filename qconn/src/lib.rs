//! QUIC growth and staged packet wiring on qtls, qprotocol and qtransport.
//!
//! Both roles publish [`InitialPhase`] immediately, allowing the server to
//! acknowledge Initial fragments before it has received a complete ClientHello.
//! Every path burst reads that shared sending snapshot.

mod burst;
mod endpoint;
mod lifecycle;
mod paths;
pub mod phase;
pub mod recv;
mod signals;
mod terminate;
pub mod tls;

pub use endpoint::{QuicEndpoint, Server, ServerRegistry};
pub use lifecycle::{Interceptor, client_growing, server_growing};
pub use paths::Paths;
pub use phase::{ArcConnPhase, ConnPhase, HandshakePhase, InitialPhase, MaturePhase};
pub use qbase::{
    error::Error,
    net::route::{Scope, Scopes},
    param::fixed::ArcParameters,
};
pub use qtransport::{ArcConnection, CloseReason, ReliableFrames};
pub use signals::HandshakeSignals;
pub use tls::TlsContext;
pub type DataStreams = qrecovery::streams::DataStreams<ReliableFrames>;
pub type FlowController = qbase::flow::FlowController<ReliableFrames>;
pub type ArcLocalCids =
    qbase::cid::ArcLocalCids<qtransport::router::QuicRouterRegistry<ReliableFrames>>;
pub type CidRegistry =
    qbase::cid::Registry<ArcLocalCids, qbase::cid::ArcRemoteCids<ReliableFrames>>;
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
