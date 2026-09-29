//! QUIC growth and staged packet wiring on qtls, qprotocol and qtransport.
//!
//! Both roles publish [`InitialPhase`] immediately, allowing the server to
//! acknowledge Initial fragments before it has received a complete ClientHello.
//! Every path burst reads that shared sending snapshot.

mod endpoint;
mod lifecycle;
mod paths;
pub mod phase;
pub mod recv;
pub mod send;
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
pub use qtransport::{ArcConnection, ArcReliableFrames, CloseReason};
pub use tls::TlsContext;
pub type DataStreams = qrecovery::streams::DataStreams<ArcReliableFrames>;
pub type FlowController = qbase::flow::FlowController<ArcReliableFrames>;
pub type ArcLocalCids =
    qbase::cid::ArcLocalCids<qtransport::router::QuicRouterRegistry<ArcReliableFrames>>;
pub type CidRegistry =
    qbase::cid::Registry<ArcLocalCids, qbase::cid::ArcRemoteCids<ArcReliableFrames>>;
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
