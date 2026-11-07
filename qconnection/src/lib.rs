//! QUIC growth and staged packet wiring on qtls, qprotocol and qtransport.
//!
//! Both roles install the Initial space immediately, allowing the server to
//! acknowledge Initial fragments before it has received a complete ClientHello.
//! Every path burst reads the shared packet-number spaces.

mod endpoint;
pub(crate) mod lifecycle;
mod paths;
mod progress;
pub mod recv;
pub mod send;
pub mod tls;

use std::sync::Arc;

pub use endpoint::{QuicEndpoint, Server, ServerRegistry};
pub use lifecycle::{Interceptor, client_growing, server_growing};
pub use paths::Paths;
pub use progress::ArcProgress;
use qbase::util::ArcIndexDeque;
pub use qbase::{
    error::Error,
    net::route::{Scope, Scopes},
    param::ArcParameters,
};
pub use qtransport::{ArcConnection, ArcReliableFrames, CloseReason};
pub use tls::TlsContext;
pub type DataStreams = qrecovery::streams::DataStreams<ArcReliableFrames>;
pub type ArcLocalCids = qbase::cid::ArcLocalCids<qtransport::router::QuicRouterRegistry<ArcReliableFrames>>;
pub type ArcRemoteCids = qbase::cid::ArcRemoteCids<ArcReliableFrames>;
pub type ArcDcid = qbase::cid::ArcDcid<ArcReliableFrames>;
pub type CidRegistry = qbase::cid::Registry<ArcLocalCids, ArcRemoteCids>;
pub type ArcHandshakeDone = qbase::handshake::ArcHandshakeDone<ArcReliableFrames>;
pub type ArcResend = ArcIndexDeque<Arc<dyn qcongestion::Resend>, 2>;

pub type Connected = (Option<qtls::LocalAuthority>, qtls::RemoteAuthority, ArcConnection);
pub type Accepted = (Option<qtls::RemoteAuthority>, qtls::LocalAuthority, ArcConnection);
