//! QUIC paths, packet transport and connection API. Handshake orchestration lives in qconnection.
//! Protocol integration lives in the modules; applications only need the root exports.
//!
//! ```no_run
//! use qtransport::{ArcConnection, VarInt};
//! use tokio::io::AsyncWriteExt;
//!
//! async fn send_message(conn: ArcConnection) -> Result<(), Box<dyn std::error::Error>> {
//!     if let Some((_, mut writer)) = conn.open_uni_stream().await? {
//!         writer.write_all(b"hello").await?;
//!         writer.shutdown().await?;
//!     }
//!     conn.close(VarInt::from_u32(0), "done");
//!     Ok(())
//! }
//! ```
mod connection;
pub mod keys;
pub mod packet;
pub mod path;
pub mod progress;
pub mod punch;
pub mod recv;
pub mod router;
pub mod send {
    pub use crate::packet::encrypt::{self as packet, Packet};
}
pub mod space;
pub mod terminate;

pub use connection::ArcConnection;
pub use path::Paths;
pub use progress::ArcProgress;
pub use qbase::{error::Error, param::ArcParameters, role::Role, sid::StreamId, varint::VarInt};
pub use qrecovery::{recv::StopSending, send::CancelStream, streams::error::StreamError};
pub use terminate::CloseReason;
pub type ArcReliableFrames = qrecovery::reliable::ArcReliableFrames<qbase::frame::ReliableFrame>;
pub type DataStreams = qrecovery::streams::ArcDataStreams<ArcReliableFrames>;
pub type ArcLocalCids = qbase::cid::ArcLocalCids<router::QuicRouterRegistry<ArcReliableFrames>>;
pub type ArcRemoteCids = qbase::cid::ArcRemoteCids<ArcReliableFrames>;
pub type ArcDcid = qbase::cid::ArcDcid<ArcReliableFrames>;
pub type CidRegistry = qbase::cid::Registry<ArcLocalCids, ArcRemoteCids>;
pub type ArcHandshakeDone = qbase::handshake::ArcHandshakeDone<ArcReliableFrames>;
pub type ArcPuncher = qtraversal::punch::ArcPuncher<ArcReliableFrames, punch::ProbeEncoder>;
pub type ArcResend = qbase::util::ArcIndexDeque<std::sync::Arc<dyn qcongestion::Resend>, 2>;
pub type StreamReader = qrecovery::recv::Reader<qrecovery::streams::Ext<ArcReliableFrames>>;
pub type StreamWriter = qrecovery::send::Writer<qrecovery::streams::Ext<ArcReliableFrames>>;

pub type Connected = (Option<qtls::LocalAuthority>, qtls::RemoteAuthority, ArcConnection);
pub type Accepted = (Option<qtls::RemoteAuthority>, qtls::LocalAuthority, ArcConnection);

pub use qbase::frame::GuaranteedFrame;
