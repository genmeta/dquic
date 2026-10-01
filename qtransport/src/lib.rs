//! Mature QUIC connection API. Handshake and Closing/Draining are driven by qconnection.
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
pub mod recv;
pub mod router;
#[cfg(test)]
#[path = "tests/send.rs"]
mod send;
pub mod space;

pub use connection::{ArcConnection, CloseReason};
pub use qbase::{
    error::Error, param::ArcParameters, role::Role, sid::StreamId, varint::VarInt,
};
pub use qrecovery::{recv::StopSending, send::CancelStream, streams::error::StreamError};
pub type ArcReliableFrames = qrecovery::reliable::ArcReliableFrames<qbase::frame::ReliableFrame>;
pub type StreamReader = qrecovery::recv::Reader<qrecovery::streams::Ext<ArcReliableFrames>>;
pub type StreamWriter = qrecovery::send::Writer<qrecovery::streams::Ext<ArcReliableFrames>>;

pub use qbase::frame::GuaranteedFrame;

#[cfg(test)]
mod tests;
