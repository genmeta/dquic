//! Mature QUIC connection API. Handshake and Closing/Draining are driven by qconn.
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
pub mod send;
pub mod space;
pub mod transport;

pub use connection::{ArcConnection, CloseReason};
pub use qbase::{
    error::Error, param::fixed::ArcParameters, role::Role, sid::StreamId, varint::VarInt,
};
pub use qrecovery::{recv::StopSending, send::CancelStream, streams::error::StreamError};
pub type ReliableFrames = qrecovery::reliable::ArcReliableFrameDeque<qbase::frame::ReliableFrame>;
pub type StreamReader = qrecovery::recv::Reader<qrecovery::streams::Ext<ReliableFrames>>;
pub type StreamWriter = qrecovery::send::Writer<qrecovery::streams::Ext<ReliableFrames>>;

use qbase::frame::{CryptoFrame, Frame, ReliableFrame, StreamFrame};

/// Recovery descriptors; STREAM and CRYPTO payloads remain in their source buffers.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum GuaranteedFrame {
    Stream(StreamFrame),
    Crypto(CryptoFrame),
    Reliable(ReliableFrame),
}

impl TryFrom<Frame<()>> for GuaranteedFrame {
    type Error = Frame<()>;

    fn try_from(frame: Frame<()>) -> Result<Self, Self::Error> {
        let reliable = match frame {
            Frame::Stream(frame, ()) => return Ok(Self::Stream(frame)),
            Frame::Crypto(frame, ()) => return Ok(Self::Crypto(frame)),
            Frame::NewToken(frame) => ReliableFrame::NewToken(frame),
            Frame::MaxData(frame) => ReliableFrame::MaxData(frame),
            Frame::DataBlocked(frame) => ReliableFrame::DataBlocked(frame),
            Frame::NewConnectionId(frame) => ReliableFrame::NewConnectionId(frame),
            Frame::RetireConnectionId(frame) => ReliableFrame::RetireConnectionId(frame),
            Frame::HandshakeDone(frame) => ReliableFrame::HandshakeDone(frame),
            Frame::AddAddress(frame) => ReliableFrame::AddAddress(frame),
            Frame::RemoveAddress(frame) => ReliableFrame::RemoveAddress(frame),
            Frame::PunchMeNow(frame) => ReliableFrame::PunchMeNow(frame),
            Frame::PunchDone(frame) => ReliableFrame::PunchDone(frame),
            Frame::StreamCtl(frame) => ReliableFrame::StreamCtl(frame),
            frame => return Err(frame),
        };
        Ok(Self::Reliable(reliable))
    }
}

impl From<GuaranteedFrame> for Frame<()> {
    fn from(frame: GuaranteedFrame) -> Self {
        match frame {
            GuaranteedFrame::Stream(frame) => Self::Stream(frame, ()),
            GuaranteedFrame::Crypto(frame) => Self::Crypto(frame, ()),
            GuaranteedFrame::Reliable(frame) => frame.into(),
        }
    }
}

#[cfg(test)]
mod tests;
