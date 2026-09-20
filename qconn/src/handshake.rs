pub(crate) mod connect;
pub(crate) mod hello;
pub(crate) mod incoming;

use std::sync::Arc;

use bytes::Bytes;
use qbase::{
    Epoch,
    cid::{ConnectionId, GenUniqueCid, RetireCid},
    error::Error,
    frame::{NewConnectionIdFrame, io::SendFrame},
    param::Parameters,
};
use qtransport::{
    ReliableFrames,
    router::{QuicRouter, ReceivedPacket},
};
use tokio::sync::mpsc;

/// TLS and partially completed TLS work live in the connection's Connecting variant.
pub(crate) struct Connecting {
    pub(crate) tls: qtls::TlsHandshake,
    pub(crate) parameters: Parameters,
    pub(crate) name: String,
    pub(crate) writing: Option<(Epoch, Bytes)>,
    pub(crate) summary: Option<qtls::HandshakeSummary>,
}

impl Connecting {
    pub(crate) fn new(tls: qtls::TlsHandshake, parameters: Parameters, name: String) -> Self {
        Self {
            tls,
            parameters,
            name,
            writing: None,
            summary: None,
        }
    }
}

/// The qbase CID manager's broker: register generated CIDs and enqueue its frames.
/// It owns no CID collection and has no independent cleanup policy.
#[derive(Clone)]
pub(crate) struct IssuedCids {
    pub(crate) router: Arc<QuicRouter>,
    pub(crate) packets: mpsc::Sender<ReceivedPacket>,
    pub(crate) reliable: ReliableFrames,
}

impl GenUniqueCid for IssuedCids {
    fn gen_unique_cid(&self) -> ConnectionId {
        loop {
            let cid = ConnectionId::random_gen(8);
            if self.router.insert(cid, self.packets.clone()) {
                return cid;
            }
        }
    }
}

impl RetireCid for IssuedCids {
    fn retire_cid(&self, cid: ConnectionId) {
        self.router.remove(&cid);
    }
}

impl SendFrame<NewConnectionIdFrame> for IssuedCids {
    fn send_frame<I: IntoIterator<Item = NewConnectionIdFrame>>(&self, frames: I) {
        self.reliable.send_frame(frames);
    }
}

pub(crate) fn tls_error(error: impl std::fmt::Display) -> Error {
    qbase::error::QuicError::with_default_fty(
        qbase::error::ErrorKind::Crypto(40),
        error.to_string(),
    )
    .into()
}
