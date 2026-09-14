use std::sync::Arc;

use qbase::{error::Error, role::Role};
use tokio::sync::{mpsc, oneshot, watch};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Initial,
    Handshake,
    Active,
    Closing,
    Draining,
    Closed,
}

pub(crate) enum Command {
    InstallKeys(qtls::InstalledKeys, oneshot::Sender<Result<(), Error>>),
    TlsComplete(oneshot::Sender<Result<(), Error>>),
    HandshakeSent,
}

/// Lifecycle commands are serialized by the receive topology. Key material lives
/// in the receiving node and sending Space, not in a second central key store.
pub(crate) struct Control {
    pub(crate) role: Role,
    pub(crate) phase: watch::Sender<Phase>,
    pub(crate) handshake: Arc<qcongestion::HandshakeStatus>,
    pub(crate) commands: mpsc::Sender<Command>,
}

impl Control {
    pub(crate) fn new(role: Role) -> (Self, mpsc::Receiver<Command>) {
        let (commands, receiver) = mpsc::channel(16);
        (
            Self {
                role,
                phase: watch::channel(Phase::Initial).0,
                handshake: Arc::new(qcongestion::HandshakeStatus::new(role == Role::Server)),
                commands,
            },
            receiver,
        )
    }

    pub(crate) async fn install_keys(&self, keys: qtls::InstalledKeys) -> Result<(), Error> {
        let (done, ready) = oneshot::channel();
        self.commands
            .send(Command::InstallKeys(keys, done))
            .await
            .map_err(|_| super::internal("receive task stopped"))?;
        ready
            .await
            .map_err(|_| super::internal("key installation interrupted"))?
    }

    pub(crate) async fn on_tls_complete(&self) -> Result<(), Error> {
        let (done, ready) = oneshot::channel();
        self.commands
            .send(Command::TlsComplete(done))
            .await
            .map_err(|_| super::internal("receive task stopped"))?;
        ready
            .await
            .map_err(|_| super::internal("handshake completion interrupted"))?
    }
}
