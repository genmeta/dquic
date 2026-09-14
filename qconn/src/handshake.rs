pub(crate) mod connect;
pub(crate) mod hello;
pub(crate) mod incoming;

use std::sync::Arc;

use bytes::Bytes;
use qbase::{
    Epoch,
    error::{Error, ErrorKind, QuicError},
    param::{ArcParameters, ClientParameters, ParameterId, Parameters, ServerParameters},
    role::Role,
};
use tokio::{io::AsyncWriteExt, sync::mpsc};

use crate::{data::DataPlane, transport::Transport};

/// The only owner of TLS during incubation. The lifecycle future consumes this
/// object and moves EstablishedTls into run_active after successful promotion.
pub(crate) struct Connecting {
    pub(crate) transport: Arc<Transport>,
    pub(crate) tls: qtls::TlsHandshake,
}

impl Connecting {
    async fn crypto_event(&mut self, event: qtls::TlsEvent) -> Result<(), Error> {
        match event {
            qtls::TlsEvent::InstallKeys(keys) => self.transport.control.install_keys(keys).await,
            qtls::TlsEvent::WriteCrypto { level, bytes } => {
                let epoch = match level {
                    qtls::CryptoLevel::Initial => Epoch::Initial,
                    qtls::CryptoLevel::Handshake => Epoch::Handshake,
                    qtls::CryptoLevel::OneRtt => Epoch::Data,
                };
                let (_, _, stream, _, _) = self
                    .transport
                    .spaces
                    .snapshot(epoch)
                    .ok_or_else(|| crate::internal("TLS wrote to an unavailable space"))?;
                stream
                    .writer()
                    .write_all(&bytes)
                    .await
                    .map_err(|error| crate::internal(error.to_string()))
            }
            qtls::TlsEvent::Alert(alert) => Err(QuicError::with_default_fty(
                ErrorKind::Crypto(alert.description()),
                "TLS alert",
            )
            .into()),
            _ => Err(crate::internal("unexpected TLS event")),
        }
    }

    async fn receive_crypto(
        &mut self,
        crypto: &mut mpsc::Receiver<(qtls::CryptoLevel, Bytes)>,
    ) -> Result<(), Error> {
        tokio::select! {
            biased;
            error = self.transport.close.closing() => Err(error),
            message = crypto.recv() => {
                let (level, bytes) = message.ok_or_else(|| crate::internal("CRYPTO receive pipe stopped"))?;
                self.tls.receive_crypto(level, &bytes).map_err(|error| QuicError::with_default_fty(ErrorKind::Crypto(40), error.to_string()).into())
            }
        }
    }

    pub(crate) async fn negotiate_parameters(
        &mut self,
        mut parameters: Parameters,
        expected_name: &str,
        crypto: &mut mpsc::Receiver<(qtls::CryptoLevel, Bytes)>,
    ) -> Result<ArcParameters, Error> {
        loop {
            while let Some(event) = self.tls.next_event() {
                match event {
                    qtls::TlsEvent::ClientHello {
                        server_name,
                        transport_parameters,
                    } => {
                        if parameters.role() != Role::Server
                            || server_name.as_deref() != Some(expected_name)
                        {
                            return Err(QuicError::with_default_fty(
                                ErrorKind::ProtocolViolation,
                                "TLS SNI changed after endpoint selection",
                            )
                            .into());
                        }
                        parameters.recv_remote_params(ClientParameters::parse_from_bytes(
                            &transport_parameters,
                        )?)?;
                    }
                    qtls::TlsEvent::ServerTransportParameters(bytes) => {
                        if parameters.role() != Role::Client {
                            return Err(crate::internal("server received server parameters"));
                        }
                        let remote = ServerParameters::parse_from_bytes(&bytes)?;
                        if remote.contains(ParameterId::RetrySourceConnectionId) {
                            return Err(QuicError::with_default_fty(
                                ErrorKind::TransportParameter,
                                "unexpected Retry source CID",
                            )
                            .into());
                        }
                        parameters.recv_remote_params(remote)?;
                    }
                    event => {
                        self.crypto_event(event).await?;
                        continue;
                    }
                }
                let peer_cid =
                    self.transport.peer_cid.get().ok_or_else(|| {
                        crate::internal("peer parameters arrived before its Initial")
                    })?;
                parameters.initial_scid_from_peer_need_equal(*peer_cid)?;
                if !parameters.is_remote_params_ready() {
                    return Err(crate::internal("peer parameters failed to become ready"));
                }
                self.transport.idle.negotiate_max_idle_timeout(
                    parameters.get_remote(ParameterId::MaxIdleTimeout).unwrap(),
                );
                let parameters = ArcParameters::from(parameters);
                let data = DataPlane::new(
                    parameters.clone(),
                    self.transport.reliable.clone(),
                    self.transport.wakers.clone(),
                )?;
                self.transport
                    .data
                    .set(data)
                    .map_err(|_| crate::internal("data components installed twice"))?;
                return Ok(parameters);
            }
            self.receive_crypto(crypto).await?;
        }
    }

    pub(crate) async fn complete_handshake(
        mut self,
        crypto: &mut mpsc::Receiver<(qtls::CryptoLevel, Bytes)>,
    ) -> Result<(qtls::HandshakeSummary, qtls::EstablishedTls), Error> {
        loop {
            let mut summary = None;
            while let Some(event) = self.tls.next_event() {
                match event {
                    qtls::TlsEvent::HandshakeComplete(completed) => {
                        if summary.replace(completed).is_some() {
                            return Err(crate::internal("TLS completed twice"));
                        }
                    }
                    event => self.crypto_event(event).await?,
                }
            }
            if let Some(summary) = summary {
                self.transport.control.on_tls_complete().await?;
                let tls = self
                    .tls
                    .finish()
                    .map_err(|error| crate::internal(error.to_string()))?;
                return Ok((summary, tls));
            }
            self.receive_crypto(crypto).await?;
        }
    }
}
