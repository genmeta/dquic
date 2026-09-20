use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use qbase::{
    cid::ConnectionId,
    error::{Error, ErrorKind, QuicError},
    net::route::{Link, Pathway},
    param::{ParameterId, Parameters, WriteParameters},
};
use tokio::sync::mpsc;

use crate::{
    Accepted,
    handshake::{
        Connecting,
        hello::{MAX_CLIENT_HELLO, peek_server_name},
    },
    listener::Registration,
    network::Network,
};

/// Only bounded ClientHello bytes exist before endpoint selection; no TLS or DataStreams yet.
#[derive(Default)]
pub(crate) struct Incoming {
    hello: Vec<u8>,
}

impl Incoming {
    #[allow(clippy::type_complexity)]
    pub(crate) fn receive(
        &mut self,
        bytes: Bytes,
        network: &Network,
        local_cid: ConnectionId,
        original_dcid: ConnectionId,
        route: (Pathway, Link),
    ) -> Result<
        Option<(
            Connecting,
            Arc<Registration>,
            mpsc::OwnedPermit<(Arc<Registration>, Accepted)>,
        )>,
        Error,
    > {
        if self.hello.len() + bytes.len() > MAX_CLIENT_HELLO {
            return Err(QuicError::with_default_fty(
                ErrorKind::CryptoBufferExceeded,
                "ClientHello exceeds buffer limit",
            )
            .into());
        }
        self.hello.extend_from_slice(&bytes);
        let Some(name) = peek_server_name(&self.hello)
            .map_err(|reason| QuicError::with_default_fty(ErrorKind::Crypto(50), reason))?
        else {
            return Ok(None);
        };
        let registration = network.listener.select(name).ok_or_else(|| {
            QuicError::with_default_fty(ErrorKind::ConnectionRefused, "endpoint is not listening")
        })?;
        if !registration.scope.allows(route.0, route.1) {
            return Err(QuicError::with_default_fty(
                ErrorKind::ConnectionRefused,
                "endpoint scope rejects this route",
            )
            .into());
        }
        let delivery = network
            .listener
            .accepted
            .clone()
            .try_reserve_owned()
            .map_err(|_| {
                QuicError::with_default_fty(
                    ErrorKind::ConnectionRefused,
                    "connection delivery queue is full",
                )
            })?;
        let mut local = registration.parameters.clone();
        local
            .set(ParameterId::InitialSourceConnectionId, local_cid)
            .map_err(QuicError::from)?;
        local
            .set(ParameterId::OriginalDestinationConnectionId, original_dcid)
            .map_err(QuicError::from)?;
        let mut parameters = BytesMut::new();
        parameters.put_parameters(&local);
        let endpoint = qtls::ServerTlsEndpoint::new(qtls::ServerTlsConfig {
            provider: network.provider.clone(),
            alpn: vec![b"qconn".to_vec()],
            resolve_local: registration.endpoint.clone(),
            verify_client: network.verify_client.clone(),
            resumption: qtls::ServerResumptionConfig::Disabled,
            limits: qtls::TlsLimits::default(),
        })
        .map_err(|error| crate::internal(error.to_string()))?;
        let mut tls = endpoint
            .start(qtls::QuicVersion::V1, parameters.freeze())
            .map_err(|error| crate::internal(error.to_string()))?;
        tls.receive_crypto(qtls::CryptoLevel::Initial, &self.hello)
            .map_err(super::tls_error)?;
        Ok(Some((
            Connecting::new(tls, Parameters::new_server(local), name.to_owned()),
            registration,
            delivery,
        )))
    }
}
