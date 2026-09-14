use tokio::{sync::mpsc, time::Instant};

use crate::router::{ReceivedPacket, RouteLease};

/// A queued server connection. No TLS session or receive/send task exists yet.
pub(crate) struct Incoming {
    pub(crate) route: RouteLease,
    pub(crate) packets: mpsc::Receiver<ReceivedPacket>,
    pub(crate) received_at: Instant,
}

use std::{sync::Arc, time::Duration};

use bytes::{Bytes, BytesMut};
use qbase::{
    error::{Error, ErrorKind, QuicError},
    param::{ParameterId, Parameters, WriteParameters},
};

use crate::{
    Accepted,
    handshake::{
        Connecting,
        hello::{MAX_CLIENT_HELLO, peek_server_name},
    },
    listener::Registration,
    network::Network,
    transport::Transport,
};

pub(crate) async fn accept_initial(
    network: &Network,
    transport: Arc<Transport>,
    crypto: &mut mpsc::Receiver<(qtls::CryptoLevel, Bytes)>,
) -> Result<
    (
        Connecting,
        Parameters,
        Arc<Registration>,
        mpsc::OwnedPermit<(Arc<Registration>, Accepted)>,
    ),
    Error,
> {
    let mut hello = Vec::new();
    let idle = transport.idle.timer();
    let name = loop {
        tokio::select! {
            error = transport.close.closing() => return Err(error),
            message = crypto.recv() => {
                let (level, bytes) = message.ok_or_else(|| crate::internal("Initial receive task stopped"))?;
                if level != qtls::CryptoLevel::Initial || hello.len() + bytes.len() > MAX_CLIENT_HELLO {
                    return Err(QuicError::with_default_fty(ErrorKind::CryptoBufferExceeded, "ClientHello exceeds buffer limit").into())
                }
                hello.extend_from_slice(&bytes);
                if let Some(name) = peek_server_name(&hello).map_err(|reason| QuicError::with_default_fty(ErrorKind::Crypto(50), reason))? {
                    break name.to_owned();
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                if idle.timed_out(Instant::now(), Duration::from_secs(1)) {
                    return Err(QuicError::with_default_fty(ErrorKind::None, "Initial idle timeout").into())
                }
            }
        }
    };
    let registration = network.listener.select(&name).ok_or_else(|| {
        QuicError::with_default_fty(ErrorKind::ConnectionRefused, "endpoint is not listening")
    })?;
    let (pathway, link) = *transport
        .received_route
        .get()
        .ok_or_else(|| crate::internal("ClientHello has no receive route"))?;
    if !registration.scope.allows(pathway, link) {
        return Err(QuicError::with_default_fty(
            ErrorKind::ConnectionRefused,
            "endpoint scope rejects this route",
        )
        .into());
    }
    let _ = transport.scope.set(registration.scope);
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
        .set(ParameterId::InitialSourceConnectionId, transport.local_cid)
        .map_err(QuicError::from)?;
    local
        .set(
            ParameterId::OriginalDestinationConnectionId,
            transport.original_dcid,
        )
        .map_err(QuicError::from)?;
    transport
        .idle
        .negotiate_max_idle_timeout(local.get(ParameterId::MaxIdleTimeout).unwrap());
    let mut bytes = BytesMut::new();
    bytes.put_parameters(&local);
    crate::tls::local_authority(&crate::LocalAuthority::from(
        registration.endpoint.identity.clone(),
    ))
    .map_err(|error| crate::internal(error.to_string()))?;
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
        .start(qtls::QuicVersion::V1, bytes.freeze())
        .map_err(|error| crate::internal(error.to_string()))?;
    tls.receive_crypto(qtls::CryptoLevel::Initial, &hello)
        .map_err(|error| QuicError::with_default_fty(ErrorKind::Crypto(40), error.to_string()))?;
    Ok((
        Connecting { transport, tls },
        Parameters::new_server(local),
        registration,
        delivery,
    ))
}
