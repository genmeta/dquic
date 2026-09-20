use std::{sync::Arc, time::Duration};

use bytes::BytesMut;
use qbase::{
    cid::ConnectionId,
    error::{Error, QuicError},
    net::route::Pathway,
    param::{ParameterId, Parameters, WriteParameters},
    role::Client,
};
use tokio::time::Instant;

use crate::{Anonymous, Endpoint, handshake::Connecting, network::Network};

/// All fallible preparation precedes route registration and connection task creation.
#[allow(clippy::type_complexity)]
pub(crate) async fn connect_initial(
    network: &Network,
    endpoint: Option<&Endpoint>,
    name: &str,
    local_cid: ConnectionId,
    original_dcid: ConnectionId,
) -> Result<
    (
        Connecting,
        qtls::BidirectionalKeys,
        Vec<Pathway>,
        Duration,
        Instant,
    ),
    Error,
> {
    let started = Instant::now();
    let host = name
        .rsplit_once(':')
        .filter(|(host, port)| !host.contains(':') && port.parse::<u16>().is_ok())
        .map_or(name, |(host, _)| host);
    let server_name = qtls::ServerName::try_from(host.to_owned())
        .map_err(|_| crate::internal("invalid server name"))?;
    let mut local = match endpoint {
        Some(endpoint) => endpoint.local_parameters::<Client>()?,
        None => qbase::param::handy::client_parameters(),
    };
    let timeout: Duration = local.get(ParameterId::MaxIdleTimeout).unwrap();
    let paths = if timeout.is_zero() {
        network.resolve(name).await?
    } else {
        tokio::time::timeout_at(started + timeout, network.resolve(name))
            .await
            .map_err(|_| crate::internal("name resolution exceeded max_idle_timeout"))??
    };
    let resolve_local: Arc<dyn qtls::ResolveClientAuthority> = match endpoint {
        Some(endpoint) => Arc::new(endpoint.clone()),
        None => Arc::new(Anonymous),
    };
    let tls_endpoint = qtls::ClientTlsEndpoint::new(qtls::ClientTlsConfig {
        provider: network.provider.clone(),
        alpn: vec![b"qconn".to_vec()],
        resolve_local,
        verify_server: network.verifier.clone(),
        resumption: qtls::ClientResumptionConfig::Disabled,
        limits: qtls::TlsLimits::default(),
    })
    .map_err(|error| crate::internal(error.to_string()))?;
    local
        .set(ParameterId::InitialSourceConnectionId, local_cid)
        .map_err(QuicError::from)?;
    let mut bytes = BytesMut::new();
    bytes.put_parameters(&local);
    let tls = tls_endpoint
        .start(qtls::ClientStart {
            server_name,
            quic_version: qtls::QuicVersion::V1,
            local_transport_parameters: bytes.freeze(),
        })
        .map_err(|error| crate::internal(error.to_string()))?;
    let keys = tls_endpoint
        .initial_keys(qtls::QuicVersion::V1, &original_dcid)
        .map_err(|error| crate::internal(error.to_string()))?;
    Ok((
        Connecting::new(
            tls,
            Parameters::new_client(local, None, original_dcid),
            host.to_owned(),
        ),
        keys,
        paths,
        timeout,
        started,
    ))
}
