use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use qbase::{
    cid::ConnectionId,
    error::{Error, QuicError},
    param::{ParameterId, Parameters, WriteParameters},
    role::{Client, Role},
};
use tokio::{sync::mpsc, task::JoinHandle, time::Instant};

use crate::{
    Anonymous, Endpoint, handshake::Connecting, network::Network, router::RouteLease,
    transport::Transport,
};

pub(crate) async fn connect_initial(
    network: &Network,
    endpoint: Option<&Endpoint>,
    name: &str,
) -> Result<
    (
        Connecting,
        Parameters,
        RouteLease,
        JoinHandle<()>,
        mpsc::Receiver<(qtls::CryptoLevel, Bytes)>,
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
    let timeout: std::time::Duration = local.get(ParameterId::MaxIdleTimeout).unwrap();
    let paths = if timeout.is_zero() {
        network.resolve(name).await?
    } else {
        tokio::time::timeout_at(started + timeout, network.resolve(name))
            .await
            .map_err(|_| crate::internal("name resolution exceeded max_idle_timeout"))??
    };
    let resolve_local: Arc<dyn qtls::ResolveClientAuthority> = match endpoint {
        Some(endpoint) => {
            crate::tls::local_authority(&crate::LocalAuthority::from(endpoint.identity.clone()))
                .map_err(|error| crate::internal(error.to_string()))?;
            Arc::new(endpoint.clone())
        }
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
    let original_dcid = ConnectionId::random_gen(8);
    let (local_cid, route, packets) = loop {
        let cid = ConnectionId::random_gen(8);
        if let Some((route, packets)) = network.router.register(cid) {
            break (cid, route, packets);
        }
    };
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
    let parameters = Parameters::new_client(local, None, original_dcid);
    let (transport, topology, commands, crypto) = Transport::new(
        Role::Client,
        keys,
        original_dcid,
        local_cid,
        network.protocol.clone(),
        timeout,
        started,
    );
    let receiver = tokio::spawn(topology.run(transport.clone(), packets, commands));
    for pathway in paths {
        transport.paths.add(pathway, &transport);
    }
    Ok((
        Connecting { transport, tls },
        parameters,
        route,
        receiver,
        crypto,
    ))
}
