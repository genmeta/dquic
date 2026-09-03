use std::sync::Arc;

use bytes::Bytes;
use rustls::{ClientConfig, ServerConfig, pki_types::ServerName};

use crate::{
    BidirectionalKeys, ClientResumptionConfig, QuicVersion, ResolveClientAuthority,
    ResolveServerAuthority, ServerResumptionConfig, TlsConfigError, TlsError, TlsHandshake,
    VerifyIdentity,
    handshake::{PeerState, Role},
};

pub struct ClientTlsConfig {
    pub provider: Arc<rustls::crypto::CryptoProvider>,
    pub alpn: Vec<Vec<u8>>,
    pub resolve_local: Arc<dyn ResolveClientAuthority>,
    pub verify_server: Arc<dyn VerifyIdentity>,
    pub resumption: ClientResumptionConfig,
    pub limits: TlsLimits,
}

pub struct ServerTlsConfig {
    pub provider: Arc<rustls::crypto::CryptoProvider>,
    pub alpn: Vec<Vec<u8>>,
    pub resolve_local: Arc<dyn ResolveServerAuthority>,
    pub verify_client: Option<Arc<dyn VerifyIdentity>>,
    pub resumption: ServerResumptionConfig,
    pub limits: TlsLimits,
}

#[derive(Clone, Copy, Debug)]
pub struct TlsLimits {
    pub max_handshake_bytes: usize,
    pub max_flight_bytes: usize,
    pub max_certificate_chain_bytes: usize,
    pub max_certificates: usize,
    pub max_ocsp_bytes: usize,
    pub max_session_bytes: usize,
}

impl Default for TlsLimits {
    fn default() -> Self {
        Self {
            max_handshake_bytes: 256 * 1024,
            max_flight_bytes: 256 * 1024,
            max_certificate_chain_bytes: 256 * 1024,
            max_certificates: 8,
            max_ocsp_bytes: 64 * 1024,
            max_session_bytes: 64 * 1024,
        }
    }
}

pub struct ClientStart {
    pub server_name: ServerName<'static>,
    pub quic_version: QuicVersion,
    pub local_transport_parameters: Bytes,
}

pub struct ClientTlsEndpoint {
    provider: Arc<rustls::crypto::CryptoProvider>,
    alpn: Arc<[Vec<u8>]>,
    resolve_local: Arc<dyn ResolveClientAuthority>,
    verify_server: Arc<dyn VerifyIdentity>,
    resumption: ClientResumptionConfig,
    limits: TlsLimits,
}

pub struct ServerTlsEndpoint {
    provider: Arc<rustls::crypto::CryptoProvider>,
    alpn: Arc<[Vec<u8>]>,
    resolve_local: Arc<dyn ResolveServerAuthority>,
    verify_client: Option<Arc<dyn VerifyIdentity>>,
    resumption: ServerResumptionConfig,
    limits: TlsLimits,
}

impl ClientTlsEndpoint {
    pub fn new(config: ClientTlsConfig) -> Result<Self, TlsConfigError> {
        validate_config(&config.provider, &config.alpn, config.limits)?;
        #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
        if matches!(&config.resumption, ClientResumptionConfig::Enabled { .. }) {
            return Err(TlsConfigError::Invalid(
                "external resumption storage requires the ring or aws-lc-rs feature".into(),
            ));
        }
        Ok(Self {
            provider: config.provider,
            alpn: config.alpn.into(),
            resolve_local: config.resolve_local,
            verify_server: config.verify_server,
            resumption: config.resumption,
            limits: config.limits,
        })
    }

    pub fn initial_keys(
        &self,
        quic_version: QuicVersion,
        destination_connection_id: &[u8],
    ) -> Result<BidirectionalKeys, crate::CryptoError> {
        initial_keys(
            &self.provider,
            rustls::Side::Client,
            quic_version,
            destination_connection_id,
        )
    }

    pub fn start(&self, input: ClientStart) -> Result<TlsHandshake, TlsError> {
        let peer = PeerState::new();
        let verifier = Arc::new(crate::handshake::ServerVerifier::new(
            self.verify_server.clone(),
            self.provider.clone(),
            peer.clone(),
            self.limits,
        ));
        let resolver = Arc::new(crate::handshake::ClientResolver::new(
            self.resolve_local.clone(),
            peer.clone(),
            self.limits,
        ));

        let mut config = ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| TlsConfigError::Invalid(error.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_client_cert_resolver(resolver.clone());
        config.alpn_protocols = self.alpn.to_vec();
        config.enable_early_data = false;
        config.resumption = match &self.resumption {
            ClientResumptionConfig::Disabled => rustls::client::Resumption::disabled(),
            ClientResumptionConfig::Enabled {
                namespace,
                store,
                seal_keys,
            } => rustls::client::Resumption::store(Arc::new(
                crate::resumption::ClientStoreAdapter::new(
                    namespace.clone(),
                    input.quic_version,
                    self.provider.clone(),
                    store.clone(),
                    seal_keys.clone(),
                    verifier,
                    resolver,
                    peer.clone(),
                    self.limits,
                ),
            )),
        };
        require_fips(config.fips())?;

        let connection = rustls::quic::ClientConnection::new(
            Arc::new(config),
            input.quic_version.into(),
            input.server_name,
            input.local_transport_parameters.to_vec(),
        )
        .map_err(crate::handshake::map_rustls_error)?;

        TlsHandshake::new(
            rustls::quic::Connection::Client(connection),
            Role::Client,
            peer,
            self.limits,
        )
    }
}

impl ServerTlsEndpoint {
    pub fn new(config: ServerTlsConfig) -> Result<Self, TlsConfigError> {
        validate_config(&config.provider, &config.alpn, config.limits)?;
        #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
        if matches!(&config.resumption, ServerResumptionConfig::Stateful { .. }) {
            return Err(TlsConfigError::Invalid(
                "stateful resumption requires the ring or aws-lc-rs feature".into(),
            ));
        }
        Ok(Self {
            provider: config.provider,
            alpn: config.alpn.into(),
            resolve_local: config.resolve_local,
            verify_client: config.verify_client,
            resumption: config.resumption,
            limits: config.limits,
        })
    }

    pub fn initial_keys(
        &self,
        quic_version: QuicVersion,
        destination_connection_id: &[u8],
    ) -> Result<BidirectionalKeys, crate::CryptoError> {
        initial_keys(
            &self.provider,
            rustls::Side::Server,
            quic_version,
            destination_connection_id,
        )
    }

    pub fn start(
        &self,
        quic_version: QuicVersion,
        local_transport_parameters: Bytes,
    ) -> Result<TlsHandshake, TlsError> {
        let peer = PeerState::new();
        let resolver = Arc::new(crate::handshake::ServerResolver::new(
            self.resolve_local.clone(),
            peer.clone(),
            self.limits,
        ));

        let builder = ServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| TlsConfigError::Invalid(error.to_string()))?;
        let mut config = match &self.verify_client {
            Some(verify_client) => builder
                .with_client_cert_verifier(Arc::new(crate::handshake::ClientVerifier::new(
                    verify_client.clone(),
                    self.provider.clone(),
                    peer.clone(),
                    self.limits,
                )))
                .with_cert_resolver(resolver),
            None => builder.with_no_client_auth().with_cert_resolver(resolver),
        };
        config.alpn_protocols = self.alpn.to_vec();
        config.max_early_data_size = 0;
        configure_server_resumption(
            &mut config,
            &self.resumption,
            quic_version,
            peer.clone(),
            self.limits,
        );
        require_fips(config.fips())?;

        let connection = rustls::quic::ServerConnection::new(
            Arc::new(config),
            quic_version.into(),
            local_transport_parameters.to_vec(),
        )
        .map_err(crate::handshake::map_rustls_error)?;

        TlsHandshake::new(
            rustls::quic::Connection::Server(connection),
            Role::Server,
            peer,
            self.limits,
        )
    }
}

fn validate_config(
    provider: &rustls::crypto::CryptoProvider,
    alpn: &[Vec<u8>],
    limits: TlsLimits,
) -> Result<(), TlsConfigError> {
    if quic_suite(provider).is_none() {
        return Err(TlsConfigError::MissingQuicSuite);
    }
    if provider.kx_groups.is_empty() {
        return Err(TlsConfigError::Invalid(
            "the crypto provider has no key exchange group".into(),
        ));
    }
    if provider
        .signature_verification_algorithms
        .supported_schemes()
        .is_empty()
    {
        return Err(TlsConfigError::Invalid(
            "the crypto provider has no signature verification algorithm".into(),
        ));
    }
    if alpn
        .iter()
        .any(|protocol| protocol.is_empty() || protocol.len() > u8::MAX as usize)
    {
        return Err(TlsConfigError::Invalid(
            "each ALPN protocol must contain 1..=255 bytes".into(),
        ));
    }
    if limits.max_handshake_bytes == 0
        || limits.max_flight_bytes == 0
        || limits.max_certificate_chain_bytes == 0
        || limits.max_certificates == 0
        || limits.max_ocsp_bytes == 0
        || limits.max_session_bytes == 0
    {
        return Err(TlsConfigError::Invalid(
            "TLS limits must be non-zero".into(),
        ));
    }
    #[cfg(feature = "fips")]
    if !provider.fips() {
        return Err(TlsConfigError::FipsRequired);
    }
    Ok(())
}

fn configure_server_resumption(
    config: &mut ServerConfig,
    resumption: &ServerResumptionConfig,
    version: QuicVersion,
    peer: PeerState,
    limits: TlsLimits,
) {
    match resumption {
        ServerResumptionConfig::Disabled => {
            config.send_tls13_tickets = 0;
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        }
        ServerResumptionConfig::Stateful {
            namespace,
            store,
            seal_keys,
        } => {
            config.session_storage = Arc::new(crate::resumption::ServerStoreAdapter::new(
                namespace.clone(),
                version,
                store.clone(),
                seal_keys.clone(),
                peer,
                limits,
            ));
        }
        ServerResumptionConfig::Stateless { ticket_keys } => {
            config.ticketer = Arc::new(crate::resumption::StatelessTicketAdapter::new(
                ticket_keys.ticketer.clone(),
                peer,
                limits,
            ));
        }
    }
}

fn require_fips(config_is_fips: bool) -> Result<(), TlsConfigError> {
    #[cfg(feature = "fips")]
    if !config_is_fips {
        return Err(TlsConfigError::FipsRequired);
    }
    let _ = config_is_fips;
    Ok(())
}

fn initial_keys(
    provider: &rustls::crypto::CryptoProvider,
    side: rustls::Side,
    version: QuicVersion,
    destination_connection_id: &[u8],
) -> Result<BidirectionalKeys, crate::CryptoError> {
    let suite = quic_suite(provider).ok_or(crate::CryptoError::OperationFailed)?;
    Ok(suite
        .keys(destination_connection_id, side, version.into())
        .into())
}

fn quic_suite(provider: &rustls::crypto::CryptoProvider) -> Option<rustls::quic::Suite> {
    provider
        .cipher_suites
        .iter()
        .find_map(|suite| match (suite.suite(), suite.tls13()) {
            (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => suite.quic_suite(),
            _ => None,
        })
}
