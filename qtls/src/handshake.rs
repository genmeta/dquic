use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::{
        ResolvesClientCert,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::{
        ClientHello, ResolvesServerCert,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
};

use crate::{
    BidirectionalKeys, CertificateError, ClientCertificateRequest, ExporterError,
    HandshakeNotComplete, LocalAuthority, OneRttKeyMaterial, PeerTlsError, RemoteAuthority,
    ResolveClientAuthority, ResolveServerAuthority, ServerCredentialRequest, TlsAlert, TlsError,
    TlsInvariantError, TlsLimits, VerifyIdentity,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoLevel {
    Initial,
    Handshake,
    OneRtt,
}

pub enum InstalledKeys {
    ZeroRtt(crate::DirectionalKeys),
    Handshake(BidirectionalKeys),
    OneRtt(OneRttKeyMaterial),
}

pub enum TlsEvent {
    WriteCrypto {
        level: CryptoLevel,
        bytes: Bytes,
    },
    InstallKeys(InstalledKeys),
    ClientHello {
        server_name: Option<Arc<str>>,
        transport_parameters: Bytes,
    },
    ServerTransportParameters(Bytes),
    HandshakeComplete(HandshakeSummary),
    Alert(TlsAlert),
}

#[derive(Clone, Debug)]
pub struct HandshakeSummary {
    pub alpn: Option<Bytes>,
    pub local: Option<LocalAuthority>,
    pub remote: Option<RemoteAuthority>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Role {
    Client,
    Server,
}

#[derive(Clone)]
pub(crate) struct PeerState {
    pub authorities: Arc<Mutex<AuthorityState>>,
}

impl PeerState {
    pub(crate) fn new() -> Self {
        Self {
            authorities: Arc::new(Mutex::new(AuthorityState::default())),
        }
    }
}

#[derive(Default)]
pub(crate) struct AuthorityState {
    pub local: Option<LocalAuthority>,
    pub remote: Option<RemoteAuthority>,
    pub resumed_local: Option<LocalAuthority>,
    pub resumed_remote: Option<RemoteAuthority>,
}

pub struct TlsHandshake {
    connection: rustls::quic::Connection,
    role: Role,
    peer: PeerState,
    limits: TlsLimits,
    events: VecDeque<TlsEvent>,
    input_level: CryptoLevel,
    output_level: CryptoLevel,
    received_bytes: usize,
    peer_parameters_emitted: bool,
    complete: bool,
    terminal: bool,
}

impl TlsHandshake {
    pub(crate) fn new(
        connection: rustls::quic::Connection,
        role: Role,
        peer: PeerState,
        limits: TlsLimits,
    ) -> Result<Self, TlsError> {
        let mut handshake = Self {
            connection,
            role,
            peer,
            limits,
            events: VecDeque::new(),
            input_level: CryptoLevel::Initial,
            output_level: CryptoLevel::Initial,
            received_bytes: 0,
            peer_parameters_emitted: false,
            complete: false,
            terminal: false,
        };
        handshake.drain_backend()?;
        Ok(handshake)
    }

    pub fn receive_crypto(
        &mut self,
        level: CryptoLevel,
        contiguous: &[u8],
    ) -> Result<(), TlsError> {
        if contiguous.is_empty() {
            return Ok(());
        }
        if self.terminal {
            return Err(TlsInvariantError::EventAfterTerminal.into());
        }
        if level != self.input_level {
            self.terminal = true;
            return Err(PeerTlsError::WrongCryptoLevel {
                expected: self.input_level,
                actual: level,
            }
            .into());
        }
        let Some(received_bytes) = self.received_bytes.checked_add(contiguous.len()) else {
            self.terminal = true;
            return Err(PeerTlsError::ResourceLimit {
                resource: "handshake bytes",
                limit: self.limits.max_handshake_bytes,
            }
            .into());
        };
        self.received_bytes = received_bytes;
        if self.received_bytes > self.limits.max_handshake_bytes {
            self.terminal = true;
            return Err(PeerTlsError::ResourceLimit {
                resource: "handshake bytes",
                limit: self.limits.max_handshake_bytes,
            }
            .into());
        }

        if let Err(error) = self.connection.read_hs(contiguous) {
            self.terminal = true;
            if let Some(description) = self.connection.alert() {
                let alert = TlsAlert::new(description);
                self.events.push_back(TlsEvent::Alert(alert));
                return Err(TlsError::Alert(alert));
            }
            return Err(PeerTlsError::Protocol(error.to_string()).into());
        }

        if let Err(error) = self.emit_peer_parameters() {
            self.terminal = true;
            return Err(error);
        }
        if let Err(error) = self.drain_backend() {
            self.terminal = true;
            return Err(error);
        }
        if !self.connection.is_handshaking() {
            self.input_level = CryptoLevel::OneRtt;
        }
        if let Err(error) = self.emit_completion() {
            self.terminal = true;
            return Err(error);
        }
        Ok(())
    }

    pub fn next_event(&mut self) -> Option<TlsEvent> {
        self.events.pop_front()
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn finish(self) -> Result<EstablishedTls, HandshakeNotComplete> {
        if !self.complete {
            return Err(HandshakeNotComplete);
        }
        Ok(EstablishedTls {
            connection: self.connection,
            terminal: self.terminal,
        })
    }

    fn emit_peer_parameters(&mut self) -> Result<(), TlsError> {
        if self.peer_parameters_emitted {
            return Ok(());
        }
        let Some(parameters) = self.connection.quic_transport_parameters() else {
            return Ok(());
        };
        let parameters = Bytes::copy_from_slice(parameters);
        match (&self.role, &self.connection) {
            (Role::Server, rustls::quic::Connection::Server(connection)) => {
                self.events.push_back(TlsEvent::ClientHello {
                    server_name: connection.server_name().map(Arc::from),
                    transport_parameters: parameters,
                });
            }
            (Role::Client, rustls::quic::Connection::Client(_)) => {
                self.events
                    .push_back(TlsEvent::ServerTransportParameters(parameters));
            }
            _ => return Err(TlsInvariantError::Missing("matching TLS role").into()),
        }
        self.peer_parameters_emitted = true;
        Ok(())
    }

    fn drain_backend(&mut self) -> Result<(), TlsError> {
        loop {
            let mut output = Vec::new();
            let key_change = self.connection.write_hs(&mut output);
            if output.len() > self.limits.max_flight_bytes {
                return Err(PeerTlsError::ResourceLimit {
                    resource: "output flight",
                    limit: self.limits.max_flight_bytes,
                }
                .into());
            }
            let output_is_empty = output.is_empty();
            if !output_is_empty {
                self.events.push_back(TlsEvent::WriteCrypto {
                    level: self.output_level,
                    bytes: output.into(),
                });
            }

            match key_change {
                Some(rustls::quic::KeyChange::Handshake { keys }) => {
                    self.events
                        .push_back(TlsEvent::InstallKeys(InstalledKeys::Handshake(keys.into())));
                    self.input_level = CryptoLevel::Handshake;
                    self.output_level = CryptoLevel::Handshake;
                }
                Some(rustls::quic::KeyChange::OneRtt { keys, next }) => {
                    self.events
                        .push_back(TlsEvent::InstallKeys(InstalledKeys::OneRtt(
                            OneRttKeyMaterial::new(keys, next),
                        )));
                    self.output_level = CryptoLevel::OneRtt;
                }
                None if output_is_empty => break,
                None => {}
            }
        }
        Ok(())
    }

    fn emit_completion(&mut self) -> Result<(), TlsError> {
        if self.complete || self.connection.is_handshaking() {
            return Ok(());
        }
        let authorities = self
            .peer
            .authorities
            .lock()
            .map_err(|_| TlsInvariantError::Missing("authority state lock"))?;
        let resumed = self.handshake_kind() == Some(rustls::HandshakeKind::Resumed);
        let local = match (authorities.local.clone(), resumed) {
            (None, true) => authorities.resumed_local.clone(),
            (local, _) => local,
        };
        let remote = match (authorities.remote.clone(), resumed) {
            (None, true) => authorities.resumed_remote.clone(),
            (remote, _) => remote,
        };
        match self.role {
            Role::Client if remote.is_none() => {
                return Err(TlsInvariantError::Missing("verified server authority").into());
            }
            Role::Server if local.is_none() => {
                return Err(TlsInvariantError::Missing("selected server authority").into());
            }
            _ => {}
        }
        let summary = HandshakeSummary {
            alpn: self.connection.alpn_protocol().map(Bytes::copy_from_slice),
            local,
            remote,
        };
        self.events.push_back(TlsEvent::HandshakeComplete(summary));
        self.complete = true;
        Ok(())
    }

    fn handshake_kind(&self) -> Option<rustls::HandshakeKind> {
        match &self.connection {
            rustls::quic::Connection::Client(connection) => connection.handshake_kind(),
            rustls::quic::Connection::Server(connection) => connection.handshake_kind(),
        }
    }
}

pub struct EstablishedTls {
    connection: rustls::quic::Connection,
    terminal: bool,
}

impl EstablishedTls {
    pub fn receive_post_handshake(
        &mut self,
        contiguous_one_rtt_crypto: &[u8],
    ) -> Result<(), TlsError> {
        if contiguous_one_rtt_crypto.is_empty() {
            return Ok(());
        }
        if self.terminal {
            return Err(TlsInvariantError::EventAfterTerminal.into());
        }
        if let Err(error) = self.connection.read_hs(contiguous_one_rtt_crypto) {
            self.terminal = true;
            if let Some(description) = self.connection.alert() {
                return Err(TlsError::Alert(TlsAlert::new(description)));
            }
            return Err(PeerTlsError::Protocol(error.to_string()).into());
        }
        let mut unexpected_output = Vec::new();
        if self.connection.write_hs(&mut unexpected_output).is_some()
            || !unexpected_output.is_empty()
        {
            return Err(TlsInvariantError::Missing("post-handshake output sink").into());
        }
        Ok(())
    }

    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), ExporterError> {
        self.connection
            .export_keying_material(output, label, context)
            .map(|_| ())
            .map_err(|_| ExporterError::Failed)
    }
}

pub(crate) fn map_rustls_error(error: rustls::Error) -> TlsError {
    PeerTlsError::Protocol(error.to_string()).into()
}

pub(crate) struct ServerResolver {
    inner: Arc<dyn ResolveServerAuthority>,
    peer: PeerState,
    limits: TlsLimits,
}

impl ServerResolver {
    pub fn new(inner: Arc<dyn ResolveServerAuthority>, peer: PeerState, limits: TlsLimits) -> Self {
        Self {
            inner,
            peer,
            limits,
        }
    }
}

impl fmt::Debug for ServerResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerResolver")
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for ServerResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let alpn: Vec<&[u8]> = hello.alpn().map(Iterator::collect).unwrap_or_default();
        let authority = self.inner.resolve(ServerCredentialRequest {
            server_name: hello.server_name(),
            signature_schemes: hello.signature_schemes(),
            alpn: &alpn,
        })?;
        if !authority_within_limits(&authority, self.limits) {
            return None;
        }
        let certified_key = authority.certified_key();
        self.peer.authorities.lock().ok()?.local = Some(authority);
        Some(certified_key)
    }
}

pub(crate) struct ClientResolver {
    inner: Arc<dyn ResolveClientAuthority>,
    peer: PeerState,
    limits: TlsLimits,
}

impl ClientResolver {
    pub fn new(inner: Arc<dyn ResolveClientAuthority>, peer: PeerState, limits: TlsLimits) -> Self {
        Self {
            inner,
            peer,
            limits,
        }
    }

    pub(crate) fn rebind(
        &self,
        expected: &crate::resumption::AuthorityProjection,
        provider: &rustls::crypto::CryptoProvider,
    ) -> Option<LocalAuthority> {
        let signature_schemes = provider
            .signature_verification_algorithms
            .supported_schemes();
        let authority = self.inner.resolve(ClientCertificateRequest {
            root_hint_subjects: &[],
            signature_schemes: &signature_schemes,
        })?;
        if !authority_within_limits(&authority, self.limits) || !expected.matches(&authority) {
            return None;
        }
        Some(authority)
    }
}

impl fmt::Debug for ClientResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientResolver")
            .finish_non_exhaustive()
    }
}

impl ResolvesClientCert for ClientResolver {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        signature_schemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        let authority = self.inner.resolve(ClientCertificateRequest {
            root_hint_subjects,
            signature_schemes,
        })?;
        if !authority_within_limits(&authority, self.limits) {
            return None;
        }
        let certified_key = authority.certified_key();
        self.peer.authorities.lock().ok()?.local = Some(authority);
        Some(certified_key)
    }

    fn has_certs(&self) -> bool {
        self.inner.has_authority()
    }
}

fn authority_within_limits(authority: &LocalAuthority, limits: TlsLimits) -> bool {
    authority.certificates().len() <= limits.max_certificates
        && authority
            .certificates()
            .iter()
            .map(|certificate| certificate.as_ref().len())
            .sum::<usize>()
            <= limits.max_certificate_chain_bytes
        && authority.ocsp().map_or(0, <[u8]>::len) <= limits.max_ocsp_bytes
}

pub(crate) struct ServerVerifier {
    inner: Arc<dyn VerifyIdentity>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
    peer: PeerState,
    limits: TlsLimits,
}

impl ServerVerifier {
    pub fn new(
        inner: Arc<dyn VerifyIdentity>,
        provider: Arc<rustls::crypto::CryptoProvider>,
        peer: PeerState,
        limits: TlsLimits,
    ) -> Self {
        Self {
            inner,
            algorithms: provider.signature_verification_algorithms,
            peer,
            limits,
        }
    }
}

impl fmt::Debug for ServerVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerVerifier")
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for ServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let certificates = chain(end_entity, intermediates);
        validate_peer_limits(&certificates, ocsp_response, self.limits)?;
        let expected = match server_name {
            ServerName::DnsName(name) => name.as_ref(),
            _ => return Err(CertificateError::NotValidForName.into()),
        };
        let name = self
            .inner
            .verify(
                Some(expected),
                &certificates,
                optional_ocsp(ocsp_response),
                now,
            )
            .map_err(rustls::Error::InvalidCertificate)?
            .ok_or(CertificateError::ApplicationVerificationFailure)?;
        let authority = RemoteAuthority::new(name, &certificates)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        self.peer
            .authorities
            .lock()
            .map_err(|_| rustls::Error::General("verified authority lock poisoned".into()))?
            .remote = Some(authority);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

pub(crate) struct ClientVerifier {
    inner: Arc<dyn VerifyIdentity>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
    peer: PeerState,
    limits: TlsLimits,
}

impl ClientVerifier {
    pub fn new(
        inner: Arc<dyn VerifyIdentity>,
        provider: Arc<rustls::crypto::CryptoProvider>,
        peer: PeerState,
        limits: TlsLimits,
    ) -> Self {
        Self {
            inner,
            algorithms: provider.signature_verification_algorithms,
            peer,
            limits,
        }
    }
}

impl fmt::Debug for ClientVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientVerifier")
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for ClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn request_client_ocsp(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.verify_client_cert_with_ocsp(end_entity, intermediates, &[], now)
    }

    fn verify_client_cert_with_ocsp(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let certificates = chain(end_entity, intermediates);
        validate_peer_limits(&certificates, ocsp_response, self.limits)?;
        let name = self
            .inner
            .verify(None, &certificates, optional_ocsp(ocsp_response), now)
            .map_err(rustls::Error::InvalidCertificate)?
            .ok_or(CertificateError::ApplicationVerificationFailure)?;
        let authority = RemoteAuthority::new(name, &certificates)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        self.peer
            .authorities
            .lock()
            .map_err(|_| rustls::Error::General("verified authority lock poisoned".into()))?
            .remote = Some(authority);
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn chain<'a>(
    end_entity: &CertificateDer<'a>,
    intermediates: &[CertificateDer<'a>],
) -> Vec<CertificateDer<'a>> {
    std::iter::once(end_entity.clone())
        .chain(intermediates.iter().cloned())
        .collect()
}

fn optional_ocsp(response: &[u8]) -> Option<&[u8]> {
    (!response.is_empty()).then_some(response)
}

fn validate_peer_limits(
    certificates: &[CertificateDer<'_>],
    ocsp: &[u8],
    limits: TlsLimits,
) -> Result<(), rustls::Error> {
    if certificates.len() > limits.max_certificates
        || certificates
            .iter()
            .map(|certificate| certificate.as_ref().len())
            .sum::<usize>()
            > limits.max_certificate_chain_bytes
    {
        return Err(CertificateError::BadEncoding.into());
    }
    if ocsp.len() > limits.max_ocsp_bytes {
        return Err(CertificateError::InvalidOcspResponse.into());
    }
    Ok(())
}
