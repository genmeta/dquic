//! Adapt signing capabilities across the two existing rustls dependencies.
//! No encoded private key crosses this boundary.
use std::sync::Arc;

use qbase::endpoint::LocalAuthority;

#[derive(Debug)]
pub(crate) struct Verifier(pub(crate) Arc<dyn rustls::client::danger::ServerCertVerifier>);

impl qtls::VerifyIdentity for Verifier {
    fn verify(
        &self,
        expected: Option<&str>,
        certificates: &[qtls::CertificateDer<'_>],
        ocsp: Option<&[u8]>,
        now: qtls::UnixTime,
    ) -> Result<Option<Arc<str>>, qtls::CertificateError> {
        let name = expected.ok_or(qtls::CertificateError::NotValidForName)?;
        let server_name = qtls::ServerName::try_from(name)
            .map_err(|_| qtls::CertificateError::NotValidForName)?;
        let (leaf, intermediates) = certificates
            .split_first()
            .ok_or(qtls::CertificateError::BadEncoding)?;
        self.0
            .verify_server_cert(
                leaf,
                intermediates,
                &server_name,
                ocsp.unwrap_or_default(),
                now,
            )
            .map_err(|_| qtls::CertificateError::ApplicationVerificationFailure)?;
        Ok(Some(name.into()))
    }
}

pub(crate) fn local_authority(
    local: &LocalAuthority,
) -> Result<qtls::LocalAuthority, qtls::InvalidLocalAuthority> {
    qtls::LocalAuthority::from_signing_key(
        local.name().into(),
        local.cert_chain().to_vec(),
        Arc::new(SigningKey(local.signing_key().clone())),
        local.ocsp().map(<[u8]>::to_vec),
    )
}

#[derive(Debug)]
struct SigningKey(Arc<dyn rustls::sign::SigningKey>);

impl tls_backend::sign::SigningKey for SigningKey {
    fn choose_scheme(
        &self,
        offered: &[tls_backend::SignatureScheme],
    ) -> Option<Box<dyn tls_backend::sign::Signer>> {
        let offered = offered
            .iter()
            .map(|scheme| rustls::SignatureScheme::from(u16::from(*scheme)))
            .collect::<Vec<_>>();
        self.0
            .choose_scheme(&offered)
            .map(|signer| Box::new(Signer(signer)) as Box<dyn tls_backend::sign::Signer>)
    }

    fn public_key(&self) -> Option<tls_backend::pki_types::SubjectPublicKeyInfoDer<'_>> {
        self.0.public_key()
    }

    fn algorithm(&self) -> tls_backend::SignatureAlgorithm {
        tls_backend::SignatureAlgorithm::from(u8::from(self.0.algorithm()))
    }
}

#[derive(Debug)]
struct Signer(Box<dyn rustls::sign::Signer>);

impl tls_backend::sign::Signer for Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, tls_backend::Error> {
        self.0
            .sign(message)
            .map_err(|error| tls_backend::Error::General(error.to_string()))
    }

    fn scheme(&self) -> tls_backend::SignatureScheme {
        tls_backend::SignatureScheme::from(u16::from(self.0.scheme()))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use bytes::Bytes;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    use super::*;

    const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
    const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");
    const CLIENT_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/client.cert");
    const CLIENT_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/client.key");

    fn authority(name: &str, certificate: &[u8], key: &[u8]) -> LocalAuthority {
        qbase::endpoint::Endpoint::new(
            &rustls::crypto::ring::default_provider(),
            name,
            vec![CertificateDer::from_pem_slice(certificate).unwrap()],
            PrivateKeyDer::from_pem_slice(key).unwrap(),
            None,
        )
        .unwrap()
        .into()
    }

    #[derive(Debug)]
    struct Authority(Option<qtls::LocalAuthority>);

    impl qtls::ResolveServerAuthority for Authority {
        fn resolve(
            &self,
            request: qtls::ServerCredentialRequest<'_>,
        ) -> Option<qtls::LocalAuthority> {
            self.0
                .as_ref()
                .filter(|local| Some(local.name()) == request.server_name)
                .cloned()
        }
    }

    impl qtls::ResolveClientAuthority for Authority {
        fn resolve(&self, _: qtls::ClientCertificateRequest<'_>) -> Option<qtls::LocalAuthority> {
            self.0.clone()
        }
        fn has_authority(&self) -> bool {
            self.0.is_some()
        }
    }

    // Fixture-only pinning; production must supply its own trust/name policy.
    #[derive(Debug)]
    struct PinnedCertificate(&'static str, CertificateDer<'static>);

    pub(crate) fn verifier(
        name: &'static str,
        certificate: &[u8],
    ) -> Arc<dyn qtls::VerifyIdentity> {
        Arc::new(PinnedCertificate(
            name,
            CertificateDer::from_pem_slice(certificate).unwrap(),
        ))
    }

    impl qtls::VerifyIdentity for PinnedCertificate {
        fn verify(
            &self,
            expected: Option<&str>,
            certificates: &[CertificateDer<'_>],
            _: Option<&[u8]>,
            _: qtls::UnixTime,
        ) -> Result<Option<Arc<str>>, qtls::CertificateError> {
            if certificates != [self.1.clone()] {
                return Err(qtls::CertificateError::UnknownIssuer);
            }
            if expected.is_some_and(|name| name != self.0) {
                return Err(qtls::CertificateError::NotValidForName);
            }
            Ok(Some(self.0.into()))
        }
    }

    pub(crate) fn pair(mutual: bool) -> (qtls::TlsHandshake, qtls::TlsHandshake) {
        let provider = Arc::new(qtls::default_provider());
        let server = authority("localhost", SERVER_CERT, SERVER_KEY);
        let client = authority("client", CLIENT_CERT, CLIENT_KEY);
        let client_tls = qtls::ClientTlsEndpoint::new(qtls::ClientTlsConfig {
            provider: provider.clone(),
            alpn: vec![b"qconn".to_vec()],
            resolve_local: Arc::new(Authority(mutual.then(|| local_authority(&client).unwrap()))),
            verify_server: Arc::new(PinnedCertificate(
                "localhost",
                server.cert_chain()[0].clone(),
            )),
            resumption: qtls::ClientResumptionConfig::Disabled,
            limits: qtls::TlsLimits::default(),
        })
        .unwrap();
        let server_tls = qtls::ServerTlsEndpoint::new(qtls::ServerTlsConfig {
            provider,
            alpn: vec![b"qconn".to_vec()],
            resolve_local: Arc::new(Authority(Some(local_authority(&server).unwrap()))),
            verify_client: mutual.then(|| {
                Arc::new(PinnedCertificate("client", client.cert_chain()[0].clone()))
                    as Arc<dyn qtls::VerifyIdentity>
            }),
            resumption: qtls::ServerResumptionConfig::Disabled,
            limits: qtls::TlsLimits::default(),
        })
        .unwrap();
        (
            client_tls
                .start(qtls::ClientStart {
                    server_name: "localhost".try_into().unwrap(),
                    quic_version: qtls::QuicVersion::V1,
                    local_transport_parameters: Bytes::from_static(b"client parameters"),
                })
                .unwrap(),
            server_tls
                .start(
                    qtls::QuicVersion::V1,
                    Bytes::from_static(b"server parameters"),
                )
                .unwrap(),
        )
    }

    pub(crate) fn initial_keys() -> qtls::BidirectionalKeys {
        qtls::ServerTlsEndpoint::new(qtls::ServerTlsConfig {
            provider: Arc::new(qtls::default_provider()),
            alpn: vec![b"qconn".to_vec()],
            resolve_local: Arc::new(Authority(None)),
            verify_client: None,
            resumption: qtls::ServerResumptionConfig::Disabled,
            limits: qtls::TlsLimits::default(),
        })
        .unwrap()
        .initial_keys(qtls::QuicVersion::V1, b"original")
        .unwrap()
    }

    pub(crate) fn handshake(mutual: bool) -> [qtls::OneRttKeyMaterial; 2] {
        let (client, server) = pair(mutual);
        let mut peers = [client, server];
        let mut keys = [None, None];
        let mut completed = [None, None];
        let mut parameters = [false, false];
        for _ in 0..16 {
            let mut progress = false;
            for i in 0..2 {
                while let Some(event) = peers[i].next_event() {
                    progress = true;
                    match event {
                        qtls::TlsEvent::WriteCrypto { level, bytes } => {
                            peers[1 - i].receive_crypto(level, &bytes).unwrap()
                        }
                        qtls::TlsEvent::InstallKeys(qtls::InstalledKeys::OneRtt(material)) => {
                            keys[i] = Some(material)
                        }
                        qtls::TlsEvent::InstallKeys(qtls::InstalledKeys::Handshake(_)) => {}
                        qtls::TlsEvent::ClientHello {
                            server_name,
                            transport_parameters,
                        } => {
                            assert_eq!(i, 1);
                            assert_eq!(server_name.as_deref(), Some("localhost"));
                            assert_eq!(transport_parameters.as_ref(), b"client parameters");
                            parameters[i] = true;
                        }
                        qtls::TlsEvent::ServerTransportParameters(bytes) => {
                            assert_eq!(i, 0);
                            assert_eq!(bytes.as_ref(), b"server parameters");
                            parameters[i] = true;
                        }
                        qtls::TlsEvent::HandshakeComplete(summary) => {
                            assert!(parameters[i] && keys[i].is_some());
                            assert!(completed[i].replace(summary).is_none());
                        }
                        _ => panic!("unexpected TLS event"),
                    }
                }
            }
            if !progress {
                break;
            }
        }
        let [client, server] = completed.map(Option::unwrap);
        assert_eq!(client.local.is_some(), mutual);
        assert_eq!(server.remote.is_some(), mutual);
        assert_eq!(client.remote.unwrap().name(), "localhost");
        assert_eq!(server.local.unwrap().name(), "localhost");
        let [client, server] = peers.map(|tls| tls.finish().unwrap());
        let mut client_exporter = [0; 32];
        let mut server_exporter = [0; 32];
        client
            .export_keying_material(&mut client_exporter, b"qconn integration", None)
            .unwrap();
        server
            .export_keying_material(&mut server_exporter, b"qconn integration", None)
            .unwrap();
        assert_eq!(client_exporter, server_exporter);
        keys.map(Option::unwrap)
    }

    #[test]
    fn loaded_qbase_keys_complete_mutual_and_anonymous_tls_handshakes() {
        handshake(true);
        handshake(false);
    }

    #[test]
    fn invalid_material_is_rejected_at_handshake_credential_creation() {
        let local = authority("localhost", CLIENT_CERT, SERVER_KEY);
        assert!(matches!(
            local_authority(&local),
            Err(qtls::InvalidLocalAuthority::InvalidPrivateKey(_))
        ));
        let local = authority("not a dns name", SERVER_CERT, SERVER_KEY);
        assert!(matches!(
            local_authority(&local),
            Err(qtls::InvalidLocalAuthority::InvalidName)
        ));
    }
}
