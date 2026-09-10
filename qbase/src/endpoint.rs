use std::{fmt, sync::Arc};

use bytes::Bytes;
use rustls::{
    SignatureScheme,
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, PrivateKeyDer},
    sign::SigningKey,
};
use thiserror::Error;

/// A local name and immutable certificate/key/OCSP material for this process.
#[derive(Clone)]
pub struct Endpoint {
    name: String,
    cert: Vec<CertificateDer<'static>>,
    key: Arc<dyn SigningKey>,
    ocsp: Option<Vec<u8>>,
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Endpoint {
    /// Loads the private key with the selected crypto provider.
    ///
    /// Names and certificate material are retained as supplied. Certificate
    /// parsing, key matching, validity and trust checks belong to the handshake.
    /// An unusable private key is returned immediately as an error.
    pub fn new(
        provider: &CryptoProvider,
        name: &str,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        ocsp: Option<Bytes>,
    ) -> Result<Arc<Self>, rustls::Error> {
        let signing_key = provider.key_provider.load_private_key(key)?;
        Ok(Arc::new(Self {
            name: name.to_owned(),
            cert: certs,
            key: signing_key,
            ocsp: ocsp.map(|bytes| bytes.to_vec()),
        }))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert
    }

    pub fn ocsp(&self) -> Option<&[u8]> {
        self.ocsp.as_deref()
    }
}

/// A local signing identity that can exchange its material with an endpoint.
#[derive(Clone, Debug)]
pub struct LocalAuthority {
    name: String,
    cert: Vec<CertificateDer<'static>>,
    key: Arc<dyn SigningKey>,
    ocsp: Option<Vec<u8>>,
}

#[derive(Debug, Error)]
pub enum SignError {
    #[error("unsupported signature scheme {scheme:?}")]
    UnsupportedScheme { scheme: SignatureScheme },
    #[error(transparent)]
    Crypto(#[from] rustls::Error),
}

impl LocalAuthority {
    /// Takes the endpoint's material when uniquely owned, otherwise clones its
    /// name, certificates and OCSP while sharing the signing key.
    pub fn new(endpoint: Arc<Endpoint>) -> Self {
        endpoint.into()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert
    }

    pub fn ocsp(&self) -> Option<&[u8]> {
        self.ocsp.as_deref()
    }

    /// Signs an unhashed message using the hash and encoding of `scheme`.
    pub fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let signer = self
            .key
            .choose_scheme(&[scheme])
            .ok_or(SignError::UnsupportedScheme { scheme })?;
        Ok(signer.sign(message)?)
    }
}

impl From<Endpoint> for LocalAuthority {
    fn from(endpoint: Endpoint) -> Self {
        Self {
            name: endpoint.name,
            cert: endpoint.cert,
            key: endpoint.key,
            ocsp: endpoint.ocsp,
        }
    }
}

impl From<LocalAuthority> for Endpoint {
    fn from(authority: LocalAuthority) -> Self {
        Self {
            name: authority.name,
            cert: authority.cert,
            key: authority.key,
            ocsp: authority.ocsp,
        }
    }
}

impl From<Arc<Endpoint>> for LocalAuthority {
    fn from(endpoint: Arc<Endpoint>) -> Self {
        Arc::unwrap_or_clone(endpoint).into()
    }
}

/// Remote identity material and message verification capabilities, without a private key.
#[derive(Clone, Debug)]
pub struct RemoteAuthority {
    name: String,
    cert: Vec<CertificateDer<'static>>,
    ocsp: Option<Bytes>,
    algorithms: WebPkiSupportedAlgorithms,
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("unsupported signature scheme {scheme:?}")]
    UnsupportedScheme { scheme: SignatureScheme },
    #[error("authority certificate chain is empty")]
    EmptyCertificateChain,
    #[error("invalid authority certificate: {0}")]
    InvalidCertificate(#[from] webpki::Error),
}

impl RemoteAuthority {
    /// Retains peer material without authenticating it.
    ///
    /// The handshake must authenticate the name and certificate chain before
    /// delivering this identity to the application. OCSP is retained as evidence;
    /// neither this constructor nor message verification validates it.
    pub fn new(
        provider: &CryptoProvider,
        name: &str,
        cert: Vec<CertificateDer<'static>>,
        ocsp: Option<Bytes>,
    ) -> Self {
        Self {
            name: name.to_owned(),
            cert,
            ocsp,
            algorithms: provider.signature_verification_algorithms,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert
    }

    pub fn ocsp(&self) -> Option<&[u8]> {
        self.ocsp.as_deref()
    }

    /// Verifies an unhashed message with the leaf certificate's public key.
    ///
    /// Returns `false` for a signature or public key that does not match, and an
    /// error for an unsupported scheme or an absent/malformed leaf certificate.
    /// This does not validate the peer's name, certificate chain, expiry or OCSP.
    pub fn verify(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, VerifyError> {
        let algorithm = self
            .algorithms
            .mapping
            .iter()
            .find(|(supported, _)| *supported == scheme)
            // Like TLS 1.3, use the first mapping for the selected scheme.
            .and_then(|(_, algorithms)| algorithms.first())
            .ok_or(VerifyError::UnsupportedScheme { scheme })?;
        let leaf = self
            .cert
            .first()
            .ok_or(VerifyError::EmptyCertificateChain)?;
        let certificate = webpki::EndEntityCert::try_from(leaf)?;
        Ok(certificate
            .verify_signature(*algorithm, message, signature)
            .is_ok())
    }
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::{PrivatePkcs8KeyDer, pem::PemObject};

    use super::*;

    const CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
    const KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");
    const OTHER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/client.cert");

    fn certificate(pem: &[u8]) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem).unwrap()
    }

    fn endpoint(certs: Vec<CertificateDer<'static>>) -> Arc<Endpoint> {
        Endpoint::new(
            &rustls::crypto::ring::default_provider(),
            "a different name",
            certs,
            PrivateKeyDer::from_pem_slice(KEY).unwrap(),
            Some(Bytes::from_static(b"ocsp")),
        )
        .unwrap()
    }

    fn signing_authorities() -> (LocalAuthority, RemoteAuthority, SignatureScheme) {
        let provider = rustls::crypto::ring::default_provider();
        let endpoint = endpoint(vec![certificate(CERT)]);
        let scheme = endpoint
            .key
            .choose_scheme(
                &provider
                    .signature_verification_algorithms
                    .supported_schemes(),
            )
            .unwrap()
            .scheme();
        let remote = RemoteAuthority::new(
            &provider,
            endpoint.name(),
            endpoint.cert_chain().to_vec(),
            None,
        );
        (LocalAuthority::new(endpoint), remote, scheme)
    }

    #[test]
    fn construction_defers_certificate_checks() {
        // Even invalid names, malformed/empty chains and mismatched keys are
        // preserved for the handshake layer to validate.
        for certs in [
            vec![],
            vec![CertificateDer::from(vec![0])],
            vec![certificate(OTHER_CERT)],
        ] {
            let endpoint = endpoint(certs);
            assert_eq!(endpoint.name(), "a different name");
            assert_eq!(endpoint.ocsp(), Some(b"ocsp".as_slice()));
        }
    }

    #[test]
    fn construction_rejects_unloadable_private_key() {
        let result = Endpoint::new(
            &rustls::crypto::ring::default_provider(),
            "localhost",
            vec![certificate(CERT)],
            PrivatePkcs8KeyDer::from(vec![0]).into(),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn owned_conversion_preserves_material_and_signing_key() {
        let endpoint = Arc::try_unwrap(endpoint(vec![certificate(CERT)])).unwrap();
        let key = endpoint.key.clone();
        let cert = endpoint.cert.as_ptr();
        let name = endpoint.name.as_ptr();
        let ocsp = endpoint.ocsp.as_ref().unwrap().as_ptr();

        let local = LocalAuthority::from(endpoint);
        assert!(Arc::ptr_eq(&local.key, &key));
        assert_eq!(local.cert.as_ptr(), cert);
        assert_eq!(local.name.as_ptr(), name);
        assert_eq!(local.ocsp.as_ref().unwrap().as_ptr(), ocsp);

        let endpoint = Endpoint::from(local);
        assert!(Arc::ptr_eq(&endpoint.key, &key));
        assert_eq!(endpoint.cert.as_ptr(), cert);
        assert_eq!(endpoint.name.as_ptr(), name);
        assert_eq!(endpoint.ocsp.as_ref().unwrap().as_ptr(), ocsp);

        let provider = rustls::crypto::ring::default_provider();
        let scheme = key
            .choose_scheme(
                &provider
                    .signature_verification_algorithms
                    .supported_schemes(),
            )
            .unwrap()
            .scheme();
        let remote = RemoteAuthority::new(
            &provider,
            endpoint.name(),
            endpoint.cert_chain().to_vec(),
            None,
        );
        let local = LocalAuthority::from(endpoint);
        let signature = local.sign(scheme, b"after conversion").unwrap();
        assert!(
            remote
                .verify(scheme, b"after conversion", &signature)
                .unwrap()
        );
    }

    #[test]
    fn arc_conversion_moves_unique_material_and_preserves_shared_endpoint() {
        let unique = endpoint(vec![certificate(CERT)]);
        let cert = unique.cert.as_ptr();
        let local = LocalAuthority::from(unique);
        assert_eq!(local.cert.as_ptr(), cert);

        let shared = endpoint(vec![certificate(CERT)]);
        let local = LocalAuthority::new(shared.clone());
        assert!(Arc::ptr_eq(&local.key, &shared.key));
        assert_eq!(local.name(), shared.name());
        assert_eq!(local.cert_chain(), shared.cert_chain());
        assert_eq!(local.ocsp(), shared.ocsp());
        drop(shared);

        let restored = Endpoint::from(local);
        assert_eq!(restored.cert_chain(), &[certificate(CERT)]);
        assert_eq!(restored.ocsp(), Some(b"ocsp".as_slice()));
    }

    #[test]
    fn signature_verification_rejects_tampering_and_wrong_public_key() {
        let (local, remote, scheme) = signing_authorities();
        let message = b"application message";
        let signature = local.sign(scheme, message).unwrap();
        assert!(remote.verify(scheme, message, &signature).unwrap());
        assert!(
            !remote
                .verify(scheme, b"changed message", &signature)
                .unwrap()
        );

        let mut changed = signature.clone();
        changed[0] ^= 1;
        assert!(!remote.verify(scheme, message, &changed).unwrap());
        assert!(!remote.verify(scheme, message, &[]).unwrap());

        let other = RemoteAuthority::new(
            &rustls::crypto::ring::default_provider(),
            "localhost",
            vec![certificate(OTHER_CERT)],
            None,
        );
        assert!(!other.verify(scheme, message, &signature).unwrap());
    }

    #[test]
    fn unsupported_signature_scheme_is_an_error() {
        let (local, remote, _) = signing_authorities();
        let scheme = SignatureScheme::Unknown(0xffff);
        assert!(matches!(
            local.sign(scheme, b"message"),
            Err(SignError::UnsupportedScheme { .. })
        ));
        assert!(matches!(
            remote.verify(scheme, b"message", b"signature"),
            Err(VerifyError::UnsupportedScheme { .. })
        ));
    }

    #[test]
    fn verification_reports_missing_or_malformed_certificate() {
        let (local, _, scheme) = signing_authorities();
        let signature = local.sign(scheme, b"message").unwrap();
        let provider = rustls::crypto::ring::default_provider();
        let empty = RemoteAuthority::new(&provider, "localhost", vec![], None);
        assert!(matches!(
            empty.verify(scheme, b"message", &signature),
            Err(VerifyError::EmptyCertificateChain)
        ));
        let malformed = RemoteAuthority::new(
            &provider,
            "localhost",
            vec![CertificateDer::from(vec![0])],
            None,
        );
        assert!(matches!(
            malformed.verify(scheme, b"message", &signature),
            Err(VerifyError::InvalidCertificate(_))
        ));
    }
}
