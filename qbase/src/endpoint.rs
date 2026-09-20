use std::{fmt, sync::Arc};

use qtls::{CertificateDer, CryptoProvider, PrivateKeyDer, SigningKey};

/// A local name and immutable certificate/key/OCSP material for this process.
#[derive(Clone)]
pub struct Endpoint {
    name: String,
    cert: Vec<CertificateDer<'static>>,
    key: Arc<dyn SigningKey>,
    ocsp: Vec<u8>,
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
        ocsp: Vec<u8>,
    ) -> Result<Arc<Self>, qtls::RustlsError> {
        if ocsp.is_empty() {
            return Err(qtls::RustlsError::General(
                "endpoint OCSP staple is empty".into(),
            ));
        }
        let signing_key = provider.key_provider.load_private_key(key)?;
        Ok(Arc::new(Self {
            name: name.to_owned(),
            cert: certs,
            key: signing_key,
            ocsp,
        }))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert
    }

    pub fn signing_key(&self) -> &Arc<dyn SigningKey> {
        &self.key
    }

    pub fn ocsp(&self) -> &[u8] {
        &self.ocsp
    }
}

#[cfg(test)]
mod tests {
    use qtls::{PrivateKeyDer, default_provider};
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};

    use super::*;

    const CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
    const KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");
    const OTHER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/client.cert");

    fn certificate(pem: &[u8]) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem).unwrap()
    }

    fn endpoint(certs: Vec<CertificateDer<'static>>) -> Arc<Endpoint> {
        Endpoint::new(
            &default_provider(),
            "a different name",
            certs,
            PrivateKeyDer::from_pem_slice(KEY).unwrap(),
            b"ocsp".to_vec(),
        )
        .unwrap()
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
            assert_eq!(endpoint.ocsp(), b"ocsp");
        }
    }

    #[test]
    fn construction_rejects_unloadable_private_key() {
        let result = Endpoint::new(
            &default_provider(),
            "localhost",
            vec![certificate(CERT)],
            PrivatePkcs8KeyDer::from(vec![0]).into(),
            b"ocsp".to_vec(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn construction_rejects_empty_ocsp() {
        let result = Endpoint::new(
            &default_provider(),
            "localhost",
            vec![certificate(CERT)],
            PrivateKeyDer::from_pem_slice(KEY).unwrap(),
            Vec::new(),
        );
        assert!(result.is_err());
    }
}
