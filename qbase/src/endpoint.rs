use std::{fmt, sync::Arc};

use qtls::{CertificateDer, PrivateKeyDer, SigningKey};

/// A local name and immutable certificate/key/OCSP material for this process.
#[derive(Clone)]
pub struct Endpoint {
    name: String,
    cert: Vec<CertificateDer<'static>>,
    key: Arc<dyn SigningKey>,
    ocsp: Vec<u8>,
}

#[derive(Debug)]
pub struct Anonymous;

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Endpoint {
    /// Loads the private key with the default qtls crypto provider.
    ///
    /// Names and certificate material are retained as supplied. Certificate
    /// parsing, key matching, validity and trust checks belong to the handshake.
    /// An unusable private key is returned immediately as an error.
    pub fn new(
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
        let signing_key = qtls::default_provider()
            .key_provider
            .load_private_key(key)?;
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
