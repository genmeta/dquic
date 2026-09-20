use std::sync::Arc;

use rustls::{
    SignatureScheme,
    pki_types::{CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer},
    sign::{CertifiedKey, SigningKey},
};
use x509_parser::prelude::FromDer;

use crate::InvalidLocalAuthority;
pub use crate::error::SignError;

#[derive(Clone, Debug)]
pub struct LocalAuthority {
    name: Arc<str>,
    certificates: Arc<[CertificateDer<'static>]>,
    public_key: SubjectPublicKeyInfoDer<'static>,
    ocsp: Vec<u8>,
    signing_key: Arc<dyn SigningKey>,
}

impl LocalAuthority {
    /// Builds handshake credentials from an already loaded signing capability.
    /// Certificate parsing and key matching happen here, without loading a
    /// private key a second time. Name/trust/validity verification of the peer
    /// remains the responsibility of the configured identity verifier.
    pub fn from_signing_key(
        name: Arc<str>,
        certificates: Vec<CertificateDer<'static>>,
        signing_key: Arc<dyn SigningKey>,
        ocsp: Vec<u8>,
    ) -> Result<Self, InvalidLocalAuthority> {
        let public_key = extract_public_key(&certificates)?;
        let certified_key = CertifiedKey::new(certificates, signing_key);
        match certified_key.keys_match() {
            Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {}
            Err(error) => return Err(InvalidLocalAuthority::InvalidPrivateKey(error.to_string())),
        }
        Self::from_certified_key(name, certified_key, public_key, ocsp)
    }

    pub fn new(
        provider: &rustls::crypto::CryptoProvider,
        name: Arc<str>,
        certificates: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        ocsp: Vec<u8>,
    ) -> Result<Self, InvalidLocalAuthority> {
        let public_key = extract_public_key(&certificates)?;
        let certified_key = CertifiedKey::from_der(certificates, private_key, provider)
            .map_err(|error| InvalidLocalAuthority::InvalidPrivateKey(error.to_string()))?;

        Self::from_certified_key(name, certified_key, public_key, ocsp)
    }

    fn from_certified_key(
        name: Arc<str>,
        mut certified_key: CertifiedKey,
        public_key: SubjectPublicKeyInfoDer<'static>,
        ocsp: Vec<u8>,
    ) -> Result<Self, InvalidLocalAuthority> {
        rustls::pki_types::DnsName::try_from(name.as_ref())
            .map_err(|_| InvalidLocalAuthority::InvalidName)?;
        if ocsp.is_empty() {
            return Err(InvalidLocalAuthority::EmptyOcsp);
        }

        certified_key.ocsp = Some(ocsp.clone());
        Ok(Self {
            name,
            certificates: certified_key.cert.into(),
            public_key,
            ocsp,
            signing_key: certified_key.key,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn certificates(&self) -> &[CertificateDer<'static>] {
        &self.certificates
    }

    pub fn public_key(&self) -> &SubjectPublicKeyInfoDer<'static> {
        &self.public_key
    }

    pub fn ocsp(&self) -> &[u8] {
        &self.ocsp
    }

    /// Signs an unhashed message using the hash and encoding implied by `scheme`.
    pub fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, SignError> {
        self.signing_key
            .choose_scheme(&[scheme])
            .ok_or(SignError::UnsupportedScheme { scheme })?
            .sign(message)
            .map_err(|_| SignError::SigningFailed)
    }

    pub(crate) fn certified_key(&self) -> Arc<CertifiedKey> {
        Arc::new(CertifiedKey {
            cert: self.certificates.to_vec(),
            key: self.signing_key.clone(),
            ocsp: Some(self.ocsp.to_vec()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct RemoteAuthority {
    name: Arc<str>,
    certificates: Arc<[CertificateDer<'static>]>,
    public_key: SubjectPublicKeyInfoDer<'static>,
}

impl RemoteAuthority {
    pub(crate) fn new(
        name: Arc<str>,
        certificates: &[CertificateDer<'_>],
    ) -> Result<Self, InvalidLocalAuthority> {
        rustls::pki_types::DnsName::try_from(name.as_ref())
            .map_err(|_| InvalidLocalAuthority::InvalidName)?;
        let certificates = certificates
            .iter()
            .map(CertificateDer::clone)
            .map(CertificateDer::into_owned)
            .collect::<Vec<_>>();
        let public_key = extract_public_key(&certificates)?;
        Ok(Self {
            name,
            certificates: certificates.into(),
            public_key,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn certificates(&self) -> &[CertificateDer<'static>] {
        &self.certificates
    }

    pub fn public_key(&self) -> &SubjectPublicKeyInfoDer<'static> {
        &self.public_key
    }
}

fn extract_public_key(
    certificates: &[CertificateDer<'_>],
) -> Result<SubjectPublicKeyInfoDer<'static>, InvalidLocalAuthority> {
    let leaf = certificates
        .first()
        .ok_or(InvalidLocalAuthority::EmptyCertificateChain)?;
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(leaf.as_ref())
        .map_err(|error| InvalidLocalAuthority::InvalidCertificate(error.to_string()))?;
    Ok(certificate.public_key().raw.to_vec().into())
}
