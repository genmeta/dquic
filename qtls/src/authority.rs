use std::{fmt::Debug, sync::Arc};

use rustls::{
    DistinguishedName, SignatureScheme,
    pki_types::{CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer, UnixTime},
    sign::{CertifiedKey, SigningKey},
};
use x509_parser::prelude::FromDer;

pub use crate::error::SignError;
use crate::{CertificateError, InvalidLocalAuthority};

#[derive(Clone, Debug)]
pub struct LocalAuthority {
    name: Arc<str>,
    certificates: Arc<[CertificateDer<'static>]>,
    public_key: SubjectPublicKeyInfoDer<'static>,
    ocsp: Option<Arc<[u8]>>,
    signing_key: Arc<dyn SigningKey>,
}

impl LocalAuthority {
    pub fn new(
        provider: &rustls::crypto::CryptoProvider,
        name: Arc<str>,
        certificates: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        ocsp: Option<Vec<u8>>,
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
        ocsp: Option<Vec<u8>>,
    ) -> Result<Self, InvalidLocalAuthority> {
        rustls::pki_types::DnsName::try_from(name.as_ref())
            .map_err(|_| InvalidLocalAuthority::InvalidName)?;

        certified_key.ocsp = ocsp.clone();
        Ok(Self {
            name,
            certificates: certified_key.cert.into(),
            public_key,
            ocsp: ocsp.map(Arc::from),
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

    pub fn ocsp(&self) -> Option<&[u8]> {
        self.ocsp.as_deref()
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
            ocsp: self.ocsp.as_deref().map(<[u8]>::to_vec),
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

#[derive(Clone, Copy, Debug)]
pub struct ServerCredentialRequest<'a> {
    pub server_name: Option<&'a str>,
    pub signature_schemes: &'a [SignatureScheme],
    pub alpn: &'a [&'a [u8]],
}

#[derive(Clone, Copy, Debug)]
pub struct ClientCertificateRequest<'a> {
    pub root_hint_subjects: &'a [&'a [u8]],
    pub signature_schemes: &'a [SignatureScheme],
}

pub trait ResolveServerAuthority: Debug + Send + Sync {
    fn resolve(&self, hello: ServerCredentialRequest<'_>) -> Option<LocalAuthority>;
}

pub trait ResolveClientAuthority: Debug + Send + Sync {
    fn resolve(&self, request: ClientCertificateRequest<'_>) -> Option<LocalAuthority>;

    fn has_authority(&self) -> bool {
        true
    }
}

pub trait VerifyIdentity: Debug + Send + Sync {
    fn verify(
        &self,
        expected: Option<&str>,
        certificates: &[CertificateDer<'_>],
        ocsp: Option<&[u8]>,
        now: UnixTime,
    ) -> Result<Option<Arc<str>>, CertificateError>;

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
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
