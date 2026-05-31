use std::sync::Arc;

use derive_more::AsRef;
use rustls::{
    SignatureScheme,
    pki_types::{CertificateDer, SubjectPublicKeyInfoDer},
    sign::{CertifiedKey, SigningKey},
};
use thiserror::Error;
use x509_parser::prelude::FromDer;

#[derive(Debug, Clone, AsRef)]
pub struct LocalAuthority {
    name: Arc<str>,
    certified_key: Arc<CertifiedKey>,
}

#[derive(Debug, Error)]
pub enum SignError {
    #[error("Unsupported signature scheme {scheme:?}")]
    UnsupportedScheme { scheme: SignatureScheme },
    #[error(transparent)]
    Crypto {
        #[from]
        source: rustls::Error,
    },
}

impl LocalAuthority {
    pub fn new(name: Arc<str>, certified_key: Arc<CertifiedKey>) -> Self {
        Self {
            name,
            certified_key,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.certified_key.cert
    }

    pub fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        public_key(self.cert_chain())
    }

    pub fn sign_algorithm(&self) -> rustls::SignatureAlgorithm {
        self.certified_key.key.algorithm()
    }

    pub fn sign(&self, scheme: SignatureScheme, data: &[u8]) -> Result<Vec<u8>, SignError> {
        sign(self.certified_key.key.as_ref(), scheme, data)
    }

    pub fn verify(
        &self,
        scheme: SignatureScheme,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, VerifyError> {
        verify(self.public_key(), scheme, data, signature)
    }
}

#[derive(Debug, Clone, AsRef)]
pub struct RemoteAuthority {
    name: Arc<str>,
    cert: Arc<[CertificateDer<'static>]>,
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("Unsupported signature scheme {scheme:?}")]
    UnsupportedScheme { scheme: SignatureScheme },
}

impl RemoteAuthority {
    pub fn new(name: Arc<str>, cert: Arc<[CertificateDer<'static>]>) -> Self {
        Self { name, cert }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert
    }

    pub fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        public_key(self.cert_chain())
    }

    pub fn verify(
        &self,
        scheme: SignatureScheme,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, VerifyError> {
        verify(self.public_key(), scheme, data, signature)
    }
}

fn public_key<'d>(cert_chain: &'d [CertificateDer<'d>]) -> SubjectPublicKeyInfoDer<'d> {
    use x509_parser::prelude::*;

    match x509_parser::certificate::X509Certificate::from_der(&cert_chain[0]) {
        Ok((_remain, certificate)) => {
            let spki = certificate.public_key().raw;
            spki.to_owned().into()
        }
        Err(_error) if cert_chain.len() == 1 => cert_chain[0].as_ref().into(),
        Err(_error) => unreachable!("rustls returned an invalid peer_certificates."),
    }
}

fn sign(
    key: &(impl SigningKey + ?Sized),
    scheme: SignatureScheme,
    data: &[u8],
) -> Result<Vec<u8>, SignError> {
    // FIXME: same as load spki then sign with ring?
    let signer = key
        .choose_scheme(&[scheme])
        .ok_or(SignError::UnsupportedScheme { scheme })?;
    Ok(signer.sign(data)?)
}

fn verify(
    spki: SubjectPublicKeyInfoDer,
    scheme: SignatureScheme,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    let algorithm: &'static dyn ring::signature::VerificationAlgorithm = match scheme {
        SignatureScheme::ECDSA_NISTP384_SHA384 => &ring::signature::ECDSA_P384_SHA384_ASN1,
        SignatureScheme::ECDSA_NISTP256_SHA256 => &ring::signature::ECDSA_P256_SHA256_ASN1,
        SignatureScheme::ED25519 => &ring::signature::ED25519,
        SignatureScheme::RSA_PKCS1_SHA256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384 => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512 => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
        SignatureScheme::RSA_PSS_SHA256 => &ring::signature::RSA_PSS_2048_8192_SHA256,
        SignatureScheme::RSA_PSS_SHA384 => &ring::signature::RSA_PSS_2048_8192_SHA384,
        SignatureScheme::RSA_PSS_SHA512 => &ring::signature::RSA_PSS_2048_8192_SHA512,
        _ => return Err(VerifyError::UnsupportedScheme { scheme }),
    };

    let public_key = match x509_parser::x509::SubjectPublicKeyInfo::from_der(&spki) {
        Ok((_remain, spki)) => spki.subject_public_key,
        Err(_error) => unreachable!("rustls returned an invalid peer_certificates."),
    };

    Ok(
        ring::signature::UnparsedPublicKey::new(algorithm, public_key)
            .verify(data, signature)
            .is_ok(),
    )
}
