pub use rustls::CertificateError;
use thiserror::Error;

use crate::{CryptoLevel, SignatureScheme};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsAlert {
    description: u8,
}

impl TlsAlert {
    pub fn description(self) -> u8 {
        self.description
    }

    pub(crate) fn new(description: rustls::AlertDescription) -> Self {
        Self {
            description: description.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum TlsConfigError {
    #[error("TLS configuration is invalid: {0}")]
    Invalid(String),
    #[error("the selected crypto provider has no QUIC-capable TLS 1.3 cipher suite")]
    MissingQuicSuite,
    #[error("FIPS mode requires a FIPS crypto provider and TLS configuration")]
    FipsRequired,
}

#[derive(Debug, Error)]
pub enum InvalidLocalAuthority {
    #[error("authority name is not a valid DNS name")]
    InvalidName,
    #[error("authority certificate chain is empty")]
    EmptyCertificateChain,
    #[error("authority leaf certificate is invalid: {0}")]
    InvalidCertificate(String),
    #[error("authority private key is invalid or does not match its certificate: {0}")]
    InvalidPrivateKey(String),
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid authentication tag buffer length: expected {expected}, got {actual}")]
    InvalidTagLength { expected: usize, actual: usize },
    #[error("QUIC key operation failed")]
    OperationFailed,
    #[error("key generation overflow")]
    GenerationOverflow,
}

#[derive(Debug, Error)]
pub enum PeerTlsError {
    #[error("received CRYPTO data at {actual:?}; expected {expected:?}")]
    WrongCryptoLevel {
        expected: CryptoLevel,
        actual: CryptoLevel,
    },
    #[error("TLS peer exceeded {resource} limit of {limit} bytes")]
    ResourceLimit {
        resource: &'static str,
        limit: usize,
    },
    #[error("TLS peer error: {0}")]
    Protocol(String),
}

#[derive(Debug, Error)]
pub enum TlsInvariantError {
    #[error("TLS backend did not provide {0}")]
    Missing(&'static str),
    #[error("TLS backend produced an event after reaching a terminal state")]
    EventAfterTerminal,
}

#[derive(Debug, Error)]
pub enum TlsError {
    #[error(transparent)]
    Config(#[from] TlsConfigError),
    #[error("TLS alert {0:?}")]
    Alert(TlsAlert),
    #[error(transparent)]
    Peer(#[from] PeerTlsError),
    #[error(transparent)]
    Invariant(#[from] TlsInvariantError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[derive(Debug, Error)]
#[error("TLS handshake is not complete")]
pub struct HandshakeNotComplete;

#[derive(Debug, Error)]
pub enum ExporterError {
    #[error("TLS exporter failed")]
    Failed,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("resumption store failed: {0}")]
    Backend(String),
}

#[derive(Debug, Error)]
pub enum SignError {
    #[error("signature scheme {scheme:?} is not supported by this authority")]
    UnsupportedScheme { scheme: SignatureScheme },
    #[error("signing failed")]
    SigningFailed,
}
