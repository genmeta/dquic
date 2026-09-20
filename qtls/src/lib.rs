//! Connection-independent TLS 1.3 support for QUIC.
//!
//! `qtls` owns no socket, QUIC connection, CRYPTO stream, runtime, or waker.
//! Callers feed contiguous CRYPTO bytes and pull typed events.

mod authority;
mod config;
mod error;
mod handshake;
pub mod incoming;
pub mod keys;
mod ocsp;
mod resumption;
mod root;

pub use authority::{LocalAuthority, RemoteAuthority, SignError};
pub use config::{ClientStart, ClientTlsConfig, ServerTlsConfig, TlsClient, TlsLimits, TlsServer};
pub use error::{
    CertificateError, CryptoError, ExporterError, HandshakeNotComplete, InvalidLocalAuthority,
    PeerTlsError, StoreError, TlsAlert, TlsConfigError, TlsError, TlsInvariantError,
};
pub use handshake::{
    CryptoLevel, EstablishedTls, HandshakeSummary, InstalledKeys, TlsEvent, TlsHandshake,
};
pub use keys::{
    BidirectionalKeys, DirectionalKeys, HeaderProtectionKey, OneRttKeyMaterial, PacketKey,
    PacketKeys, Secrets,
};
pub use resumption::{
    ClientResumptionConfig, MemoryResumptionStore, ResumptionKey, ResumptionStore,
    ServerResumptionConfig, SessionSealKeyRing, StoredSession, TicketKeyRing,
};
pub use root::RootCerts;
/// Default provider for the enabled qtls backend; AWS-LC takes precedence over ring.
#[cfg(feature = "aws-lc-rs")]
pub use rustls::crypto::aws_lc_rs::default_provider;
/// Default provider when only the ring backend is enabled.
#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
pub use rustls::crypto::ring::default_provider;
pub use rustls::{
    Error as RustlsError, SignatureScheme,
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    sign::SigningKey,
};

/// QUIC versions whose TLS labels and Initial salts are supported by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum QuicVersion {
    V1,
    V2,
}

impl From<QuicVersion> for rustls::quic::Version {
    fn from(value: QuicVersion) -> Self {
        match value {
            QuicVersion::V1 => Self::V1,
            QuicVersion::V2 => Self::V2,
        }
    }
}
