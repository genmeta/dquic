//! Connection-independent TLS 1.3 support for QUIC.
//!
//! `qtls` owns no socket, QUIC connection, CRYPTO stream, runtime, or waker.
//! Callers feed contiguous CRYPTO bytes and pull typed events.

mod authority;
mod config;
mod error;
mod handshake;
pub mod keys;
mod resumption;

pub use authority::{
    ClientCertificateRequest, LocalAuthority, RemoteAuthority, ResolveClientAuthority,
    ResolveServerAuthority, ServerCredentialRequest, SignError, VerifyIdentity,
};
pub use config::{
    ClientStart, ClientTlsConfig, ClientTlsEndpoint, ServerTlsConfig, ServerTlsEndpoint, TlsLimits,
};
pub use error::{
    CertificateError, CryptoError, ExporterError, HandshakeNotComplete, InvalidLocalAuthority,
    PeerTlsError, StoreError, TlsAlert, TlsConfigError, TlsError, TlsInvariantError,
};
pub use handshake::{
    CryptoLevel, EstablishedTls, HandshakeSummary, InstalledKeys, TlsEvent, TlsHandshake,
};
pub use keys::{
    BidirectionalKeys, DerivedPacketKey, DirectionalKeys, HeaderProtectionKey, OneRttKeyMaterial,
    OpeningKeyCursor, PacketKey, SealingKeyCursor,
};
pub use resumption::{
    ClientResumptionConfig, MemoryResumptionStore, ResumptionKey, ResumptionStore,
    ServerResumptionConfig, SessionSealKeyRing, StoredSession, TicketKeyRing,
};
pub use rustls::{
    SignatureScheme,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
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
