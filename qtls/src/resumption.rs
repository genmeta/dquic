use std::{
    collections::VecDeque,
    fmt::{self, Debug},
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs as record_crypto;
use bytes::Bytes;
#[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
use ring as record_crypto;
use rustls::{
    NamedGroup,
    client::{ClientSessionStore, Tls13ClientSessionValue},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::{ProducesTickets, StoresServerSessions},
};
use x509_parser::prelude::FromDer;
use zeroize::Zeroizing;

use crate::{
    LocalAuthority, RemoteAuthority, StoreError, TlsLimits,
    handshake::{ClientResolver, PeerState, ServerVerifier},
};

const RECORD_MAGIC: &[u8; 4] = b"QTS1";
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
const RECORD_SCHEMA: u8 = 1;
const NONCE_LEN: usize = 12;
const RECORD_OVERHEAD: usize = RECORD_MAGIC.len() + 1 + 4 + NONCE_LEN + 16;
const STATEFUL_TICKET_LIFETIME_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ResumptionKey(Bytes);

impl ResumptionKey {
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct StoredSession {
    pub not_after: UnixTime,
    pub sealed: Bytes,
}

pub trait ResumptionStore: Debug + Send + Sync {
    fn put(&self, key: ResumptionKey, session: StoredSession) -> Result<(), StoreError>;

    /// Atomically returns and removes the newest unexpired session for `key`.
    fn take(&self, key: &ResumptionKey) -> Result<Option<StoredSession>, StoreError>;
}

#[derive(Debug)]
pub struct MemoryResumptionStore {
    capacity: usize,
    entries: Mutex<VecDeque<(ResumptionKey, StoredSession)>>,
}

impl MemoryResumptionStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::new()),
        }
    }
}

impl ResumptionStore for MemoryResumptionStore {
    fn put(&self, key: ResumptionKey, session: StoredSession) -> Result<(), StoreError> {
        if self.capacity == 0 {
            return Ok(());
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| StoreError::Backend("memory store lock poisoned".into()))?;
        entries.push_back((key, session));
        while entries.len() > self.capacity {
            entries.pop_front();
        }
        Ok(())
    }

    fn take(&self, key: &ResumptionKey) -> Result<Option<StoredSession>, StoreError> {
        let now = UnixTime::now();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| StoreError::Backend("memory store lock poisoned".into()))?;
        while let Some(index) = entries
            .iter()
            .rposition(|(stored_key, _)| stored_key == key)
        {
            let Some((_, session)) = entries.remove(index) else {
                return Ok(None);
            };
            if session.not_after > now {
                return Ok(Some(session));
            }
        }
        Ok(None)
    }
}

/// Protects session records before they are handed to a [`ResumptionStore`].
///
/// The current key seals new records. Keys added with [`Self::with_previous`]
/// only open records, which permits non-disruptive key rotation.
pub struct SessionSealKeyRing {
    current: RecordKey,
    previous: Vec<RecordKey>,
}

impl SessionSealKeyRing {
    pub fn new(key_id: u32, key: [u8; 32]) -> Self {
        Self {
            current: RecordKey::new(key_id, key),
            previous: Vec::new(),
        }
    }

    pub fn with_previous(mut self, key_id: u32, key: [u8; 32]) -> Self {
        if key_id != self.current.id && !self.previous.iter().any(|item| item.id == key_id) {
            self.previous.push(RecordKey::new(key_id, key));
        }
        self
    }

    fn seal(
        &self,
        store_key: &ResumptionKey,
        not_after: UnixTime,
        plaintext: &mut Vec<u8>,
    ) -> Option<Bytes> {
        #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
        {
            use record_crypto::rand::SecureRandom;

            let mut nonce = [0u8; NONCE_LEN];
            record_crypto::rand::SystemRandom::new()
                .fill(&mut nonce)
                .ok()?;
            let mut header = Vec::with_capacity(RECORD_MAGIC.len() + 1 + 4 + NONCE_LEN);
            header.extend_from_slice(RECORD_MAGIC);
            header.push(RECORD_SCHEMA);
            header.extend_from_slice(&self.current.id.to_be_bytes());
            header.extend_from_slice(&nonce);
            let aad = record_aad(&header, store_key, not_after);
            self.current
                .key
                .seal_in_place_append_tag(
                    record_crypto::aead::Nonce::assume_unique_for_key(nonce),
                    record_crypto::aead::Aad::from(aad.as_slice()),
                    plaintext,
                )
                .ok()?;
            header.append(plaintext);
            Some(header.into())
        }
        #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
        {
            let _ = (store_key, not_after, plaintext);
            None
        }
    }

    fn open(
        &self,
        store_key: &ResumptionKey,
        session: &StoredSession,
    ) -> Option<Zeroizing<Vec<u8>>> {
        #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
        {
            let header_len = RECORD_MAGIC.len() + 1 + 4 + NONCE_LEN;
            let header = session.sealed.get(..header_len)?;
            if header.get(..4)? != RECORD_MAGIC || *header.get(4)? != RECORD_SCHEMA {
                return None;
            }
            let id = u32::from_be_bytes(header.get(5..9)?.try_into().ok()?);
            let nonce: [u8; NONCE_LEN] = header.get(9..header_len)?.try_into().ok()?;
            let record_key = std::iter::once(&self.current)
                .chain(self.previous.iter())
                .find(|item| item.id == id)?;
            let aad = record_aad(header, store_key, session.not_after);
            let mut ciphertext = Zeroizing::new(session.sealed.get(header_len..)?.to_vec());
            let plaintext = record_key
                .key
                .open_in_place(
                    record_crypto::aead::Nonce::assume_unique_for_key(nonce),
                    record_crypto::aead::Aad::from(aad.as_slice()),
                    &mut ciphertext,
                )
                .ok()?;
            let plaintext_len = plaintext.len();
            ciphertext.truncate(plaintext_len);
            Some(ciphertext)
        }
        #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
        {
            let _ = (store_key, session);
            None
        }
    }
}

impl fmt::Debug for SessionSealKeyRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionSealKeyRing")
            .field("current_key_id", &self.current.id)
            .field("previous_key_count", &self.previous.len())
            .finish()
    }
}

struct RecordKey {
    id: u32,
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    key: record_crypto::aead::LessSafeKey,
}

impl RecordKey {
    fn new(id: u32, key: [u8; 32]) -> Self {
        #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
        let key = record_crypto::aead::LessSafeKey::new(
            record_crypto::aead::UnboundKey::new(&record_crypto::aead::AES_256_GCM, &key)
                .expect("AES-256-GCM accepts a 32-byte key"),
        );
        #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
        let _ = key;
        Self {
            id,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            key,
        }
    }
}

#[derive(Debug)]
pub struct TicketKeyRing {
    pub(crate) ticketer: Arc<dyn rustls::server::ProducesTickets>,
}

impl TicketKeyRing {
    pub fn new(ticketer: Arc<dyn rustls::server::ProducesTickets>) -> Self {
        Self { ticketer }
    }
}

pub enum ClientResumptionConfig {
    Disabled,
    Enabled {
        namespace: Arc<str>,
        store: Arc<dyn ResumptionStore>,
        seal_keys: Arc<SessionSealKeyRing>,
    },
}

pub enum ServerResumptionConfig {
    Disabled,
    Stateful {
        namespace: Arc<str>,
        store: Arc<dyn ResumptionStore>,
        seal_keys: Arc<SessionSealKeyRing>,
    },
    Stateless {
        ticket_keys: Arc<TicketKeyRing>,
    },
}

pub(crate) struct ClientStoreAdapter {
    namespace: Arc<str>,
    version: crate::QuicVersion,
    provider: Arc<rustls::crypto::CryptoProvider>,
    store: Arc<dyn ResumptionStore>,
    seal_keys: Arc<SessionSealKeyRing>,
    verifier: Arc<ServerVerifier>,
    resolver: Arc<ClientResolver>,
    peer: PeerState,
    limits: TlsLimits,
    kx_hints: Mutex<Vec<(ServerName<'static>, NamedGroup)>>,
}

impl ClientStoreAdapter {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        namespace: Arc<str>,
        version: crate::QuicVersion,
        provider: Arc<rustls::crypto::CryptoProvider>,
        store: Arc<dyn ResumptionStore>,
        seal_keys: Arc<SessionSealKeyRing>,
        verifier: Arc<ServerVerifier>,
        resolver: Arc<ClientResolver>,
        peer: PeerState,
        limits: TlsLimits,
    ) -> Self {
        Self {
            namespace,
            version,
            provider,
            store,
            seal_keys,
            verifier,
            resolver,
            peer,
            limits,
            kx_hints: Mutex::new(Vec::new()),
        }
    }

    fn key(&self, server_name: &ServerName<'_>) -> Option<ResumptionKey> {
        let ServerName::DnsName(server_name) = server_name else {
            return None;
        };
        Some(derive_store_key(
            b"client",
            &self.namespace,
            self.version,
            server_name.as_ref().as_bytes(),
        ))
    }
}

impl fmt::Debug for ClientStoreAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientStoreAdapter")
            .finish_non_exhaustive()
    }
}

impl ClientSessionStore for ClientStoreAdapter {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        let Ok(mut hints) = self.kx_hints.lock() else {
            return;
        };
        if let Some((_, current)) = hints.iter_mut().find(|(name, _)| name == &server_name) {
            *current = group;
        } else {
            hints.push((server_name, group));
        }
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.kx_hints
            .lock()
            .ok()?
            .iter()
            .find(|(name, _)| name == server_name)
            .map(|(_, group)| *group)
    }

    fn set_tls12_session(
        &self,
        _server_name: ServerName<'static>,
        _value: rustls::client::Tls12ClientSessionValue,
    ) {
    }

    fn tls12_session(
        &self,
        _server_name: &ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        None
    }

    fn remove_tls12_session(&self, _server_name: &ServerName<'static>) {}

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        let Some(key) = self.key(&server_name) else {
            return;
        };
        let Some(context) = SessionContext::capture(&self.peer) else {
            return;
        };
        let Some(not_after) = context.not_after(value.resumption_expiry()) else {
            return;
        };
        let encoded = value.encode_resumption_state();
        let Some(mut plaintext) = context.encode(&encoded, self.limits.max_session_bytes) else {
            return;
        };
        let Some(sealed) = self.seal_keys.seal(&key, not_after, &mut plaintext) else {
            return;
        };
        let _ = self.store.put(key, StoredSession { not_after, sealed });
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        let key = self.key(server_name)?;
        let session = self.store.take(&key).ok()??;
        if session.not_after <= UnixTime::now()
            || session.sealed.len()
                > self
                    .limits
                    .max_session_bytes
                    .saturating_add(RECORD_OVERHEAD)
        {
            return None;
        }
        let plaintext = self.seal_keys.open(&key, &session)?;
        let (context, encoded) = SessionContext::decode(&plaintext, self.limits)?;
        context.restore_client(&self.peer, &self.resolver, &self.provider)?;
        Tls13ClientSessionValue::decode_resumption_state(
            encoded,
            &self.provider,
            self.verifier.clone(),
            self.resolver.clone(),
        )
        .ok()
    }
}

pub(crate) struct ServerStoreAdapter {
    namespace: Arc<str>,
    version: crate::QuicVersion,
    store: Arc<dyn ResumptionStore>,
    seal_keys: Arc<SessionSealKeyRing>,
    peer: PeerState,
    limits: TlsLimits,
}

pub(crate) struct StatelessTicketAdapter {
    inner: Arc<dyn ProducesTickets>,
    peer: PeerState,
    limits: TlsLimits,
}

impl StatelessTicketAdapter {
    pub(crate) fn new(inner: Arc<dyn ProducesTickets>, peer: PeerState, limits: TlsLimits) -> Self {
        Self {
            inner,
            peer,
            limits,
        }
    }
}

impl fmt::Debug for StatelessTicketAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatelessTicketAdapter")
            .finish_non_exhaustive()
    }
}

impl ProducesTickets for StatelessTicketAdapter {
    fn enabled(&self) -> bool {
        self.inner.enabled()
    }

    fn lifetime(&self) -> u32 {
        self.inner.lifetime()
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let context = SessionContext::capture(&self.peer)?;
        let ticket_not_after = UnixTime::since_unix_epoch(Duration::from_secs(
            UnixTime::now()
                .as_secs()
                .saturating_add(u64::from(self.inner.lifetime())),
        ));
        let not_after = context.not_after(ticket_not_after)?;
        let context = context.encode(plain, self.limits.max_session_bytes)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(8 + context.len()));
        plaintext.extend_from_slice(&not_after.as_secs().to_be_bytes());
        plaintext.extend_from_slice(&context);
        self.inner.encrypt(&plaintext)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        let plaintext = Zeroizing::new(self.inner.decrypt(cipher)?);
        let not_after = u64::from_be_bytes(plaintext.get(..8)?.try_into().ok()?);
        if not_after <= UnixTime::now().as_secs() {
            return None;
        }
        let (context, encoded) = SessionContext::decode(plaintext.get(8..)?, self.limits)?;
        context.restore_server(&self.peer)?;
        Some(encoded.to_vec())
    }
}

impl ServerStoreAdapter {
    pub(crate) fn new(
        namespace: Arc<str>,
        version: crate::QuicVersion,
        store: Arc<dyn ResumptionStore>,
        seal_keys: Arc<SessionSealKeyRing>,
        peer: PeerState,
        limits: TlsLimits,
    ) -> Self {
        Self {
            namespace,
            version,
            store,
            seal_keys,
            peer,
            limits,
        }
    }

    fn key(&self, ticket: &[u8]) -> ResumptionKey {
        derive_store_key(b"server", &self.namespace, self.version, ticket)
    }
}

impl fmt::Debug for ServerStoreAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerStoreAdapter")
            .finish_non_exhaustive()
    }
}

impl StoresServerSessions for ServerStoreAdapter {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        let store_key = self.key(&key);
        let Some(context) = SessionContext::capture(&self.peer) else {
            return false;
        };
        let ticket_not_after = UnixTime::since_unix_epoch(Duration::from_secs(
            UnixTime::now()
                .as_secs()
                .saturating_add(STATEFUL_TICKET_LIFETIME_SECS),
        ));
        let Some(not_after) = context.not_after(ticket_not_after) else {
            return false;
        };
        let Some(mut plaintext) = context.encode(&value, self.limits.max_session_bytes) else {
            return false;
        };
        let Some(sealed) = self.seal_keys.seal(&store_key, not_after, &mut plaintext) else {
            return false;
        };
        self.store
            .put(store_key, StoredSession { not_after, sealed })
            .is_ok()
    }

    fn get(&self, _key: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let store_key = self.key(key);
        let session = self.store.take(&store_key).ok()??;
        if session.not_after <= UnixTime::now()
            || session.sealed.len()
                > self
                    .limits
                    .max_session_bytes
                    .saturating_add(RECORD_OVERHEAD)
        {
            return None;
        }
        let plaintext = self.seal_keys.open(&store_key, &session)?;
        let (context, encoded) = SessionContext::decode(&plaintext, self.limits)?;
        context.restore_server(&self.peer)?;
        Some(encoded.to_vec())
    }

    fn can_cache(&self) -> bool {
        true
    }
}

#[derive(Clone)]
pub(crate) struct AuthorityProjection {
    name: Arc<str>,
    certificates: Vec<CertificateDer<'static>>,
}

impl AuthorityProjection {
    fn local(authority: &LocalAuthority) -> Self {
        Self {
            name: Arc::from(authority.name()),
            certificates: authority.certificates().to_vec(),
        }
    }

    fn remote(authority: &RemoteAuthority) -> Self {
        Self {
            name: Arc::from(authority.name()),
            certificates: authority.certificates().to_vec(),
        }
    }

    pub(crate) fn matches(&self, authority: &LocalAuthority) -> bool {
        self.name.as_ref() == authority.name()
            && self.certificates.as_slice() == authority.certificates()
    }

    fn into_remote(self) -> Option<RemoteAuthority> {
        RemoteAuthority::new(self.name, &self.certificates).ok()
    }
}

struct SessionContext {
    local: Option<AuthorityProjection>,
    remote: Option<AuthorityProjection>,
}

impl SessionContext {
    fn capture(peer: &PeerState) -> Option<Self> {
        let authorities = peer.authorities.lock().ok()?;
        let local = authorities
            .local
            .clone()
            .or_else(|| authorities.resumed_local.clone())
            .as_ref()
            .map(AuthorityProjection::local);
        let remote = authorities
            .remote
            .clone()
            .or_else(|| authorities.resumed_remote.clone())
            .as_ref()
            .map(AuthorityProjection::remote);
        Some(Self { local, remote })
    }

    fn not_after(&self, ticket_not_after: UnixTime) -> Option<UnixTime> {
        self.local.iter().chain(self.remote.iter()).try_fold(
            ticket_not_after,
            |not_after, authority| {
                let certificate = authority.certificates.first()?;
                let (_, certificate) =
                    x509_parser::certificate::X509Certificate::from_der(certificate.as_ref())
                        .ok()?;
                let timestamp: u64 = certificate
                    .validity()
                    .not_after
                    .timestamp()
                    .try_into()
                    .ok()?;
                Some(std::cmp::min(
                    not_after,
                    UnixTime::since_unix_epoch(Duration::from_secs(timestamp)),
                ))
            },
        )
    }

    fn restore_client(
        self,
        peer: &PeerState,
        resolver: &ClientResolver,
        provider: &rustls::crypto::CryptoProvider,
    ) -> Option<()> {
        let local = match self.local {
            Some(expected) => Some(resolver.rebind(&expected, provider)?),
            None => None,
        };
        let remote = self.remote?.into_remote()?;
        let mut authorities = peer.authorities.lock().ok()?;
        authorities.resumed_local = local;
        authorities.resumed_remote = Some(remote);
        Some(())
    }

    fn restore_server(self, peer: &PeerState) -> Option<()> {
        let mut authorities = peer.authorities.lock().ok()?;
        let local = authorities.local.clone();
        match (&self.local, &local) {
            (Some(expected), Some(current)) if expected.matches(current) => {}
            _ => return None,
        }
        let remote = match self.remote {
            Some(authority) => Some(authority.into_remote()?),
            None => None,
        };
        authorities.resumed_remote = remote;
        Some(())
    }

    fn encode(&self, tls_state: &[u8], limit: usize) -> Option<Vec<u8>> {
        let mut output = Vec::new();
        encode_projection(&mut output, self.local.as_ref())?;
        encode_projection(&mut output, self.remote.as_ref())?;
        put_bytes(&mut output, tls_state)?;
        (output.len() <= limit).then_some(output)
    }

    fn decode(encoded: &[u8], limits: TlsLimits) -> Option<(Self, &[u8])> {
        if encoded.len() > limits.max_session_bytes {
            return None;
        }
        let mut cursor = Cursor::new(encoded);
        let local = decode_projection(&mut cursor, limits)?;
        let remote = decode_projection(&mut cursor, limits)?;
        let tls_state = cursor.bytes()?;
        cursor
            .is_empty()
            .then_some((Self { local, remote }, tls_state))
    }
}

fn encode_projection(output: &mut Vec<u8>, authority: Option<&AuthorityProjection>) -> Option<()> {
    let Some(authority) = authority else {
        output.push(0);
        return Some(());
    };
    output.push(1);
    put_bytes(output, authority.name.as_bytes())?;
    let count: u16 = authority.certificates.len().try_into().ok()?;
    output.extend_from_slice(&count.to_be_bytes());
    for certificate in &authority.certificates {
        put_bytes(output, certificate.as_ref())?;
    }
    Some(())
}

fn decode_projection(
    cursor: &mut Cursor<'_>,
    limits: TlsLimits,
) -> Option<Option<AuthorityProjection>> {
    match cursor.u8()? {
        0 => Some(None),
        1 => {
            let name = std::str::from_utf8(cursor.bytes()?).ok()?;
            rustls::pki_types::DnsName::try_from(name).ok()?;
            let certificate_count = usize::from(cursor.u16()?);
            if certificate_count == 0 || certificate_count > limits.max_certificates {
                return None;
            }
            let mut total = 0usize;
            let mut certificates = Vec::with_capacity(certificate_count);
            for _ in 0..certificate_count {
                let certificate = cursor.bytes()?;
                total = total.checked_add(certificate.len())?;
                if total > limits.max_certificate_chain_bytes {
                    return None;
                }
                certificates.push(CertificateDer::from(certificate.to_vec()));
            }
            Some(Some(AuthorityProjection {
                name: Arc::from(name),
                certificates,
            }))
        }
        _ => None,
    }
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    let length: u32 = bytes.len().try_into().ok()?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Some(())
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn u8(&mut self) -> Option<u8> {
        let byte = *self.remaining.first()?;
        self.remaining = &self.remaining[1..];
        Some(byte)
    }

    fn u16(&mut self) -> Option<u16> {
        let value = u16::from_be_bytes(self.remaining.get(..2)?.try_into().ok()?);
        self.remaining = &self.remaining[2..];
        Some(value)
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let length = u32::from_be_bytes(self.remaining.get(..4)?.try_into().ok()?) as usize;
        let bytes = self.remaining.get(4..4usize.checked_add(length)?)?;
        self.remaining = self.remaining.get(4 + length..)?;
        Some(bytes)
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
fn record_aad(header: &[u8], store_key: &ResumptionKey, not_after: UnixTime) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + store_key.as_bytes().len() + 8);
    aad.extend_from_slice(header);
    aad.extend_from_slice(store_key.as_bytes());
    aad.extend_from_slice(&not_after.as_secs().to_be_bytes());
    aad
}

fn derive_store_key(
    role: &[u8],
    namespace: &str,
    version: crate::QuicVersion,
    context: &[u8],
) -> ResumptionKey {
    let mut input = Vec::with_capacity(role.len() + namespace.len() + context.len() + 24);
    input.extend_from_slice(b"qtls-resumption-v1\0");
    input.extend_from_slice(role);
    input.push(0);
    input.extend_from_slice(namespace.as_bytes());
    input.push(0);
    input.push(match version {
        crate::QuicVersion::V1 => 1,
        crate::QuicVersion::V2 => 2,
    });
    input.extend_from_slice(context);
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    return ResumptionKey::from_bytes(
        record_crypto::digest::digest(&record_crypto::digest::SHA256, &input)
            .as_ref()
            .to_vec(),
    );
    #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
    ResumptionKey::from_bytes(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_key_rotation_opens_records_from_the_previous_key() {
        let store_key = ResumptionKey::from_bytes(Bytes::from_static(b"store-key"));
        let not_after = UnixTime::since_unix_epoch(Duration::from_secs(u64::MAX));
        let old = SessionSealKeyRing::new(1, [0x11; 32]);
        let mut plaintext = b"ticket and psk".to_vec();
        let sealed = old.seal(&store_key, not_after, &mut plaintext).unwrap();
        let rotated = SessionSealKeyRing::new(2, [0x22; 32]).with_previous(1, [0x11; 32]);

        let opened = rotated
            .open(&store_key, &StoredSession { not_after, sealed })
            .unwrap();
        assert_eq!(opened.as_slice(), b"ticket and psk");
    }

    #[test]
    fn sealed_record_rejects_ciphertext_and_metadata_tampering() {
        let store_key = ResumptionKey::from_bytes(Bytes::from_static(b"store-key"));
        let not_after = UnixTime::since_unix_epoch(Duration::from_secs(u64::MAX));
        let keys = SessionSealKeyRing::new(1, [0x11; 32]);
        let mut plaintext = b"ticket and psk".to_vec();
        let sealed = keys.seal(&store_key, not_after, &mut plaintext).unwrap();
        let mut tampered = sealed.to_vec();
        let last = tampered.last_mut().unwrap();
        *last ^= 1;

        assert!(
            keys.open(
                &store_key,
                &StoredSession {
                    not_after,
                    sealed: tampered.into(),
                },
            )
            .is_none()
        );
        assert!(
            keys.open(
                &ResumptionKey::from_bytes(Bytes::from_static(b"another-key")),
                &StoredSession { not_after, sealed },
            )
            .is_none()
        );
    }
}
