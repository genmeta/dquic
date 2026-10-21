mod support;

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use qtls::{
    CertificateDer, ClientResumptionConfig, ClientStart, ClientTlsConfig, PrivateKeyDer,
    QuicVersion, ResumptionKey, ResumptionStore, RootCerts, SessionSealKeyRing, StoreError,
    StoredSession, TlsClient, UnixTime,
};
use rustls::{HandshakeKind, pki_types::pem::PemObject};
use support::tls::{drive, server_config};

// Deliberately returns the saved record even for another key, to verify that qtls
// authenticates the store key rather than trusting the storage backend.
#[derive(Debug, Default)]
struct ReplayStore {
    record: Mutex<Option<(ResumptionKey, StoredSession)>>,
    requested: Mutex<Option<ResumptionKey>>,
}

impl ResumptionStore for ReplayStore {
    fn put(&self, key: ResumptionKey, session: StoredSession) -> Result<(), StoreError> {
        *self.record.lock().unwrap() = Some((key, session));
        Ok(())
    }

    fn take(&self, key: &ResumptionKey) -> Result<Option<StoredSession>, StoreError> {
        *self.requested.lock().unwrap() = Some(key.clone());
        Ok(self
            .record
            .lock()
            .unwrap()
            .take()
            .map(|(_, session)| session))
    }
}

fn server() -> Arc<rustls::ServerConfig> {
    RootCerts::set([
        CertificateDer::from_pem_slice(include_bytes!("keychain/localhost/ca.cert")).unwrap(),
    ])
    .unwrap();
    Arc::new(server_config(
        CertificateDer::from_pem_slice(include_bytes!("keychain/localhost/server.cert")).unwrap(),
        PrivateKeyDer::from_pem_slice(include_bytes!("keychain/localhost/server.key")).unwrap(),
        include_bytes!("keychain/localhost/server.ocsp").to_vec(),
    ))
}

fn connect(
    server: &Arc<rustls::ServerConfig>,
    store: &Arc<ReplayStore>,
    seal_keys: SessionSealKeyRing,
    namespace: &str,
) -> HandshakeKind {
    let client = TlsClient::new(ClientTlsConfig {
        provider: Arc::new(qtls::default_provider()),
        alpn: vec![b"h3".to_vec()],
        authority: None,
        resumption: ClientResumptionConfig::Enabled {
            namespace: Arc::from(namespace),
            store: store.clone(),
            seal_keys: Arc::new(seal_keys),
        },
        limits: Default::default(),
    })
    .unwrap()
    .start(ClientStart {
        server_name: "localhost".try_into().unwrap(),
        quic_version: QuicVersion::V1,
        local_transport_parameters: Bytes::from_static(b"client-params"),
    })
    .unwrap();
    let peer = rustls::quic::ServerConnection::new(
        server.clone(),
        rustls::quic::Version::V1,
        b"server-params".to_vec(),
    )
    .unwrap();
    let (summary, peer) = drive(client, peer.into()).unwrap();
    assert_eq!(summary.remote.unwrap().name(), "localhost");
    let rustls::quic::Connection::Server(peer) = peer else {
        unreachable!()
    };
    peer.handshake_kind().unwrap()
}

#[test]
fn seal_key_rotation_opens_records_from_the_previous_key() {
    let server = server();
    let store = Arc::new(ReplayStore::default());
    assert_eq!(
        connect(
            &server,
            &store,
            SessionSealKeyRing::new(1, [0x11; 32]),
            "rotation"
        ),
        HandshakeKind::Full
    );
    let record = store.record.lock().unwrap().clone().unwrap();
    for previous in [false, true] {
        *store.record.lock().unwrap() = Some(record.clone());
        let mut keys = SessionSealKeyRing::new(2, [0x22; 32]);
        if previous {
            keys = keys.with_previous(1, [0x11; 32]);
        }
        let kind = connect(&server, &store, keys, "rotation");
        assert_eq!(
            kind,
            if previous {
                HandshakeKind::Resumed
            } else {
                HandshakeKind::Full
            }
        );
        assert_eq!(store.requested.lock().unwrap().as_ref(), Some(&record.0));
    }
}

#[test]
fn sealed_record_rejects_ciphertext_and_metadata_tampering() {
    let server = server();
    let store = Arc::new(ReplayStore::default());
    assert_eq!(
        connect(
            &server,
            &store,
            SessionSealKeyRing::new(1, [0x11; 32]),
            "original"
        ),
        HandshakeKind::Full
    );
    let (key, original) = store.record.lock().unwrap().clone().unwrap();
    for tamper in ["ciphertext", "expiry", "store key", "none"] {
        let mut session = original.clone();
        let namespace = match tamper {
            "ciphertext" => {
                let mut bytes = session.sealed.to_vec();
                *bytes.last_mut().unwrap() ^= 1;
                session.sealed = bytes.into();
                "original"
            }
            "expiry" => {
                session.not_after = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                    session.not_after.as_secs() + 1,
                ));
                "original"
            }
            "store key" => "another-key",
            _ => "original",
        };
        *store.record.lock().unwrap() = Some((key.clone(), session));
        let kind = connect(
            &server,
            &store,
            SessionSealKeyRing::new(1, [0x11; 32]),
            namespace,
        );
        assert_eq!(
            kind,
            if tamper == "none" {
                HandshakeKind::Resumed
            } else {
                HandshakeKind::Full
            },
            "{tamper}"
        );
        let same_key = store.requested.lock().unwrap().as_ref() == Some(&key);
        assert_eq!(same_key, tamper != "store key");
    }
}
