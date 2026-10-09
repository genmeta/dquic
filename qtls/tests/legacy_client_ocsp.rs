//! A legacy-style client uses with_client_auth_cert and sends no client OCSP.
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use qtls::{
    CertificateDer, Epoch, LocalAuthority, PrivateKeyDer, QuicVersion, RootCerts,
    ServerResumptionConfig, ServerTlsConfig, TlsEvent, TlsLimits, TlsServer,
};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{ServerName, UnixTime, pem::PemObject},
};

const CA: &[u8] = include_bytes!("keychain/localhost/ca.cert");
const SERVER_CERT: &[u8] = include_bytes!("keychain/localhost/server.cert");
const SERVER_KEY: &[u8] = include_bytes!("keychain/localhost/server.key");
const SERVER_OCSP: &[u8] = include_bytes!("keychain/localhost/server.ocsp");
const CLIENT_CERT: &[u8] = include_bytes!("keychain/localhost/client.cert");
const CLIENT_KEY: &[u8] = include_bytes!("keychain/localhost/client.key");

#[derive(Debug)]
struct ObservedServerVerifier {
    inner: Arc<WebPkiServerVerifier>,
    staple: Arc<Mutex<Vec<u8>>>,
}

impl ServerCertVerifier for ObservedServerVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.staple.lock().unwrap() = ocsp.to_vec();
        self.inner.verify_server_cert(leaf, chain, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls12_signature(message, certificate, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls13_signature(message, certificate, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn connect_without_client_ocsp(
    optional_client_ocsp: bool,
) -> Result<(qtls::HandshakeSummary, Vec<u8>), Box<dyn std::error::Error>> {
    let provider = Arc::new(qtls::default_provider());
    let ca = CertificateDer::from_pem_slice(CA)?;
    RootCerts::set([ca.clone()])?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca)?;
    let staple = Arc::new(Mutex::new(Vec::new()));
    let verifier = ObservedServerVerifier {
        inner: WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()?,
        staple: staple.clone(),
    };
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(
            vec![CertificateDer::from_pem_slice(CLIENT_CERT)?],
            PrivateKeyDer::from_pem_slice(CLIENT_KEY)?,
        )?;
    config.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = rustls::quic::ClientConnection::new(
        Arc::new(config),
        rustls::quic::Version::V1,
        "localhost".try_into()?,
        b"client-params".to_vec(),
    )?;
    let server = TlsServer::new(ServerTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        authority: LocalAuthority::new(
            &provider,
            "localhost".into(),
            vec![CertificateDer::from_pem_slice(SERVER_CERT)?],
            PrivateKeyDer::from_pem_slice(SERVER_KEY)?,
            SERVER_OCSP.to_vec(),
        )?,
        resumption: ServerResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })?;
    let server = if optional_client_ocsp {
        server.with_optional_client_ocsp()
    } else {
        server
    };
    let mut server = server.start(QuicVersion::V1, Bytes::from_static(b"server-params"))?;
    let mut client_epoch = Epoch::Initial;
    let mut summary = None;
    for _ in 0..32 {
        drain_client(&mut client, &mut server, &mut client_epoch)?;
        while let Some(event) = server.next_event() {
            match event {
                TlsEvent::WriteCrypto { bytes, .. } => {
                    client.read_hs(&bytes)?;
                    drain_client(&mut client, &mut server, &mut client_epoch)?;
                }
                TlsEvent::HandshakeComplete(observed) => summary = Some(observed),
                _ => {}
            }
        }
        if !client.is_handshaking() && server.is_complete() {
            return Ok((summary.unwrap(), staple.lock().unwrap().clone()));
        }
    }
    Err("handshake did not complete".into())
}

fn drain_client(
    client: &mut rustls::quic::ClientConnection,
    server: &mut qtls::TlsHandshake,
    epoch: &mut Epoch,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let mut bytes = Vec::new();
        let change = client.write_hs(&mut bytes);
        let empty = bytes.is_empty();
        if !empty {
            server.receive_crypto(*epoch, &bytes)?;
        }
        match change {
            Some(rustls::quic::KeyChange::Handshake { .. }) => *epoch = Epoch::Handshake,
            Some(rustls::quic::KeyChange::OneRtt { .. }) => *epoch = Epoch::Data,
            None if empty => break,
            None => {}
        }
    }
    Ok(())
}

#[test]
fn legacy_authenticated_client_needs_explicit_compatibility_policy() {
    assert!(connect_without_client_ocsp(false).is_err());
    let (summary, staple) = connect_without_client_ocsp(true).unwrap();
    assert_eq!(summary.remote.unwrap().name(), "client");
    assert_eq!(summary.local.unwrap().name(), "localhost");
    assert_eq!(
        staple, SERVER_OCSP,
        "server must still present its OCSP to a legacy client"
    );
}
