//! A legacy-style client uses with_client_auth_cert and sends no client OCSP.
use std::sync::Arc;

use bytes::Bytes;
use qtls::{
    CertificateDer, Epoch, LocalAuthority, PrivateKeyDer, QuicVersion, RootCerts,
    ServerResumptionConfig, ServerTlsConfig, TlsEvent, TlsLimits, TlsServer,
};
use rustls::pki_types::pem::PemObject;

const CA: &[u8] = include_bytes!("keychain/localhost/ca.cert");
const SERVER_CERT: &[u8] = include_bytes!("keychain/localhost/server.cert");
const SERVER_KEY: &[u8] = include_bytes!("keychain/localhost/server.key");
const SERVER_OCSP: &[u8] = include_bytes!("keychain/localhost/server.ocsp");
const CLIENT_CERT: &[u8] = include_bytes!("keychain/localhost/client.cert");
const CLIENT_KEY: &[u8] = include_bytes!("keychain/localhost/client.key");

fn connect_without_client_ocsp() -> Result<(), Box<dyn std::error::Error>> {
    let provider = Arc::new(qtls::default_provider());
    let ca = CertificateDer::from_pem_slice(CA)?;
    RootCerts::set([ca.clone()])?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca)?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
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
    let mut server = server.start(QuicVersion::V1, Bytes::from_static(b"server-params"))?;
    let mut client_epoch = Epoch::Initial;
    for _ in 0..32 {
        drain_client(&mut client, &mut server, &mut client_epoch)?;
        while let Some(event) = server.next_event() {
            if let TlsEvent::WriteCrypto { bytes, .. } = event {
                client.read_hs(&bytes)?;
                drain_client(&mut client, &mut server, &mut client_epoch)?;
            }
        }
        if !client.is_handshaking() && server.is_complete() {
            return Ok(());
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
fn legacy_authenticated_client_without_ocsp_is_rejected() {
    let error = connect_without_client_ocsp().unwrap_err();
    assert!(
        matches!(
            error.downcast_ref::<qtls::TlsError>(),
            Some(qtls::TlsError::Alert(alert))
                if alert.description() == u8::from(rustls::AlertDescription::BadCertificateStatusResponse)
        ),
        "unexpected handshake error: {error:?}"
    );
}
