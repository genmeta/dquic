use rustls::sign::{CertifiedKey, SingleCertAndKey};

use crate::{support::tls::drive, *};

fn connect(
    certificate: CertificateDer<'static>,
    key: &[u8],
    ocsp: &[u8],
) -> Result<HandshakeSummary, qtls::TlsError> {
    let provider = Arc::new(crypto_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(CA_CERT).unwrap())
        .unwrap();
    let mut credentials = CertifiedKey::from_der(
        vec![certificate],
        PrivateKeyDer::from_pem_slice(key).unwrap(),
        &provider,
    )
    .unwrap();
    credentials.ocsp = (!ocsp.is_empty()).then(|| ocsp.to_vec());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(credentials)));
    config.alpn_protocols = vec![b"h3".to_vec()];
    let client = rustls::quic::ClientConnection::new(
        Arc::new(config),
        rustls::quic::Version::V1,
        "localhost".try_into().unwrap(),
        b"client-params".to_vec(),
    )
    .unwrap();
    let server = TlsServer::new(ServerTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        authority: authority(&provider, "localhost", SERVER_CERT, SERVER_KEY, SERVER_OCSP),
        resumption: ServerResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })
    .unwrap()
    .start(QuicVersion::V1, Bytes::from_static(b"server-params"))
    .unwrap();
    drive(server, client.into()).map(|(summary, _)| summary)
}

#[test]
fn authenticated_client_without_ocsp_is_rejected() {
    let _roots = set_roots();
    assert_rejected(
        connect(
            CertificateDer::from_pem_slice(CLIENT_CERT).unwrap(),
            CLIENT_KEY,
            &[],
        ),
        rustls::AlertDescription::BadCertificateStatusResponse,
    );
}

#[test]
fn supplied_client_ocsp_must_still_be_valid_and_bound_to_the_certificate() {
    let _roots = set_roots();
    let certificate = CertificateDer::from_pem_slice(CLIENT_CERT).unwrap();
    let summary = connect(certificate.clone(), CLIENT_KEY, CLIENT_OCSP).unwrap();
    assert_eq!(summary.remote.unwrap().name(), "client");
    for staple in [&[1_u8][..], SERVER_OCSP] {
        assert_rejected(
            connect(certificate.clone(), CLIENT_KEY, staple),
            rustls::AlertDescription::BadCertificateStatusResponse,
        );
    }
}

#[test]
fn missing_client_ocsp_does_not_bypass_certificate_signature_or_validity() {
    let _roots = set_roots();
    let mut damaged = CertificateDer::from_pem_slice(CLIENT_CERT)
        .unwrap()
        .to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    assert_rejected(
        connect(CertificateDer::from(damaged), CLIENT_KEY, &[]),
        rustls::AlertDescription::DecryptError,
    );
    assert_rejected(
        connect(
            CertificateDer::from_pem_slice(include_bytes!("../keychain/localhost/expired.cert"))
                .unwrap(),
            SERVER_KEY,
            &[],
        ),
        rustls::AlertDescription::CertificateExpired,
    );
}
