use crate::{
    support::tls::{drive, server_config},
    *,
};

fn connect(
    certificate: CertificateDer<'static>,
    ocsp: &[u8],
    name: &str,
) -> Result<HandshakeSummary, qtls::TlsError> {
    let client = TlsClient::new(ClientTlsConfig {
        provider: Arc::new(crypto_provider()),
        alpn: vec![b"h3".to_vec()],
        authority: None,
        resumption: ClientResumptionConfig::Disabled,
        limits: TlsLimits::default(),
    })
    .unwrap()
    .start(ClientStart {
        server_name: name.to_owned().try_into().unwrap(),
        quic_version: QuicVersion::V1,
        local_transport_parameters: Bytes::from_static(b"client-params"),
    })
    .unwrap();
    let server = rustls::quic::ServerConnection::new(
        Arc::new(server_config(
            certificate,
            PrivateKeyDer::from_pem_slice(SERVER_KEY).unwrap(),
            ocsp.to_vec(),
        )),
        rustls::quic::Version::V1,
        b"server-params".to_vec(),
    )
    .unwrap();
    drive(client, server.into()).map(|(summary, _)| summary)
}

#[test]
fn server_without_ocsp_is_rejected() {
    let _roots = set_roots();
    assert_rejected(
        connect(
            CertificateDer::from_pem_slice(SERVER_CERT).unwrap(),
            &[],
            "localhost",
        ),
        rustls::AlertDescription::BadCertificateStatusResponse,
    );
}

#[test]
fn supplied_server_ocsp_still_requires_matching_good_status() {
    let _roots = set_roots();
    let certificate = CertificateDer::from_pem_slice(SERVER_CERT).unwrap();
    let summary = connect(certificate.clone(), SERVER_OCSP, "localhost").unwrap();
    assert_eq!(summary.remote.unwrap().name(), "localhost");
    for staple in [&[1_u8][..], CLIENT_OCSP, SERVER_REVOKED_OCSP] {
        assert_rejected(
            connect(certificate.clone(), staple, "localhost"),
            rustls::AlertDescription::BadCertificateStatusResponse,
        );
    }
}

#[test]
fn missing_server_ocsp_preserves_name_chain_signature_and_validity_checks() {
    let _roots = set_roots();
    let certificate = CertificateDer::from_pem_slice(SERVER_CERT).unwrap();
    assert_rejected(
        connect(certificate.clone(), &[], "other.example"),
        rustls::AlertDescription::BadCertificate,
    );
    let mut damaged = certificate.as_ref().to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    assert_rejected(
        connect(CertificateDer::from(damaged), &[], "localhost"),
        rustls::AlertDescription::DecryptError,
    );
    assert_rejected(
        connect(
            CertificateDer::from_pem_slice(include_bytes!("../keychain/localhost/expired.cert"))
                .unwrap(),
            &[],
            "localhost",
        ),
        rustls::AlertDescription::CertificateExpired,
    );
    RootCerts::set([CertificateDer::from_pem_slice(include_bytes!(
        "../keychain/root/rootCA-ECC.crt"
    ))
    .unwrap()])
    .unwrap();
    assert_rejected(
        connect(certificate, &[], "localhost"),
        rustls::AlertDescription::UnknownCA,
    );
}
