use std::sync::Arc;

use qtls::{
    CertificateDer, ClientResumptionConfig, ClientTlsConfig, RootCerts, TlsClient, TlsConfigError,
};
use rustls::pki_types::pem::PemObject;

const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");

#[test]
fn tls_endpoints_require_an_explicit_nonempty_root_store() {
    let config = || ClientTlsConfig {
        provider: Arc::new(qtls::default_provider()),
        alpn: Vec::new(),
        local: None,
        resumption: ClientResumptionConfig::Disabled,
        limits: Default::default(),
    };

    assert!(matches!(
        TlsClient::new(config()),
        Err(TlsConfigError::RootCertsNotSet)
    ));
    assert!(RootCerts::set([]).is_err());

    RootCerts::set([CertificateDer::from_pem_slice(CA_CERT).unwrap()]).unwrap();
    TlsClient::new(config()).unwrap();
}
