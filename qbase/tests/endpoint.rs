use std::sync::Arc;

use qbase::endpoint::*;
use qtls::PrivateKeyDer;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};

const CERT: &[u8] = include_bytes!("keychain/localhost/server.cert");
const KEY: &[u8] = include_bytes!("keychain/localhost/server.key");
const OTHER_CERT: &[u8] = include_bytes!("keychain/localhost/client.cert");

fn certificate(pem: &[u8]) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(pem).unwrap()
}

fn endpoint(certs: Vec<CertificateDer<'static>>) -> Arc<Endpoint> {
    Endpoint::new(
        "a different name",
        certs,
        PrivateKeyDer::from_pem_slice(KEY).unwrap(),
        b"ocsp".to_vec(),
    )
    .unwrap()
}

#[test]
fn construction_defers_certificate_checks() {
    // Even invalid names, malformed/empty chains and mismatched keys are
    // preserved for the handshake layer to validate.
    for certs in [
        vec![],
        vec![CertificateDer::from(vec![0])],
        vec![certificate(OTHER_CERT)],
    ] {
        let endpoint = endpoint(certs);
        assert_eq!(endpoint.name(), "a different name");
        assert_eq!(endpoint.ocsp(), b"ocsp");
    }
}

#[test]
fn construction_rejects_unloadable_private_key() {
    let result = Endpoint::new(
        "localhost",
        vec![certificate(CERT)],
        PrivatePkcs8KeyDer::from(vec![0]).into(),
        b"ocsp".to_vec(),
    );
    assert!(result.is_err());
}

#[test]
fn construction_rejects_empty_ocsp() {
    let result = Endpoint::new(
        "localhost",
        vec![certificate(CERT)],
        PrivateKeyDer::from_pem_slice(KEY).unwrap(),
        Vec::new(),
    );
    assert!(result.is_err());
}
