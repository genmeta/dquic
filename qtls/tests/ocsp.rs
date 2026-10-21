use std::time::Duration;

use qtls::{CertificateDer, CertificateError, RootCerts, RustlsError, UnixTime, validate_ocsp};
use rustls::pki_types::pem::PemObject;

#[test]
fn response_must_be_current() {
    RootCerts::set([
        CertificateDer::from_pem_slice(include_bytes!("keychain/localhost/ca.cert")).unwrap(),
    ])
    .unwrap();
    // Same issuer, serial and public key as server.cert, with a wider validity window:
    // rejection must come from the OCSP response's times, not certificate expiry.
    let certificate = CertificateDer::from_pem_slice(include_bytes!(
        "keychain/localhost/server-extended-validity.cert"
    ))
    .unwrap();
    let response = include_bytes!("keychain/localhost/server.ocsp");
    validate_ocsp(
        response,
        std::slice::from_ref(&certificate),
        UnixTime::now(),
    )
    .unwrap();
    for now in [1_700_000_000, 2_200_000_000] {
        assert!(matches!(
            validate_ocsp(
                response,
                std::slice::from_ref(&certificate),
                UnixTime::since_unix_epoch(Duration::from_secs(now))
            ),
            Err(RustlsError::InvalidCertificate(
                CertificateError::InvalidOcspResponse
            ))
        ));
    }
}
