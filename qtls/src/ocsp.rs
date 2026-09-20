use der::{Decode as _, Encode as _};
use pkix_path::SignatureVerifier as _;
use pkix_revocation::{OcspChecker, RevocationChecker as _};
use rustls::{
    CertificateError,
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{CertificateDer, UnixTime},
};
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef, der::referenced::OwnedToRef as _};
use x509_cert::Certificate;

use crate::root::RootCertsSnapshot;

pub(crate) fn verify(
    response: &[u8],
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    roots: &RootCertsSnapshot,
    now: UnixTime,
    algorithms: WebPkiSupportedAlgorithms,
) -> Result<(), rustls::Error> {
    if response.is_empty() {
        return Err(invalid());
    }

    let certificate = Certificate::from_der(end_entity.as_ref()).map_err(|_| invalid())?;
    let verifier = ProviderVerifier { algorithms };
    let checker = OcspChecker::new(response, now.as_secs(), verifier).map_err(|_| invalid())?;

    for issuer in intermediates.iter().chain(roots.certificates.iter()) {
        let Ok(issuer) = Certificate::from_der(issuer.as_ref()) else {
            continue;
        };
        if !issued_by(&certificate, &issuer, verifier) {
            continue;
        }
        return checker
            .check_revocation(&certificate, &issuer)
            .map_err(|_| invalid());
    }

    Err(invalid())
}

fn issued_by(certificate: &Certificate, issuer: &Certificate, verifier: ProviderVerifier) -> bool {
    if certificate.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return false;
    }
    let Ok(message) = certificate.tbs_certificate.to_der() else {
        return false;
    };
    verifier
        .verify_signature(
            certificate.signature_algorithm.owned_to_ref(),
            issuer
                .tbs_certificate
                .subject_public_key_info
                .owned_to_ref(),
            &message,
            certificate.signature.raw_bytes(),
        )
        .is_ok()
}

#[derive(Clone, Copy)]
struct ProviderVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}

impl pkix_path::SignatureVerifier for ProviderVerifier {
    fn verify_signature(
        &self,
        signature_algorithm: AlgorithmIdentifierRef<'_>,
        issuer_spki: SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), signature::Error> {
        let signature_algorithm = algorithm_identifier_value(signature_algorithm)?;
        let public_key_algorithm = algorithm_identifier_value(issuer_spki.algorithm)?;
        let public_key = issuer_spki.subject_public_key.raw_bytes();

        self.algorithms
            .all
            .iter()
            .find(|algorithm| {
                algorithm.signature_alg_id().as_ref() == signature_algorithm
                    && algorithm.public_key_alg_id().as_ref() == public_key_algorithm
            })
            .ok_or_else(signature::Error::new)?
            .verify_signature(public_key, message, signature)
            .map_err(|_| signature::Error::new())
    }
}

fn algorithm_identifier_value(
    algorithm: AlgorithmIdentifierRef<'_>,
) -> Result<Vec<u8>, signature::Error> {
    let mut encoded = algorithm
        .oid
        .to_der()
        .map_err(|_| signature::Error::new())?;
    if let Some(parameters) = algorithm.parameters {
        encoded.extend(parameters.to_der().map_err(|_| signature::Error::new())?);
    }
    Ok(encoded)
}

fn invalid() -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::InvalidOcspResponse)
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use rustls::{RootCertStore, pki_types::pem::PemObject as _};

    use super::*;

    #[test]
    fn response_must_be_current() {
        let issuer = CertificateDer::from_pem_slice(include_bytes!(
            "../../tests/keychain/localhost/ca.cert"
        ))
        .unwrap();
        let certificate = CertificateDer::from_pem_slice(include_bytes!(
            "../../tests/keychain/localhost/server.cert"
        ))
        .unwrap();
        let mut store = RootCertStore::empty();
        store.add(issuer.clone()).unwrap();
        let roots = RootCertsSnapshot {
            store: Arc::new(store),
            certificates: vec![issuer].into(),
        };
        let algorithms = crate::default_provider().signature_verification_algorithms;
        let response = include_bytes!("../../tests/keychain/localhost/server.ocsp");

        for now in [1_700_000_000, 2_200_000_000] {
            assert!(
                verify(
                    response,
                    &certificate,
                    &[],
                    &roots,
                    UnixTime::since_unix_epoch(Duration::from_secs(now)),
                    algorithms,
                )
                .is_err()
            );
        }
    }
}
