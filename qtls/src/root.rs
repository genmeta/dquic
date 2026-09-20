use std::sync::{Arc, OnceLock, RwLock};

use rustls::{RootCertStore, pki_types::CertificateDer};

use crate::TlsConfigError;

pub struct RootCerts;

#[derive(Clone)]
pub(crate) struct RootCertsSnapshot {
    pub store: Arc<RootCertStore>,
    pub certificates: Arc<[CertificateDer<'static>]>,
}

impl RootCerts {
    pub fn set(
        certificates: impl IntoIterator<Item = CertificateDer<'static>>,
    ) -> Result<(), TlsConfigError> {
        let certificates: Vec<_> = certificates.into_iter().collect();
        let mut roots = RootCertStore::empty();
        for certificate in &certificates {
            roots
                .add(certificate.clone())
                .map_err(|error| TlsConfigError::Invalid(error.to_string()))?;
        }
        if roots.is_empty() {
            return Err(TlsConfigError::Invalid(
                "root certificate collection is empty".into(),
            ));
        }
        *root_certs()
            .write()
            .map_err(|_| TlsConfigError::Invalid("root certificate lock poisoned".into()))? =
            Some(RootCertsSnapshot {
                store: Arc::new(roots),
                certificates: certificates.into(),
            });
        Ok(())
    }

    pub(crate) fn get() -> Result<RootCertsSnapshot, TlsConfigError> {
        root_certs()
            .read()
            .map_err(|_| TlsConfigError::Invalid("root certificate lock poisoned".into()))?
            .clone()
            .ok_or(TlsConfigError::RootCertsNotSet)
    }
}

fn root_certs() -> &'static RwLock<Option<RootCertsSnapshot>> {
    static ROOT_CERTS: OnceLock<RwLock<Option<RootCertsSnapshot>>> = OnceLock::new();
    ROOT_CERTS.get_or_init(|| RwLock::new(None))
}
