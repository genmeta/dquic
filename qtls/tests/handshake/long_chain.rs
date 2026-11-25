use crate::*;

const ROOT: &[u8] = include_bytes!("../keychain/long-chain/ca.pem");
const KEY: &[u8] = include_bytes!("../keychain/long-chain/leaf.key");
const NINE: &[u8] = include_bytes!("../keychain/long-chain/chain-9.pem");
const SIXTEEN: &[u8] = include_bytes!("../keychain/long-chain/chain-16.pem");
const OCSP_NINE: &[u8] = include_bytes!("../keychain/long-chain/chain-9.ocsp");
const OCSP_SIXTEEN: &[u8] = include_bytes!("../keychain/long-chain/chain-16.ocsp");

fn certificates(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem).map(|cert| cert.unwrap().into_owned()).collect()
}

fn connect(
    server_chain: Vec<CertificateDer<'static>>,
    client_chain: Option<Vec<CertificateDer<'static>>>,
    ocsp: &[u8],
    client_limits: TlsLimits,
    server_limits: TlsLimits,
) -> Result<(), qtls::TlsError> {
    let provider = Arc::new(crypto_provider());
    let authority = |chain| {
        LocalAuthority::new(&provider, "localhost".into(), chain, PrivateKeyDer::from_pem_slice(KEY).unwrap(), ocsp.to_vec()).unwrap()
    };
    let client = TlsClient::new(ClientTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        authority: client_chain.map(authority),
        resumption: ClientResumptionConfig::Disabled,
        limits: client_limits,
    })?;
    let server = TlsServer::new(ServerTlsConfig {
        provider: provider.clone(),
        alpn: vec![b"h3".to_vec()],
        authority: authority(server_chain),
        resumption: ServerResumptionConfig::Disabled,
        limits: server_limits,
    })?;
    handshake(&client, &server).map(|_| ())
}

#[test]
fn long_chains_complete_mutual_auth_with_default_limits() {
    let _roots = set_roots();
    RootCerts::set(certificates(ROOT)).unwrap();
    connect(certificates(NINE), Some(certificates(NINE)), OCSP_NINE, TlsLimits::default(), TlsLimits::default()).unwrap();
    connect(certificates(SIXTEEN), Some(certificates(SIXTEEN)), OCSP_SIXTEEN, TlsLimits::default(), TlsLimits::default()).unwrap();
}

#[test]
fn long_chain_still_rejects_untrusted_roots_bad_signatures_and_name_constraints() {
    let _roots = set_roots();
    let limits = TlsLimits { max_certificates: 16, ..TlsLimits::default() };
    assert!(connect(certificates(NINE), None, OCSP_NINE, limits, limits).is_err());
    RootCerts::set(certificates(ROOT)).unwrap();
    let mut damaged = certificates(NINE);
    let mut certificate = damaged[4].to_vec();
    *certificate.last_mut().unwrap() ^= 1;
    damaged[4] = CertificateDer::from(certificate);
    assert!(connect(damaged.clone(), None, OCSP_NINE, limits, limits).is_err());
    assert!(connect(certificates(NINE), Some(damaged), OCSP_NINE, limits, limits).is_err());
    let mut restricted = certificates(NINE);
    restricted[5] = certificates(include_bytes!("../keychain/long-chain/restricted-ca.pem")).remove(0);
    assert!(connect(restricted, None, OCSP_NINE, limits, limits).is_err());
}

#[test]
fn long_chain_still_obeys_local_and_peer_certificate_resource_limits() {
    let _roots = set_roots();
    RootCerts::set(certificates(ROOT)).unwrap();
    let defaults = TlsLimits::default();
    for limits in [
        TlsLimits { max_certificates: 8, ..defaults },
        TlsLimits { max_certificate_chain_bytes: certificates(NINE).iter().map(|cert| cert.as_ref().len()).sum::<usize>() - 1, ..defaults },
    ] {
        assert!(connect(certificates(NINE), None, OCSP_NINE, limits, defaults).is_err());
        assert!(connect(certificates(NINE), None, OCSP_NINE, defaults, limits).is_err());
        assert!(connect(certificates(NINE), Some(certificates(NINE)), OCSP_NINE, defaults, limits).is_err());
    }
}
