mod common;

use std::sync::Arc;

use qbase::endpoint::Endpoint;
use qconnection::{QuicEndpoint, Scopes, ServerRegistry};
use tls_backend::pki_types::pem::PemObject;

#[tokio::test]
async fn missing_server_name_requires_exactly_one_listener() {
    let registry = ServerRegistry::global();
    assert!(registry.get(None).is_none());
    assert!(registry.get(Some("localhost")).is_none());

    common::quic_endpoint().listen(Scopes::ALL, |_| {}).unwrap();
    let server = registry.get(Some("localhost")).unwrap();
    assert!(Arc::ptr_eq(&server, &registry.get(None).unwrap()));
    assert!(registry.get(Some("unknown.test")).is_none());

    let identity = Endpoint::new(
        "other.test",
        common::identity().cert_chain().to_vec(),
        qtls::PrivateKeyDer::from_pem_slice(include_bytes!("keychain/localhost/server.key"))
            .unwrap(),
        common::identity().ocsp().to_vec(),
    )
    .unwrap();
    QuicEndpoint::from(identity)
        .listen(Scopes::ALL, |_| {})
        .unwrap();
    assert!(registry.get(None).is_none());
    assert!(Arc::ptr_eq(
        &server,
        &registry.get(Some("localhost")).unwrap()
    ));
    assert!(registry.get(Some("other.test")).is_some());
    assert!(registry.get(Some("unknown.test")).is_none());

    registry.remove("other.test");
    assert!(Arc::ptr_eq(&server, &registry.get(None).unwrap()));
    registry.remove("localhost");
    assert!(registry.get(None).is_none());
}
