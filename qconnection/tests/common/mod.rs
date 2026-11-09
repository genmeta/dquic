#![allow(dead_code)]

#[path = "../../../qtransport/tests/common/mod.rs"]
mod transport;

use std::sync::Arc;

pub use transport::*;

pub fn quic_endpoint() -> qconnection::QuicEndpoint {
    let (client_parameters, server_parameters) = parameters();
    let mut endpoint: qconnection::QuicEndpoint = identity().into();
    for (id, value) in client_parameters.iter() {
        endpoint.set_parameters(qbase::role::Role::Client, *id, value.clone()).unwrap();
    }
    for (id, value) in server_parameters.iter() {
        endpoint.set_parameters(qbase::role::Role::Server, *id, value.clone()).unwrap();
    }
    endpoint
}

/// Tests that use localhost DNS opt in explicitly; mock-only tests do not call this.
pub fn use_system_resolver() {
    static REGISTER: std::sync::Once = std::sync::Once::new();
    REGISTER.call_once(|| qresolve::Resolver::add(Arc::new(qresolve::SystemResolver)));
}

/// Release the test's owner and wait for Drop to clear its original CID.
/// These fixtures keep CID zero until connection teardown.
pub async fn drop_paths_and_wait(paths: Arc<qconnection::Paths>) {
    let weak = Arc::downgrade(&paths);
    let cids = paths.cid_registry.local.clone();
    drop(paths);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while weak.strong_count() != 0 || cids.initial_scid().is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("last Paths owner must release connection resources");
}
