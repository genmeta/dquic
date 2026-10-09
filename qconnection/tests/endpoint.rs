mod common;

use std::sync::Arc;

use qbase::endpoint::{Anonymous, Endpoint};
use qconnection::{QuicEndpoint, Scopes, ServerRegistry};

struct UnusedScopes;

impl From<UnusedScopes> for Scopes {
    fn from(_: UnusedScopes) -> Self {
        panic!("anonymous listen must not process scopes");
    }
}

#[test]
fn anonymous_listen_is_a_noop_without_a_runtime() {
    let endpoints: [QuicEndpoint; 3] = [
        Anonymous.into(),
        None::<Endpoint>.into(),
        None::<Arc<Endpoint>>.into(),
    ];
    for endpoint in endpoints {
        endpoint
            .listen(UnusedScopes, |_| panic!("anonymous endpoint cannot accept"))
            .unwrap();
    }
}

#[tokio::test]
async fn converted_identities_listen_and_anonymous_listen_preserves_the_listener() {
    let identity = common::identity();
    let endpoints: [QuicEndpoint; 4] = [
        identity.as_ref().clone().into(),
        Some(identity.as_ref().clone()).into(),
        identity.clone().into(),
        Some(identity).into(),
    ];
    for endpoint in endpoints {
        endpoint.listen(Scopes::ALL, |_| {}).unwrap();
        let registered = ServerRegistry::global().get("localhost").unwrap();
        let anonymous: QuicEndpoint = Anonymous.into();
        anonymous
            .listen(UnusedScopes, |_| panic!("cannot accept"))
            .unwrap();
        assert!(Arc::ptr_eq(
            &registered,
            &ServerRegistry::global().get("localhost").unwrap(),
        ));
        ServerRegistry::global().remove("localhost");
    }
}
