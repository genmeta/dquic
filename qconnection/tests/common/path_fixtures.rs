use std::{sync::Arc, time::Duration};

use qbase::{
    cid::ConnectionId,
    net::{addr::EndpointAddr, route::Pathway},
    role::Role,
};
use qconnection::Paths;

pub fn paths(role: Role) -> Arc<Paths> {
    paths_with_timeouts(role, Duration::ZERO, Duration::ZERO)
}

pub fn paths_with_timeouts(role: Role, max: Duration, defer: Duration) -> Arc<Paths> {
    let keys = qtls::default_provider()
        .cipher_suites
        .iter()
        .find_map(|suite| suite.tls13().and_then(|suite| suite.quic_suite()))
        .unwrap()
        .keys(
            b"original",
            if role == Role::Server {
                tls_backend::Side::Server
            } else {
                tls_backend::Side::Client
            },
            tls_backend::quic::Version::V1,
        )
        .into();
    crate::common::initial_paths_with_timeouts(
        role,
        ConnectionId::from_slice(b"localcid"),
        ConnectionId::from_slice(b"original"),
        keys,
        max,
        defer,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
    )
}

pub fn pathway(port: u16) -> Pathway {
    Pathway::new(
        EndpointAddr::direct(([127, 0, 0, 1], 30001).into()),
        EndpointAddr::direct(([127, 0, 0, 1], port).into()),
    )
}
