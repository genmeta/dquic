use std::{collections::HashSet, future::poll_fn, task::Poll};

use super::*;

// Inject scripted NAT responses at the protocol boundary and advance virtual
// time for loss. macOS does not deliver UDP to unconfigured loopback aliases;
// these tests require neither alias configuration nor public NAT servers.
struct Network {
    protocol: Arc<StunProtocol>,
    client: Arc<UdpSocket>,
    _listener: UdpSocket,
    servers: [SocketAddr; 3],
    local: SocketAddr,
    outer: SocketAddr,
}

#[derive(Clone)]
struct Step {
    source: SocketAddr,
    response: Option<Response>,
    attempts: u8,
}

impl Step {
    fn unanswered(mut self, attempts: u8) -> Self {
        self.response = None;
        self.attempts = attempts;
        self
    }
}

impl Network {
    fn new() -> Self {
        let protocol = Arc::new(StunProtocol::new());
        let client = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let local = client.local_addr().unwrap();
        protocol.register_socket(local, &client);
        let listener = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = listener.local_addr().unwrap().port();
        Self {
            protocol,
            client,
            _listener: listener,
            servers: [
                SocketAddr::from(([127, 0, 0, 1], port)),
                SocketAddr::from(([127, 0, 0, 2], port ^ 1)),
                SocketAddr::from(([127, 0, 0, 3], port)),
            ],
            local,
            outer: "203.0.113.1:40000".parse().unwrap(),
        }
    }

    fn binding(&self, server: usize, mapped: SocketAddr) -> Step {
        Step {
            source: self.servers[server],
            response: Some(Response::with(vec![
                Attr::MappedAddress(mapped),
                Attr::ChangedAddress(self.servers[(server + 1) % 3]),
            ])),
            attempts: 1,
        }
    }

    fn filter(&self, server: usize, change_ip: bool, mapped: SocketAddr) -> Step {
        let source = if change_ip {
            self.servers[(server + 1) % 3]
        } else {
            SocketAddr::new(
                self.servers[server].ip(),
                self.servers[(server + 1) % 3].port(),
            )
        };
        Step {
            source,
            response: Some(Response::with(vec![
                Attr::MappedAddress(mapped),
                Attr::SourceAddress(source),
            ])),
            attempts: 1,
        }
    }

    async fn run<T: std::fmt::Debug>(&self, task: impl Future<Output = T>, steps: Vec<Step>) -> T {
        poll_fn(|cx| self.client.poll_send_ready(cx)).await.unwrap();
        let mut detection = Box::pin(task);
        let mut ids = HashSet::new();
        for step in steps {
            let mut step_id = None;
            for _ in 0..step.attempts {
                poll_fn(|cx| {
                    let state = detection.as_mut().poll(cx);
                    assert!(
                        state.is_pending(),
                        "unexpected detection completion: {state:?}"
                    );
                    Poll::Ready(())
                })
                .await;
                assert_eq!(self.protocol.transactions.len(), 1);
                let id = *self.protocol.transactions.iter().next().unwrap().key();
                if let Some(previous) = step_id {
                    assert_eq!(id, previous, "retries must reuse the transaction ID");
                } else {
                    assert!(ids.insert(id), "new steps must use new transaction IDs");
                    step_id = Some(id);
                }
                if let Some(response) = &step.response {
                    self.protocol
                        .on_datagram(
                            &self.client,
                            id,
                            Message::Response(response.clone()),
                            Link::new(self.local, step.source),
                        )
                        .await
                        .unwrap();
                } else {
                    tokio::time::advance(PROBE_TIMEOUT).await;
                }
            }
        }
        let result = poll_fn(|cx| match detection.as_mut().poll(cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => panic!("unexpected additional NAT probe"),
        })
        .await;
        assert!(self.protocol.transactions.is_empty());
        result
    }
}

#[tokio::test(start_paused = true)]
async fn detects_cone_types_and_probes_third_server_last() {
    for nat in [
        NatType::FullCone,
        NatType::RestrictedCone,
        NatType::RestrictedPort,
    ] {
        let network = Network::new();
        let ip_filter = network.filter(1, true, network.outer);
        let port_filter = network.filter(1, false, network.outer);
        let steps = vec![
            network.binding(0, network.outer),
            network.binding(1, network.outer),
            if nat == NatType::FullCone {
                ip_filter
            } else {
                ip_filter.unanswered(FILTER_ATTEMPTS)
            },
            if nat == NatType::RestrictedPort {
                port_filter.unanswered(FILTER_ATTEMPTS)
            } else {
                port_filter
            },
            network.binding(2, network.outer),
        ];
        assert_eq!(
            network
                .run(
                    network
                        .protocol
                        .detect_nat(network.local, network.servers[0]),
                    steps
                )
                .await
                .unwrap(),
            nat
        );
    }
}

#[tokio::test(start_paused = true)]
async fn symmetric_nat_needs_only_two_mapping_probes() {
    let network = Network::new();
    let steps = vec![
        network.binding(0, network.outer),
        network.binding(1, "203.0.113.1:40001".parse().unwrap()),
    ];
    assert_eq!(
        network
            .run(
                network
                    .protocol
                    .detect_nat(network.local, network.servers[0]),
                steps
            )
            .await
            .unwrap(),
        NatType::Symmetric
    );
}

#[tokio::test(start_paused = true)]
async fn detects_dynamic_mapping_and_unanswered_third_probe() {
    for unanswered in [false, true] {
        let network = Network::new();
        let last = network.binding(2, "203.0.113.1:40002".parse().unwrap());
        let steps = vec![
            network.binding(0, network.outer),
            network.binding(1, network.outer),
            network
                .filter(1, true, network.outer)
                .unanswered(FILTER_ATTEMPTS),
            network
                .filter(1, false, network.outer)
                .unanswered(FILTER_ATTEMPTS),
            if unanswered {
                last.unanswered(PROBE_ATTEMPTS)
            } else {
                last
            },
        ];
        assert_eq!(
            network
                .run(
                    network
                        .protocol
                        .detect_nat(network.local, network.servers[0]),
                    steps
                )
                .await
                .unwrap(),
            NatType::Dynamic
        );
    }
}

#[tokio::test(start_paused = true)]
async fn public_filtering_targets_the_first_server() {
    for nat in [
        NatType::FullCone,
        NatType::RestrictedCone,
        NatType::RestrictedPort,
    ] {
        let network = Network::new();
        let ip_filter = network.filter(0, true, network.local);
        let port_filter = network.filter(0, false, network.local);
        let steps = vec![
            network.binding(0, network.local),
            if nat == NatType::FullCone {
                ip_filter
            } else {
                ip_filter.unanswered(PROBE_ATTEMPTS)
            },
            if nat == NatType::RestrictedPort {
                port_filter.unanswered(PROBE_ATTEMPTS)
            } else {
                port_filter
            },
        ];
        assert_eq!(
            network
                .run(
                    network
                        .protocol
                        .detect_nat(network.local, network.servers[0]),
                    steps
                )
                .await
                .unwrap(),
            nat
        );
    }
}

#[tokio::test(start_paused = true)]
async fn initial_timeout_is_blocked_but_mapping_timeout_is_an_error() {
    let network = Network::new();
    assert_eq!(
        network
            .run(
                network
                    .protocol
                    .detect_nat(network.local, network.servers[0]),
                vec![network.binding(0, network.outer).unanswered(PROBE_ATTEMPTS)]
            )
            .await
            .unwrap(),
        NatType::Blocked
    );

    let network = Network::new();
    let result = network
        .run(
            network
                .protocol
                .detect_nat(network.local, network.servers[0]),
            vec![
                network.binding(0, network.outer),
                network.binding(1, network.outer).unanswered(PROBE_ATTEMPTS),
            ],
        )
        .await;
    assert!(matches!(result, Err(StunError::Io(error)) if error.kind() == io::ErrorKind::TimedOut));
}

#[tokio::test(start_paused = true)]
async fn invalid_input_and_unregistered_socket_are_errors() {
    let protocol = Arc::new(StunProtocol::new());
    let server = "127.0.0.1:3478".parse().unwrap();
    for local in ["0.0.0.0:10000", "[::]:10000", "127.0.0.1:0"] {
        let result = protocol.detect_nat(local.parse().unwrap(), server).await;
        assert!(
            matches!(result, Err(StunError::Io(error)) if error.kind() == io::ErrorKind::InvalidInput)
        );
        let result = protocol.detect_outer(local.parse().unwrap(), server).await;
        assert!(
            matches!(result, Err(StunError::Io(error)) if error.kind() == io::ErrorKind::InvalidInput)
        );
    }
    let result = protocol
        .detect_nat("127.0.0.1:10000".parse().unwrap(), server)
        .await;
    assert!(matches!(result, Err(StunError::Io(error)) if error.kind() == io::ErrorKind::NotFound));
    let result = protocol
        .detect_outer("127.0.0.1:10000".parse().unwrap(), server)
        .await;
    assert!(matches!(result, Err(StunError::Io(error)) if error.kind() == io::ErrorKind::NotFound));
    assert!(protocol.transactions.is_empty());
}

#[tokio::test(start_paused = true)]
async fn missing_attributes_and_invalid_server_topology_are_errors() {
    for attrs in [
        vec![],
        vec![Attr::MappedAddress("203.0.113.1:40000".parse().unwrap())],
    ] {
        let network = Network::new();
        let mut first = network.binding(0, network.outer);
        first.response = Some(Response::with(attrs));
        assert!(
            network
                .run(
                    network
                        .protocol
                        .detect_nat(network.local, network.servers[0]),
                    vec![first]
                )
                .await
                .is_err()
        );
    }
    let network = Network::new();
    let mut first = network.binding(0, network.outer);
    first.response = Some(Response::with(vec![
        Attr::MappedAddress(network.outer),
        Attr::ChangedAddress(network.servers[0]),
    ]));
    assert!(
        network
            .run(
                network
                    .protocol
                    .detect_nat(network.local, network.servers[0]),
                vec![first]
            )
            .await
            .is_err()
    );

    let network = Network::new();
    let mut second = network.binding(1, network.outer);
    second.response = Some(Response::with(vec![
        Attr::MappedAddress(network.outer),
        Attr::ChangedAddress(network.servers[0]),
    ]));
    assert!(
        network
            .run(
                network
                    .protocol
                    .detect_nat(network.local, network.servers[0]),
                vec![network.binding(0, network.outer), second]
            )
            .await
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn rejects_unchanged_source_and_inconsistent_source_attribute() {
    for unchanged in [true, false] {
        let network = Network::new();
        let mut filter = network.filter(0, true, network.local);
        if unchanged {
            filter.source = network.servers[0];
        } else {
            filter.response = Some(Response::with(vec![
                Attr::MappedAddress(network.local),
                Attr::SourceAddress(network.servers[0]),
            ]));
        }
        let result = network
            .run(
                network
                    .protocol
                    .detect_nat(network.local, network.servers[0]),
                vec![network.binding(0, network.local), filter],
            )
            .await;
        assert!(
            matches!(result, Err(StunError::Io(error)) if error.kind() == io::ErrorKind::InvalidData)
        );
    }
}

#[tokio::test(start_paused = true)]
async fn cancelling_detection_removes_the_pending_transaction() {
    let network = Network::new();
    assert!(
        timeout(
            Duration::from_millis(20),
            network
                .protocol
                .detect_nat(network.local, network.servers[0])
        )
        .await
        .is_err()
    );
    assert!(network.protocol.transactions.is_empty());
    assert!(
        timeout(
            Duration::from_millis(20),
            network
                .protocol
                .detect_outer(network.local, network.servers[0])
        )
        .await
        .is_err()
    );
    assert!(network.protocol.transactions.is_empty());
}

#[tokio::test(start_paused = true)]
async fn outer_discovery_needs_only_a_mapped_address() {
    let network = Network::new();
    let mut first = network.binding(0, network.outer);
    first.response = Some(Response::with(vec![Attr::MappedAddress(network.outer)]));
    let outer = network
        .run(
            network
                .protocol
                .detect_outer(network.local, network.servers[0]),
            vec![first.clone()],
        )
        .await
        .unwrap();
    assert_eq!(outer, Some(network.outer));

    // Classification makes its own first request and can fail independently.
    assert!(
        network
            .run(
                network
                    .protocol
                    .detect_nat(network.local, network.servers[0]),
                vec![first]
            )
            .await
            .is_err()
    );
    assert_eq!(outer, Some(network.outer));
}

#[tokio::test(start_paused = true)]
async fn outer_discovery_timeout_and_invalid_response() {
    let network = Network::new();
    let result = network
        .run(
            network
                .protocol
                .detect_outer(network.local, network.servers[0]),
            vec![network.binding(0, network.outer).unanswered(PROBE_ATTEMPTS)],
        )
        .await;
    assert_eq!(result.unwrap(), None);

    let mut first = network.binding(0, network.outer);
    first.response = Some(Response::with(vec![]));
    assert!(
        network
            .run(
                network
                    .protocol
                    .detect_outer(network.local, network.servers[0]),
                vec![first],
            )
            .await
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn nat_detection_uses_a_fresh_mapping_after_outer_discovery() {
    let network = Network::new();
    let outer = network
        .run(
            network
                .protocol
                .detect_outer(network.local, network.servers[0]),
            vec![network.binding(0, network.outer)],
        )
        .await
        .unwrap();
    assert_eq!(outer, Some(network.outer));

    // A new public mapping takes the public filtering branch, regardless of the
    // private mapping returned by the earlier independent outer discovery task.
    assert_eq!(
        network
            .run(
                network
                    .protocol
                    .detect_nat(network.local, network.servers[0]),
                vec![
                    network.binding(0, network.local),
                    network.filter(0, true, network.local),
                    network.filter(0, false, network.local),
                ]
            )
            .await
            .unwrap(),
        NatType::FullCone
    );
}
