use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, LazyLock},
    time::Duration,
};

use dquic::{
    prelude::{handy::*, *},
    qinterface::{component::local_endpoint::LocalEndpoints, manager::InterfaceManager},
    qresolve::Source,
    qtraversal::nat::client::{NatType, StunClientsComponent},
};
use futures::{
    FutureExt,
    future::{BoxFuture, Shared},
};
use rustls::RootCertStore;
use tokio::task::JoinSet;
use tracing::{info, warn};

mod common;
use common::*;
mod echo_common;
use echo_common::*;

#[derive(Debug, Clone, Copy)]
pub struct TestCase {
    pub bind_addr: &'static str,
    pub outer_addr: &'static str,
    pub nat_type: NatType,
}

pub const STUN_SERVERS: &str = "10.10.0.64:20002";

pub const CASES: [TestCase; 10] = [
    TestCase {
        bind_addr: "192.168.0.98:6001",
        outer_addr: "10.10.0.98:6001",
        nat_type: NatType::FullCone,
    },
    TestCase {
        bind_addr: "192.168.0.96:6002",
        outer_addr: "10.10.0.96:6002",
        nat_type: NatType::RestrictedCone,
    },
    TestCase {
        bind_addr: "192.168.0.88:6003",
        outer_addr: "10.10.0.88:6003",
        nat_type: NatType::RestrictedPort,
    },
    TestCase {
        bind_addr: "192.168.0.86:6004",
        outer_addr: "10.10.0.86:6004",
        nat_type: NatType::Dynamic,
    },
    TestCase {
        bind_addr: "192.168.0.84:6005",
        outer_addr: "10.10.0.84:6005",
        nat_type: NatType::Symmetric,
    },
    // server
    TestCase {
        bind_addr: "172.16.0.48:6006",
        outer_addr: "10.10.0.48:6006",
        nat_type: NatType::FullCone,
    },
    TestCase {
        bind_addr: "172.16.0.46:6007",
        outer_addr: "10.10.0.46:6007",
        nat_type: NatType::RestrictedCone,
    },
    TestCase {
        bind_addr: "172.16.0.38:6008",
        outer_addr: "10.10.0.38:6008",
        nat_type: NatType::RestrictedPort,
    },
    TestCase {
        bind_addr: "172.16.0.36:6009",
        outer_addr: "10.10.0.36:6009",
        nat_type: NatType::Dynamic,
    },
    TestCase {
        bind_addr: "172.16.0.34:6010",
        outer_addr: "10.10.0.34:6010",
        nat_type: NatType::Symmetric,
    },
];

static CLIENT_CASES: LazyLock<HashMap<NatType, TestCase>> = LazyLock::new(|| {
    CASES[0..5]
        .iter()
        .map(|case| (case.nat_type, *case))
        .collect()
});

static SERVER_CASES: LazyLock<HashMap<NatType, TestCase>> = LazyLock::new(|| {
    CASES[5..10]
        .iter()
        .map(|case| (case.nat_type, *case))
        .collect()
});

macro_rules! test_punch_matrix {
    (async fn $test_name:ident = test_punch_case($client:expr, $server:expr) $($tt:tt)*) => {

        #[test]
        #[ignore]
        fn $test_name() {
            run(async move {
                let span = tracing::info_span!(
                    target: "dquic",
                    stringify!($test_name),
                    client = stringify!($client),
                    server = stringify!($server)
                );
                let _enter = span.enter();
                test_punch_case($client, $server).await
            });
        }

        test_punch_matrix!($($tt)*);
    };
    () => {}
}

/*
    // in host:
    sudo docker buildx build -f qtraversal/tools/dockerfile -t dquic-traversal-test:latest .
    sudo docker run -it --rm --privileged -v .:/dquic dquic-traversal-test:latest

    // in contrainer:
    cd /dquic && ./qtraversal/tools/run_stun.sh
    ip netns exec nsa cargo test --test traversal -- --include-ignored --nocapture
*/

test_punch_matrix! {
    async fn test_punch_full_cone_to_full_cone = test_punch_case(NatType::FullCone, NatType::FullCone)
    async fn test_punch_full_cone_to_restricted_cone = test_punch_case(NatType::FullCone, NatType::RestrictedCone)
    async fn test_punch_full_cone_to_port_restricted = test_punch_case(NatType::FullCone, NatType::RestrictedPort)
    async fn test_punch_full_cone_to_dynamic = test_punch_case(NatType::FullCone, NatType::Dynamic)
    async fn test_punch_full_cone_to_symmetric = test_punch_case(NatType::FullCone, NatType::Symmetric)
    async fn test_punch_restricted_cone_to_full_cone = test_punch_case(NatType::RestrictedCone, NatType::FullCone)
    async fn test_punch_restricted_cone_to_restricted_cone = test_punch_case(NatType::RestrictedCone, NatType::RestrictedCone)
    async fn test_punch_restricted_cone_to_port_restricted = test_punch_case(NatType::RestrictedCone, NatType::RestrictedPort)
    async fn test_punch_restricted_cone_to_dynamic = test_punch_case(NatType::RestrictedCone, NatType::Dynamic)
    async fn test_punch_restricted_cone_to_symmetric = test_punch_case(NatType::RestrictedCone, NatType::Symmetric)
    async fn test_punch_port_restricted_to_full_cone = test_punch_case(NatType::RestrictedPort, NatType::FullCone)
    async fn test_punch_port_restricted_to_restricted_cone = test_punch_case(NatType::RestrictedPort, NatType::RestrictedCone)
    async fn test_punch_port_restricted_to_port_restricted = test_punch_case(NatType::RestrictedPort, NatType::RestrictedPort)
    async fn test_punch_port_restricted_to_dynamic = test_punch_case(NatType::RestrictedPort, NatType::Dynamic)
    async fn test_punch_port_restricted_to_symmetric = test_punch_case(NatType::RestrictedPort, NatType::Symmetric)
    async fn test_punch_dynamic_to_full_cone = test_punch_case(NatType::Dynamic, NatType::FullCone)
    async fn test_punch_dynamic_to_restricted_cone = test_punch_case(NatType::Dynamic, NatType::RestrictedCone)
    async fn test_punch_dynamic_to_port_restricted = test_punch_case(NatType::Dynamic, NatType::RestrictedPort)
    async fn test_punch_dynamic_to_dynamic = test_punch_case(NatType::Dynamic, NatType::Dynamic)
    async fn test_punch_dynamic_to_symmetric = test_punch_case(NatType::Dynamic, NatType::Symmetric)
    async fn test_punch_symmetric_to_full_cone = test_punch_case(NatType::Symmetric, NatType::FullCone)
    async fn test_punch_symmetric_to_restricted_cone = test_punch_case(NatType::Symmetric, NatType::RestrictedCone)
    async fn test_punch_symmetric_to_port_restricted = test_punch_case(NatType::Symmetric, NatType::RestrictedPort)
    async fn test_punch_symmetric_to_dynamic = test_punch_case(NatType::Symmetric, NatType::Dynamic)
    async fn test_punch_symmetric_to_symmetric = test_punch_case(NatType::Symmetric, NatType::Symmetric)
}

async fn launch_stun_test_server(server_case: TestCase) -> Arc<QuicListeners> {
    let server_addr: SocketAddr = server_case.bind_addr.parse().unwrap();
    let local_endpoints = Arc::new(LocalEndpoints::new());
    let listeners = QuicListeners::builder()
        .with_parameters(server_parameters())
        .without_client_cert_verifier()
        .with_stun(STUN_SERVERS)
        .with_router(Arc::default())
        .with_local_endpoints(local_endpoints)
        .with_qlog(qlogger())
        .listen(1000)
        .unwrap();

    listeners
        .add_server("localhost", SERVER_CERT, SERVER_KEY, [server_addr], None)
        .await
        .unwrap();

    info!(target: "dquic", %server_addr, "server listening");

    tokio::spawn(serve_echo(listeners.clone()));

    listeners
}

static SERVERS: LazyLock<HashMap<NatType, Shared<BoxFuture<Arc<QuicListeners>>>>> =
    LazyLock::new(|| {
        SERVER_CASES
            .values()
            .map(|case| {
                let server = launch_stun_test_server(*case).boxed().shared();
                (case.nat_type, server)
            })
            .collect()
    });

async fn launch_stun_test_client(client_case: TestCase) -> Arc<QuicClient> {
    let client_addr: SocketAddr = client_case.bind_addr.parse().unwrap();

    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(CA_CERT.to_certificate());

    let local_endpoints = Arc::new(LocalEndpoints::new());
    let client = QuicClient::builder()
        .with_root_certificates(roots)
        .without_cert()
        .enable_sslkeylog()
        .with_parameters(client_parameters())
        .with_stun(STUN_SERVERS)
        .with_local_endpoints(local_endpoints)
        .bind([client_addr])
        .await
        .with_qlog(qlogger())
        .build();

    info!(target: "dquic", %client_addr, "client bound");

    Arc::new(client)
}

static CLIENTS: LazyLock<HashMap<NatType, Shared<BoxFuture<Arc<QuicClient>>>>> =
    LazyLock::new(|| {
        CLIENT_CASES
            .values()
            .map(|case| {
                let client = launch_stun_test_client(*case).boxed().shared();
                (case.nat_type, client)
            })
            .collect()
    });

async fn test_punch_case(client_nat: NatType, server_nat: NatType) {
    let client_case = CLIENT_CASES[&client_nat];
    let server_case = SERVER_CASES[&server_nat];

    info!(target: "dquic", ?client_nat, ?server_nat, "testing punch case");

    if client_nat == NatType::Dynamic || server_nat == NatType::Dynamic {
        warn!(target: "dquic", "skipping Dynamic NAT test case");
        // TODO: Dynamic NAT 模拟有问题
        return;
    }
    if client_nat == NatType::Symmetric && server_nat == NatType::Symmetric {
        warn!(target: "dquic", "skipping Symmetric NAT to Symmetric NAT test case");
        // Symmetric NAT 互穿不通
        return;
    }

    let _server = SERVERS[&server_nat].clone().await;
    let server_iface = InterfaceManager::global()
        .borrow(&(server_case.bind_addr.parse::<SocketAddr>().unwrap().into()))
        .unwrap();

    let server_ep = get_stun_data(server_iface).await[0].0;
    launch_client(client_case, server_ep).await;
}

const STUN_DATA_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const STUN_DATA_POLL_INTERVAL: Duration = Duration::from_millis(10);

async fn get_stun_data(server_iface: dquic::qinterface::Interface) -> Vec<(EndpointAddr, NatType)> {
    let deadline = tokio::time::Instant::now() + STUN_DATA_WAIT_TIMEOUT;

    loop {
        let mut outer_addresses = server_iface
            .with_component(|clients: &StunClientsComponent| {
                clients.with_clients(|clients| {
                    // workaround. clippy issue: https://github.com/rust-lang/rust-clippy/issues/16428
                    #[allow(clippy::redundant_iter_cloned)]
                    clients
                        .values()
                        .cloned()
                        .map(|client| async move {
                            let agent = client.agent_addr();
                            let outer = client.outer_addr().await?;
                            let ep = EndpointAddr::with_agent(agent, outer);
                            let nat_type = client.nat_type().await?;
                            io::Result::Ok((ep, nat_type))
                        })
                        .collect::<JoinSet<_>>()
                })
            })
            .expect("interface rebinded too quickly")
            .expect("traversal components missing");
        let mut datas = vec![];

        while let Some(join_result) = outer_addresses.join_next().await {
            let result = join_result.expect("detect panic");
            let data = result.expect("detect outer addr or nat type failed");
            datas.push(data);
        }

        if !datas.is_empty() {
            return datas;
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            panic!(
                "timed out waiting for STUN endpoint discovery on {}",
                server_iface.bind_uri()
            );
        }

        tokio::time::sleep_until(std::cmp::min(now + STUN_DATA_POLL_INTERVAL, deadline)).await;
    }
}

async fn launch_client(client_case: TestCase, server_ep: EndpointAddr) {
    let client = CLIENTS[&client_case.nat_type].clone().await;

    get_stun_data(
        InterfaceManager::global()
            .borrow(&client_case.bind_addr.parse::<SocketAddr>().unwrap().into())
            .unwrap(),
    )
    .await;

    // 不会进行绑定，不会出错
    let connection = client
        .connected_to_with_source("localhost", [(Source::System, server_ep)])
        .await
        .unwrap();
    let odcid = connection.origin_dcid().expect("connection failed");
    tracing::info!(target: "dquic", %odcid, "connected to server");
    let test_data = Arc::new(TEST_DATA.to_vec());

    // 循环检查直连路径，每秒检查一次
    // 如果没有直连路径，执行 echo 测试确保连接正常
    // 总超时由 run() 函数的 60s 超时控制
    loop {
        // 检查是否有直连路径
        let paths = connection
            .path_context()
            .expect("connection failed")
            .paths::<Vec<_>>()
            .into_iter()
            .map(|(p, _)| p)
            .collect::<Vec<_>>();

        let has_direct = paths
            .iter()
            .any(|pathway| matches!(pathway.local(), EndpointAddr::Direct { .. }));

        if has_direct {
            tracing::info!(target: "dquic", ?paths, "direct path established");
            return;
        }

        // 没有直连路径，执行 echo 测试确保连接正常
        tracing::debug!(target: "dquic", "no direct path yet, verifying connection with echo test");
        send_and_verify_echo(&connection, &test_data)
            .await
            .expect("echo test failed");

        // 等待 1 秒后再次检查
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[test]
fn test_knock_ttl_is_1_in_tests() {
    assert_eq!(dquic::qtraversal::punch::puncher::KNOCK_TTL, 1);
}
