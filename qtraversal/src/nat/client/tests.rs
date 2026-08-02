use std::{
    fmt,
    sync::atomic::{AtomicUsize, Ordering},
};

use futures::{FutureExt, StreamExt, stream};
use qresolve::{ResolveFuture, Source};

use super::*;

#[derive(Debug, Clone)]
enum LookupResult {
    Records(Vec<EndpointAddr>),
    Error,
}

#[derive(Debug, Clone)]
struct TestResolver {
    lookups: Arc<AtomicUsize>,
    result: LookupResult,
}

impl TestResolver {
    fn new(result: LookupResult) -> Self {
        Self {
            lookups: Arc::new(AtomicUsize::new(0)),
            result,
        }
    }

    fn lookup_count(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

impl fmt::Display for TestResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("test resolver")
    }
}

impl Resolve for TestResolver {
    fn lookup<'l>(&'l self, _name: &'l str) -> ResolveFuture<'l> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let result = self.result.clone();
        async move {
            match result {
                LookupResult::Records(endpoints) => Ok(stream::iter(
                    endpoints
                        .into_iter()
                        .map(|endpoint| (Source::System, endpoint)),
                )
                .boxed()),
                LookupResult::Error => Err(io::Error::other("lookup failed")),
            }
        }
        .boxed()
    }
}

fn direct(addr: &str) -> EndpointAddr {
    EndpointAddr::direct(addr.parse().unwrap())
}

#[tokio::test]
async fn single_dns_result_is_a_complete_snapshot() {
    let resolver = TestResolver::new(LookupResult::Records(vec![direct("192.0.2.1:20004")]));

    let agents = resolve_stun_agents(&resolver, "stun.example:20004", Family::V4)
        .await
        .unwrap();

    assert_eq!(agents, vec!["192.0.2.1:20004".parse().unwrap()]);
    assert_eq!(resolver.lookup_count(), 1);
}

#[tokio::test]
async fn dns_snapshot_is_filtered_deduplicated_and_bounded() {
    let resolver = TestResolver::new(LookupResult::Records(vec![
        direct("192.0.2.1:20004"),
        direct("192.0.2.1:20004"),
        direct("[2001:db8::1]:20004"),
        direct("192.0.2.2:20004"),
        direct("192.0.2.3:20004"),
        direct("192.0.2.4:20004"),
    ]));

    let agents = resolve_stun_agents(&resolver, "stun.example:20004", Family::V4)
        .await
        .unwrap();

    assert_eq!(
        agents,
        vec![
            "192.0.2.1:20004".parse().unwrap(),
            "192.0.2.2:20004".parse().unwrap(),
            "192.0.2.3:20004".parse().unwrap(),
        ]
    );
    assert_eq!(resolver.lookup_count(), 1);
}

#[tokio::test]
async fn dns_failure_is_reported_to_discovery_loop() {
    let resolver = TestResolver::new(LookupResult::Error);

    let result = resolve_stun_agents(&resolver, "stun.example:20004", Family::V4).await;

    assert!(result.is_err());
    assert_eq!(resolver.lookup_count(), 1);
}

#[tokio::test]
async fn stun_discovery_is_dormant_when_local_address_is_unavailable() {
    use qinterface::io::handy::unsupported::Unsupported;

    let agent = "192.0.2.1:20004".parse().unwrap();
    let iface = Arc::new(Unsupported::bind("inet://0.0.0.0:0".into()));
    assert!(iface.bound_addr().is_err());
    let resolver = TestResolver::new(LookupResult::Error);
    let clients = StunClients::new(
        iface,
        StunRouter::new(),
        Arc::new(resolver.clone()),
        "stun.example:20004",
        std::iter::once(agent),
        None,
    );

    assert!(clients.with_clients(|clients| clients.is_empty()));
    tokio::task::yield_now().await;
    assert_eq!(resolver.lookup_count(), 0);
}

#[tokio::test]
async fn existing_clients_are_refreshed_from_dns() {
    use qinterface::io::{ProductIO, handy::DEFAULT_IO_FACTORY};

    let old_agent = "192.0.2.1:20004".parse().unwrap();
    let new_agent = "192.0.2.2:20004".parse().unwrap();
    let iface: Arc<dyn IO> = Arc::from(DEFAULT_IO_FACTORY.bind("inet://127.0.0.1:0".into()));
    assert!(iface.bound_addr().is_ok());
    let resolver = TestResolver::new(LookupResult::Records(vec![EndpointAddr::direct(new_agent)]));
    let clients = StunClients::new(
        iface,
        StunRouter::new(),
        Arc::new(resolver.clone()),
        "stun.example:20004",
        std::iter::once(old_agent),
        None,
    );

    assert!(clients.with_clients(|clients| clients.contains_key(&old_agent)));
    tokio::time::timeout(Duration::from_secs(3), async {
        while !clients.with_clients(|clients| clients.contains_key(&new_agent)) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("refreshed STUN agent was not installed");

    assert_eq!(resolver.lookup_count(), 1);
    clients.with_clients(|clients| {
        assert_eq!(clients.len(), 1);
        assert!(!clients.contains_key(&old_agent));
    });
}

#[test]
fn stun_probe_failure_backoff_is_bounded() {
    let mut retry_interval = STUN_PROBE_RETRY_INITIAL;

    let delays = (0..11)
        .map(|_| stun_probe_delay(false, &mut retry_interval))
        .collect::<Vec<_>>();

    assert_eq!(
        delays,
        [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300].map(Duration::from_secs)
    );
    assert_eq!(retry_interval, STUN_PROBE_RETRY_MAX);
}

#[test]
fn stun_probe_success_resets_backoff() {
    let mut retry_interval = STUN_PROBE_RETRY_INITIAL;
    assert_eq!(
        stun_probe_delay(false, &mut retry_interval),
        Duration::from_secs(1)
    );
    assert_eq!(
        stun_probe_delay(false, &mut retry_interval),
        Duration::from_secs(2)
    );

    assert_eq!(
        stun_probe_delay(true, &mut retry_interval),
        NAT_MAPPING_REFRESH_INTERVAL
    );
    assert_eq!(retry_interval, STUN_PROBE_RETRY_INITIAL);
    assert_eq!(
        stun_probe_delay(false, &mut retry_interval),
        Duration::from_secs(1)
    );
}

#[test]
fn recent_stun_endpoint_is_retained_during_failure_grace_period() {
    let last_success = Instant::now();

    assert!(retain_last_stun_endpoint(
        Some(last_success),
        last_success + STUN_ENDPOINT_FAILURE_GRACE_PERIOD - Duration::from_millis(1),
    ));
    assert!(!retain_last_stun_endpoint(
        Some(last_success),
        last_success + STUN_ENDPOINT_FAILURE_GRACE_PERIOD,
    ));
    assert!(!retain_last_stun_endpoint(
        None,
        last_success + Duration::from_secs(1),
    ));
}

#[test]
fn discovery_retry_backoff_is_bounded() {
    let mut retry_interval = STUN_DISCOVERY_RETRY_INITIAL;

    let delays = (0..11)
        .map(|_| retry_delay(&mut retry_interval, STUN_DISCOVERY_RETRY_MAX))
        .collect::<Vec<_>>();

    assert_eq!(
        delays,
        [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300].map(Duration::from_secs)
    );
    assert_eq!(retry_interval, STUN_DISCOVERY_RETRY_MAX);
}
