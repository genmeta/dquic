use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
};

use futures::{FutureExt, StreamExt, stream, task::noop_waker_ref};
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
    expected_servname: &'static str,
}

impl TestResolver {
    fn new(result: LookupResult) -> Self {
        Self {
            lookups: Arc::new(AtomicUsize::new(0)),
            result,
            expected_servname: "20004",
        }
    }

    fn with_expected_servname(mut self, expected_servname: &'static str) -> Self {
        self.expected_servname = expected_servname;
        self
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
    fn lookup<'l>(
        &'l self,
        hostname: &'l str,
        servname: &'l str,
        family: Option<Family>,
    ) -> ResolveFuture<'l> {
        assert_eq!(hostname, "stun.example");
        assert_eq!(servname, self.expected_servname);
        assert_eq!(family, Some(Family::V4));
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
async fn single_dns_result_is_selected() {
    let resolver = TestResolver::new(LookupResult::Records(vec![direct("192.0.2.1:20004")]));

    let agent = resolve_stun_agent(&resolver, "stun.example:20004", Family::V4, None)
        .await
        .unwrap();

    assert_eq!(agent, Some("192.0.2.1:20004".parse().unwrap()));
    assert_eq!(resolver.lookup_count(), 1);
}

#[tokio::test]
async fn missing_stun_service_uses_the_default() {
    let resolver = TestResolver::new(LookupResult::Records(vec![direct("192.0.2.1:443")]))
        .with_expected_servname("");

    let agent = resolve_stun_agent(&resolver, "stun.example", Family::V4, None)
        .await
        .unwrap();

    assert_eq!(agent, Some("192.0.2.1:443".parse().unwrap()));
    assert_eq!(resolver.lookup_count(), 1);
}

#[tokio::test]
async fn dns_lookup_selects_first_compatible_agent() {
    let resolver = TestResolver::new(LookupResult::Records(vec![
        direct("[2001:db8::1]:20004"),
        direct("192.0.2.1:20004"),
        direct("192.0.2.2:20004"),
    ]));

    let agent = resolve_stun_agent(&resolver, "stun.example:20004", Family::V4, None)
        .await
        .unwrap();

    assert_eq!(agent, Some("192.0.2.1:20004".parse().unwrap()));
    assert_eq!(resolver.lookup_count(), 1);
}

#[tokio::test]
async fn dns_failure_is_reported_to_discovery_loop() {
    let resolver = TestResolver::new(LookupResult::Error);

    let result = resolve_stun_agent(&resolver, "stun.example:20004", Family::V4, None).await;

    assert!(result.is_err());
    assert_eq!(resolver.lookup_count(), 1);
}

#[tokio::test]
async fn dns_lookup_skips_the_failed_active_agent() {
    let failed_agent = "192.0.2.1:20004".parse().unwrap();
    let replacement_agent = "192.0.2.2:20004".parse().unwrap();
    let resolver = TestResolver::new(LookupResult::Records(vec![
        EndpointAddr::direct(failed_agent),
        EndpointAddr::direct(replacement_agent),
    ]));

    let agent = resolve_stun_agent(
        &resolver,
        "stun.example:20004",
        Family::V4,
        Some(failed_agent),
    )
    .await
    .unwrap();

    assert_eq!(agent, Some(replacement_agent));
    assert_eq!(resolver.lookup_count(), 1);
}

#[tokio::test]
async fn dns_lookup_returns_none_when_only_the_failed_agent_remains() {
    let failed_agent = "192.0.2.1:20004".parse().unwrap();
    let resolver = TestResolver::new(LookupResult::Records(vec![
        EndpointAddr::direct(failed_agent),
        EndpointAddr::direct(failed_agent),
    ]));

    let agent = resolve_stun_agent(
        &resolver,
        "stun.example:20004",
        Family::V4,
        Some(failed_agent),
    )
    .await
    .unwrap();

    assert_eq!(agent, None);
    assert_eq!(resolver.lookup_count(), 1);
}

#[tokio::test]
async fn stun_discovery_is_dormant_when_local_address_is_unavailable() {
    use qinterface::io::handy::unsupported::Unsupported;

    let agent = "192.0.2.1:20004".parse().unwrap();
    let iface = Arc::new(Unsupported::bind("inet://0.0.0.0:0".into()));
    assert!(iface.bound_addr().is_err());
    let resolver = TestResolver::new(LookupResult::Error);
    let component = StunClientComponent::new(
        iface,
        StunRouter::new(),
        Arc::new(resolver.clone()),
        "stun.example:20004",
        Some(agent),
        None,
    );

    assert!(component.with_client(|client| client.is_none()));
    tokio::task::yield_now().await;
    assert_eq!(resolver.lookup_count(), 0);
}

#[tokio::test]
async fn known_agent_is_installed_immediately() {
    use qinterface::io::{ProductIO, handy::DEFAULT_IO_FACTORY};

    let first_agent = "192.0.2.1:20004".parse().unwrap();
    let iface: Arc<dyn IO> = Arc::from(DEFAULT_IO_FACTORY.bind("inet://127.0.0.1:0".into()));
    let component = StunClientComponent::new(
        iface,
        StunRouter::new(),
        Arc::new(TestResolver::new(LookupResult::Error)),
        "stun.example:20004",
        Some(first_agent),
        None,
    );

    assert!(
        component.with_client(|client| {
            client.is_some_and(|client| client.agent_addr() == first_agent)
        })
    );
}

#[tokio::test]
async fn failed_client_is_replaced_from_a_fresh_dns_lookup() {
    use qinterface::io::{ProductIO, handy::DEFAULT_IO_FACTORY};

    let old_agent = "192.0.2.1:20004".parse().unwrap();
    let new_agent = "192.0.2.2:20004".parse().unwrap();
    let iface: Arc<dyn IO> = Arc::from(DEFAULT_IO_FACTORY.bind("inet://127.0.0.1:0".into()));
    assert!(iface.bound_addr().is_ok());
    let resolver = TestResolver::new(LookupResult::Records(vec![
        EndpointAddr::direct(old_agent),
        EndpointAddr::direct(new_agent),
    ]));
    let component = StunClientComponent::new(
        iface,
        StunRouter::new(),
        Arc::new(resolver.clone()),
        "stun.example:20004",
        Some(old_agent),
        None,
    );

    assert!(
        component.with_client(|client| {
            client.is_some_and(|client| client.agent_addr() == old_agent)
        })
    );
    component.with_client(|client| {
        client
            .expect("old STUN client missing")
            .refresh_agent
            .notify_one();
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while !component
            .with_client(|client| client.is_some_and(|client| client.agent_addr() == new_agent))
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("refreshed STUN agent was not installed");

    assert!(resolver.lookup_count() >= 1);
    assert!(
        component.with_client(|client| {
            client.is_some_and(|client| client.agent_addr() == new_agent)
        })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_close_stays_pending_until_all_tasks_exit() {
    use qinterface::io::{ProductIO, handy::DEFAULT_IO_FACTORY};

    let iface: Arc<dyn IO> = Arc::from(DEFAULT_IO_FACTORY.bind("inet://127.0.0.1:0".into()));
    let client = StunClient::new(
        iface,
        StunRouter::new(),
        "192.0.2.1:20004".parse().unwrap(),
        None,
    );

    let (task_started_tx, task_started_rx) = mpsc::channel();
    let (release_task_tx, release_task_rx) = mpsc::channel();
    client.lock_tasks().spawn(async move {
        task_started_tx.send(()).unwrap();
        let _ = release_task_rx.recv();
    });
    task_started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("blocking STUN task did not start");

    let mut cx = Context::from_waker(noop_waker_ref());
    assert!(client.poll_close(&mut cx).is_pending());
    assert!(client.poll_close(&mut cx).is_pending());

    release_task_tx.send(()).unwrap();
    tokio::time::timeout(
        Duration::from_secs(3),
        core::future::poll_fn(|cx| client.poll_close(cx)),
    )
    .await
    .expect("STUN client did not finish closing");
    assert!(client.lock_tasks().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inactive_generation_cannot_finish_an_inflight_replacement() {
    use qinterface::io::{ProductIO, handy::DEFAULT_IO_FACTORY};

    let old_agent = "192.0.2.1:20004".parse().unwrap();
    let new_agent = "192.0.2.2:20004".parse().unwrap();
    let iface: Arc<dyn IO> = Arc::from(DEFAULT_IO_FACTORY.bind("inet://127.0.0.1:0".into()));
    let old_client = StunClient::new(iface, StunRouter::new(), old_agent, None);

    let (task_started_tx, task_started_rx) = mpsc::channel();
    let (release_task_tx, release_task_rx) = mpsc::channel();
    old_client.lock_tasks().spawn(async move {
        task_started_tx.send(()).unwrap();
        let _ = release_task_rx.recv();
    });
    task_started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("blocking STUN task did not start");

    let client = Arc::new(Mutex::new(Some(old_client)));
    let active = Arc::new(AtomicBool::new(true));
    let replacement = tokio::spawn({
        let client = client.clone();
        let active = active.clone();
        async move {
            replace_stun_client(&client, &active, new_agent, |_| {
                panic!("inactive generation installed a replacement client")
            })
            .await
        }
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !client
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .closing
            .load(Ordering::SeqCst)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replacement did not begin closing the old client");

    active.store(false, Ordering::SeqCst);
    release_task_tx.send(()).unwrap();
    let replaced = tokio::time::timeout(Duration::from_secs(3), replacement)
        .await
        .expect("replacement did not finish")
        .expect("replacement task panicked");

    assert!(!replaced);
    assert_eq!(
        client.lock().unwrap().as_ref().unwrap().agent_addr(),
        old_agent
    );
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
