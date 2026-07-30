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

    let agents = resolve_stun_agents(&resolver, "stun.example:20004", Family::V4).await;

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

    let agents = resolve_stun_agents(&resolver, "stun.example:20004", Family::V4).await;

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
async fn dns_failure_is_not_retried() {
    let resolver = TestResolver::new(LookupResult::Error);

    let agents = resolve_stun_agents(&resolver, "stun.example:20004", Family::V4).await;

    assert!(agents.is_empty());
    assert_eq!(resolver.lookup_count(), 1);
}
