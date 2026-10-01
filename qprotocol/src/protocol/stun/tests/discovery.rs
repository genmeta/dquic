use std::{
    fmt,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use futures::{FutureExt, stream};
use qresolve::{Family, ResolveFuture, Source};
use tokio::sync::Semaphore;

use super::*;

#[derive(Debug)]
struct Resolver {
    calls: AtomicUsize,
    gate: Semaphore,
    endpoints: Vec<EndpointAddr>,
    fail: bool,
}

impl fmt::Display for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("STUN test resolver")
    }
}

impl Resolve for Resolver {
    fn lookup<'a>(
        &'a self,
        hostname: &'a str,
        service: &'a str,
        family: Option<Family>,
    ) -> ResolveFuture<'a> {
        async move {
            assert_eq!(hostname, STUN_SERVER);
            assert_eq!(service, STUN_PORT);
            assert_eq!(family, None);
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.gate.acquire().await.unwrap().forget();
            if self.fail {
                return Err(io::Error::new(io::ErrorKind::NotFound, "DNS lookup failed"));
            }
            Ok(stream::iter(
                self.endpoints
                    .clone()
                    .into_iter()
                    .map(|ep| (Source::System, ep)),
            )
            .boxed())
        }
        .boxed()
    }
}

#[tokio::test]
async fn startup_lookup_is_shared_and_survives_cancelled_waiters() {
    let port = STUN_PORT.parse().unwrap();
    let v4 = SocketAddr::new("192.0.2.1".parse().unwrap(), port);
    let v6 = SocketAddr::new("2001:db8::1".parse().unwrap(), port);
    let resolver = Arc::new(Resolver {
        calls: AtomicUsize::new(0),
        gate: Semaphore::new(0),
        endpoints: vec![
            v4.into(),
            v6.into(),
            v4.into(),
            EndpointAddr::mediate(v4, v6),
        ],
        fail: false,
    });
    let lookup = resolve_stun_servers(resolver.clone());
    assert!(lookup.clone().now_or_never().is_none());
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    // A new socket or consumer must neither restart nor cancel startup DNS.
    resolver.gate.add_permits(1);
    let (first, second) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(lookup.clone(), lookup.clone())
    })
    .await
    .unwrap();
    let first = first.unwrap();
    assert_eq!(&*first, &[v4, v6]);
    assert!(Arc::ptr_eq(&first, &second.unwrap()));
    assert!(Arc::ptr_eq(&first, &lookup.clone().await.unwrap()));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn empty_and_failed_startup_lookups_are_cached_without_retry() {
    for fail in [false, true] {
        let resolver = Arc::new(Resolver {
            calls: AtomicUsize::new(0),
            gate: Semaphore::new(1),
            endpoints: Vec::new(),
            fail,
        });
        let lookup = resolve_stun_servers(resolver.clone());
        for _ in 0..3 {
            let result = tokio::time::timeout(Duration::from_secs(1), lookup.clone())
                .await
                .unwrap();
            if fail {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
            } else {
                assert!(result.unwrap().is_empty());
            }
        }
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }
}
