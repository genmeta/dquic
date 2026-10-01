use std::{fmt, sync::Arc};

use futures::{FutureExt, StreamExt, stream};
use qresolve::{EndpointAddr, Family, Resolve, ResolveFuture, Resolver, Source};

#[derive(Debug)]
struct ExtraResolver;

impl fmt::Display for ExtraResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("extra resolver")
    }
}

impl Resolve for ExtraResolver {
    fn lookup<'l>(
        &'l self,
        hostname: &'l str,
        servname: &'l str,
        family: Option<Family>,
    ) -> ResolveFuture<'l> {
        async move {
            assert_eq!(hostname, "127.0.0.1");
            assert_eq!(servname, "8443");
            assert_eq!(family, Some(Family::V4));
            Ok(stream::iter([(
                Source::Dht,
                EndpointAddr::mediate(
                    "198.51.100.1:3478".parse().unwrap(),
                    "203.0.113.1:8443".parse().unwrap(),
                ),
            )])
            .boxed())
        }
        .boxed()
    }
}

// Keep global configuration checks in one test in this separate test process.
#[test]
fn adding_a_resolver_keeps_system_and_preserves_existing_snapshots() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let snapshot = Resolver::get();
            let pending = snapshot.lookup("127.0.0.1", "8443", Some(Family::V4));
            Resolver::add(Arc::new(ExtraResolver));

            let records = pending.await.unwrap().collect::<Vec<_>>().await;
            assert!(!records.is_empty());
            assert!(records.iter().all(|(source, endpoint)| {
                *source == Source::System
                    && *endpoint == EndpointAddr::direct("127.0.0.1:8443".parse().unwrap())
            }));

            let records = Resolver::get()
                .lookup("127.0.0.1", "8443", Some(Family::V4))
                .await
                .unwrap()
                .collect::<Vec<_>>()
                .await;
            assert!(records.iter().any(|(source, _)| *source == Source::System));
            assert!(records.iter().any(|(source, _)| *source == Source::Dht));
        });
}
