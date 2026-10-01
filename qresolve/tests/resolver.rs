use std::{fmt, sync::Arc};

use futures::{FutureExt, StreamExt, stream};
use qresolve::{EndpointAddr, Family, Resolve, ResolveFuture, Resolver, Source, SystemResolver};

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
fn registry_starts_empty_and_only_uses_explicit_sources() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let snapshot = Resolver::get();
            let pending = snapshot.lookup("127.0.0.1", "8443", Some(Family::V4));
            Resolver::add(Arc::new(ExtraResolver));

            assert_eq!(
                pending.await.err().unwrap().kind(),
                std::io::ErrorKind::NotFound
            );
            let mock_only = Resolver::get();
            Resolver::add(Arc::new(SystemResolver));
            let records = mock_only
                .lookup("127.0.0.1", "8443", Some(Family::V4))
                .await
                .unwrap()
                .collect::<Vec<_>>()
                .await;
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].0, Source::Dht);

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
