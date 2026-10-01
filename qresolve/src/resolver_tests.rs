use std::{fmt, sync::Mutex};

use futures::{
    channel::{mpsc, oneshot},
    executor::block_on,
};

use super::*;

#[derive(Debug)]
struct ControlledResolver(Mutex<Option<oneshot::Receiver<ResolveResult>>>);

impl Display for ControlledResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("controlled resolver")
    }
}

impl Resolve for ControlledResolver {
    fn lookup<'l>(
        &'l self,
        hostname: &'l str,
        servname: &'l str,
        family: Option<Family>,
    ) -> ResolveFuture<'l> {
        assert_eq!(hostname, "example.test");
        assert_eq!(servname, "8443");
        assert_eq!(family, Some(Family::V4));
        let ready = self.0.lock().unwrap().take().unwrap();
        async move { ready.await.unwrap() }.boxed()
    }
}

fn controlled() -> (Arc<dyn Resolve>, oneshot::Sender<ResolveResult>) {
    let (sender, receiver) = oneshot::channel();
    (
        Arc::new(ControlledResolver(Mutex::new(Some(receiver)))),
        sender,
    )
}

fn record(source: Source, port: u16) -> Record {
    (source, EndpointAddr::direct(([192, 0, 2, 1], port).into()))
}

#[test]
fn merges_streams_while_other_lookups_and_streams_are_pending() {
    block_on(async {
        let (slow, release_slow) = controlled();
        let (fast, release_fast) = controlled();
        let resolver = Resolver {
            resolvers: vec![slow, fast],
        };
        let mut lookup = resolver.lookup("example.test", "8443", Some(Family::V4));
        assert!(futures::poll!(&mut lookup).is_pending());

        let (fast_tx, fast_rx) = mpsc::unbounded();
        assert!(release_fast.send(Ok(fast_rx.boxed())).is_ok());
        let mut records = match futures::poll!(&mut lookup) {
            std::task::Poll::Ready(Ok(records)) => records,
            _ => panic!("a slow lookup must not block a ready stream"),
        };
        drop(lookup);
        drop(resolver);
        let first = record(Source::Dht, 1);
        fast_tx.unbounded_send(first.clone()).unwrap();
        assert_eq!(records.next().await, Some(first));

        let second = record(Source::System, 2);
        assert!(
            release_slow
                .send(Ok(stream::iter([second.clone()]).boxed()))
                .is_ok()
        );
        // The first stream is still open but idle; the newly ready one must progress.
        assert_eq!(records.next().await, Some(second));
        let third = record(Source::Dht, 3);
        fast_tx.unbounded_send(third.clone()).unwrap();
        drop(fast_tx);
        assert_eq!(records.next().await, Some(third));
        assert_eq!(records.next().await, None);
    });
}

#[test]
fn failed_sources_before_and_after_success_do_not_stop_results() {
    block_on(async {
        let (early, fail_early) = controlled();
        let (success, release) = controlled();
        let (late, fail_late) = controlled();
        let resolver = Resolver {
            resolvers: vec![early, success, late],
        };
        let mut lookup = resolver.lookup("example.test", "8443", Some(Family::V4));
        assert!(fail_early.send(Err(io::ErrorKind::NotFound.into())).is_ok());
        assert!(futures::poll!(&mut lookup).is_pending());
        let expected = record(Source::Dht, 1);
        assert!(
            release
                .send(Ok(stream::iter([expected.clone()]).boxed()))
                .is_ok()
        );
        let mut records = lookup.await.unwrap();
        assert!(fail_late.send(Err(io::ErrorKind::TimedOut.into())).is_ok());
        assert_eq!(records.next().await, Some(expected));
        assert_eq!(records.next().await, None);
    });
}

#[test]
fn all_failed_lookups_return_the_last_error() {
    block_on(async {
        let (first, fail_first) = controlled();
        let (last, fail_last) = controlled();
        let resolver = Resolver {
            resolvers: vec![first, last],
        };
        let mut lookup = resolver.lookup("example.test", "8443", Some(Family::V4));
        assert!(fail_first.send(Err(io::ErrorKind::NotFound.into())).is_ok());
        assert!(futures::poll!(&mut lookup).is_pending());
        assert!(fail_last.send(Err(io::ErrorKind::TimedOut.into())).is_ok());
        match lookup.await {
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::TimedOut),
            Ok(_) => panic!("all sources failed"),
        }
    });
}

#[test]
fn an_empty_successful_stream_is_not_a_lookup_error() {
    block_on(async {
        let (success, release) = controlled();
        let (failed, fail) = controlled();
        let resolver = Resolver {
            resolvers: vec![success, failed],
        };
        assert!(release.send(Ok(stream::empty().boxed())).is_ok());
        assert!(fail.send(Err(io::ErrorKind::NotFound.into())).is_ok());
        let mut records = resolver
            .lookup("example.test", "8443", Some(Family::V4))
            .await
            .unwrap();
        assert_eq!(records.next().await, None);
    });
}

#[test]
fn dropping_aggregate_operations_cancels_children() {
    block_on(async {
        let (pending, sender) = controlled();
        let resolver = Resolver {
            resolvers: vec![pending],
        };
        let mut lookup = resolver.lookup("example.test", "8443", Some(Family::V4));
        assert!(futures::poll!(&mut lookup).is_pending());
        drop(lookup);
        assert!(sender.is_canceled());

        let (success, release) = controlled();
        let (pending, sender) = controlled();
        let resolver = Resolver {
            resolvers: vec![success, pending],
        };
        let mut lookup = resolver.lookup("example.test", "8443", Some(Family::V4));
        assert!(futures::poll!(&mut lookup).is_pending());
        let (stream_tx, stream_rx) = mpsc::unbounded();
        assert!(release.send(Ok(stream_rx.boxed())).is_ok());
        let records = lookup.await.unwrap();
        drop(records);
        assert!(sender.is_canceled());
        assert!(stream_tx.is_closed());
    });
}
