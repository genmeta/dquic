use std::{
    future::Future,
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant},
};

use qbase::{cid::ConnectionId, net::route::Pathway, role::Role, time::heartbeat::ArcHeartbeat};
use qcongestion::Transport as _;
use qtransport::{
    Paths,
    path::{Datagram, Path},
};
use tokio::io::AsyncWriteExt;

use crate::common;

#[derive(Default)]
struct Counter(AtomicUsize);

impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn path(pathway: Pathway) -> (Arc<Paths>, Arc<Path>) {
    let paths = common::initial_paths(
        Role::Client,
        ConnectionId::from_slice(b"clientid"),
        ConnectionId::from_slice(b"original"),
        common::initial_keys(false),
    );
    let path = common::registered_path(
        &paths,
        Path::new(
            paths.cid_registry.remote.apply_dcid(),
            pathway,
            paths.progress.facts(),
            paths.spaces.clone(),
            paths.resenders.clone(),
            ArcHeartbeat::new(Duration::ZERO, Duration::ZERO),
            paths.terminator.clone(),
            paths.progress.clone(),
        ),
    );
    path.validation.exempt().unwrap();
    (paths, path)
}

#[tokio::test(start_paused = true)]
async fn ready_collection_consumes_source_notifications_without_scheduling_the_sender() {
    let (paths, path) = path(common::path_fixtures::pathway(38033));
    paths.progress.facts().quit_mp_replaying();
    let crypto = common::initial_space(&paths.spaces).crypto.clone();
    crypto.writer().write_all(b"first").await.unwrap();
    let count = Arc::new(Counter::default());
    let waker = Waker::from(count.clone());
    let mut datagrams = std::array::from_fn::<_, 2, _>(|_| Datagram::default());
    let mut frames = Vec::new();
    assert!(matches!(
        std::pin::pin!(path.collect(&mut datagrams, &mut frames)).poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Ok((1, _)))
    ));
    // The second datagram checked the now-empty source, but the whole collect is Ready.
    crypto.writer().write_all(b"second").await.unwrap();
    crypto.writer().write_all(b"third").await.unwrap();
    assert_eq!(count.0.load(Ordering::Relaxed), 0, "a running sender must consume source notifications without being scheduled");
    path.refresh(&mut datagrams, &mut frames);
    paths.del_path(&path);
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn repeated_pending_polls_keep_one_source_identity_and_path_removal_unregisters_it() {
    let (paths, path) = path(common::path_fixtures::pathway(38034));
    let count = Arc::new(Counter::default());
    let waker = Waker::from(count.clone());
    let mut datagrams = [Datagram::default()];
    let mut frames = Vec::new();
    let mut cx = Context::from_waker(&waker);
    assert!(std::pin::pin!(path.collect(&mut datagrams, &mut frames)).poll(&mut cx).is_pending());
    let references = Arc::strong_count(&path.send_waker);
    for _ in 0..64 {
        assert!(std::pin::pin!(path.collect(&mut datagrams, &mut frames)).poll(&mut cx).is_pending());
        assert_eq!(Arc::strong_count(&path.send_waker), references, "sources must replace the same path's subscription");
    }
    assert_eq!(count.0.load(Ordering::Relaxed), 0);
    assert!(paths.del_path(&path));
    let before = count.0.load(Ordering::Relaxed);
    common::initial_space(&paths.spaces).crypto.writer().write_all(b"unregistered").await.unwrap();
    path.cc.on_charged();
    path.wake_sender();
    assert_eq!(count.0.load(Ordering::Relaxed), before);
    assert_eq!(Arc::strong_count(&path.send_waker), 1);
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn data_budget_and_external_notifications_consume_one_pending_registration() {
    let (paths, path) = path(common::path_fixtures::pathway(38035));
    let count = Arc::new(Counter::default());
    let waker = Waker::from(count.clone());
    let mut datagrams = [Datagram::default()];
    let mut frames = Vec::new();
    assert!(std::pin::pin!(path.collect(&mut datagrams, &mut frames)).poll(&mut Context::from_waker(&waker)).is_pending());
    common::initial_space(&paths.spaces).crypto.writer().write_all(b"ready").await.unwrap();
    path.cc.on_charged();
    path.wake_sender();
    assert_eq!(count.0.load(Ordering::Relaxed), 1);
    assert!(matches!(
        std::pin::pin!(path.collect(&mut datagrams, &mut frames)).poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Ok((1, _)))
    ));
    path.refresh(&mut datagrams, &mut frames);
    paths.del_path(&path);
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn collect_errors_release_the_native_task_before_path_cleanup() {
    let (paths, path) = path(common::path_fixtures::pathway(38036));
    path.close();
    let count = Arc::new(Counter::default());
    let task = Arc::downgrade(&count);
    let waker = Waker::from(count.clone());
    let mut datagrams = [Datagram::default()];
    let mut frames = Vec::new();
    assert!(matches!(
        std::pin::pin!(path.collect(&mut datagrams, &mut frames)).poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe
    ));
    drop(waker);
    drop(count);
    assert!(task.upgrade().is_none());
    paths.del_path(&path);
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn collect_waiter_is_consumed_rearmed_and_absent_on_ready() {
    let (paths, path) = path(common::path_fixtures::pathway(38031));
    let count = Arc::new(Counter::default());
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    let mut datagrams = [Datagram::default()];
    let mut frames = Vec::new();
    for expected in 1..=2 {
        assert!(std::pin::pin!(path.collect(&mut datagrams, &mut frames)).poll(&mut cx).is_pending());
        path.wake_sender();
        path.wake_sender();
        assert_eq!(count.0.load(Ordering::Relaxed), expected);
    }
    common::initial_space(&paths.spaces).crypto.writer().write_all(b"ready").await.unwrap();
    assert!(matches!(std::pin::pin!(path.collect(&mut datagrams, &mut frames)).poll(&mut cx), Poll::Ready(Ok((1, _)))));
    let before = count.0.load(Ordering::Relaxed);
    path.cc.on_charged();
    path.wake_sender();
    assert_eq!(count.0.load(Ordering::Relaxed), before);
    path.refresh(&mut datagrams, &mut frames);
    paths.del_path(&path);
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn notification_during_collect_cannot_pass_the_pending_registration() {
    let (paths, path) = path(common::path_fixtures::pathway(38032));
    paths.progress.facts().on_handshake_done();
    let count = Arc::new(Counter::default());
    let waker = Waker::from(count.clone());
    // Stop collect inside its readiness check, after it has registered its native waker.
    let references = Arc::strong_count(&path.send_waker);
    let cc = path.cc.lock();
    std::thread::scope(|scope| {
        let collect = scope.spawn(|| {
            let mut datagrams = [Datagram::default()];
            let mut frames = Vec::new();
            std::pin::pin!(path.collect(&mut datagrams, &mut frames)).poll(&mut Context::from_waker(&waker))
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while Arc::strong_count(&path.send_waker) == references {
            if Instant::now() >= deadline {
                drop(cc);
                panic!("collect did not enter its readiness check");
            }
            std::thread::yield_now();
        }
        let (notified, returned) = mpsc::channel();
        let notifying_path = &path;
        let notify = scope.spawn(move || {
            notifying_path.wake_sender();
            notified.send(()).unwrap();
        });
        let notification = returned.recv_timeout(Duration::from_secs(2));
        drop(cc);
        assert!(collect.join().unwrap().is_pending());
        notify.join().unwrap();
        notification.expect("notifying a running collect must not wait for its source locks");
    });
    assert_eq!(count.0.load(Ordering::Relaxed), 1);
    path.wake_sender();
    assert_eq!(count.0.load(Ordering::Relaxed), 1);
    paths.del_path(&path);
    paths.retire_all();
}

#[tokio::test(start_paused = true)]
async fn socket_wait_is_interrupted_by_disable_or_close_after_collect_waiter_is_cleared() {
    use qprotocol::{QuicProtocol, UdpSocket};

    for close in [false, true] {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let local = qbase::net::addr::EndpointAddr::direct(socket.local_addr().unwrap());
        QuicProtocol::global().register(local, &socket).unwrap();
        let (paths, path) = path(Pathway::new(local, peer.local_addr().unwrap().into()));
        paths.progress.facts().quit_mp_replaying();
        common::initial_space(&paths.spaces).crypto.writer().write_all(b"ready").await.unwrap();
        let mut datagrams = std::array::from_fn::<_, 2, _>(|_| Datagram::default());
        let mut frames = Vec::new();
        let count = Arc::new(Counter::default());
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(std::pin::pin!(path.collect(&mut datagrams, &mut frames)).poll(&mut cx), Poll::Ready(Ok((1, _)))));
        let idle = paths.idle_timer();
        {
            let mut send = std::pin::pin!(path.send(&mut datagrams[..1], &idle));
            // The current-thread runtime has not yet polled the new socket's readiness.
            assert!(send.as_mut().poll(&mut cx).is_pending());
            common::initial_space(&paths.spaces).crypto.writer().write_all(b"queued during UDP wait").await.unwrap();
            path.cc.on_charged();
            path.wake_sender();
            assert_eq!(count.0.load(Ordering::Relaxed), 0);
            if close {
                path.close();
            } else {
                path.disable();
            }
            assert_eq!(count.0.load(Ordering::Relaxed), 1);
            match send.as_mut().poll(&mut cx) {
                Poll::Ready(Err(error)) if close => assert_eq!(error.kind(), io::ErrorKind::BrokenPipe),
                Poll::Ready(Ok(())) if !close => (),
                result => panic!("socket wait must end after path state changes: {result:?}"),
            }
        }
        path.refresh(&mut datagrams, &mut frames);
        paths.del_path(&path);
        paths.retire_all();
        QuicProtocol::global().unregister(socket.local_addr().unwrap());
    }
}
