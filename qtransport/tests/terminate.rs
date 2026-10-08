use std::{
    task::{Context, Poll, Waker},
    time::Duration,
};

use futures::FutureExt;
use qbase::{
    error::{ErrorKind, QuicError},
    frame::{ConnectionCloseFrame, Frame},
    packet::{PacketBuffer, Constraints, GetType, Limit, OneRttHeader, Package},
};
use qtransport::{CloseReason, Error, terminate::ArcTerminator};
use tokio::time::Instant;

fn close_frame(reason: &'static str) -> ConnectionCloseFrame {
    ConnectionCloseFrame::from(Error::from(QuicError::with_default_fty(
        ErrorKind::Internal,
        reason,
    )))
}

fn local_reason() -> CloseReason {
    CloseReason::Internal(QuicError::with_default_fty(ErrorKind::Internal, "local"))
}

fn poll_close(terminator: &ArcTerminator, waker: &Waker) -> Poll<Result<usize, Error>> {
    let mut limits = Constraints {
        send_quota: 2400,
        credit: 2400,
        max_size: 1200,
        ..Default::default()
    };
    let mut bytes = bytes::BytesMut::new();
    let mut frames = Vec::new();
    let mut buffer = PacketBuffer::new(
        &mut bytes,
        &mut limits,
        &mut frames,
        OneRttHeader::new(Default::default(), Default::default()).get_type(),
        0,
        0,
    );
    (&*terminator).poll_dump(&mut Context::from_waker(waker), &mut buffer)
}

#[tokio::test(start_paused = true)]
async fn draining_writes_one_close_and_never_schedules_another() {
    for via_error in [false, true] {
        let terminator = ArcTerminator::no_error();
        let frame = close_frame("peer");
        let pto = Duration::from_secs(1);
        if via_error {
            terminator.close(CloseReason::Peer(frame.clone()), pto);
        } else {
            terminator.recv_conn_close_frame(frame.clone(), pto);
        }
        // Insufficient space must not consume the one permitted response.
        for (max_size, expected) in [(1, 0), (1200, 1), (1200, 0)] {
            let mut limits = Constraints {
                send_quota: 2400,
                credit: 2400,
                max_size,
                ..Default::default()
            };
            let mut bytes = bytes::BytesMut::new();
            let mut frames = Vec::new();
            let mut buffer = PacketBuffer::new(
                &mut bytes,
                &mut limits,
                &mut frames,
                OneRttHeader::new(Default::default(), Default::default()).get_type(),
                0,
                0,
            );
            assert!(matches!(
                (&terminator).poll_dump(
                    &mut Context::from_waker(Waker::noop()),
                    &mut buffer,
                ),
                Poll::Ready(Ok(n)) if n == expected
            ));
            if expected == 1 {
                assert!(frames.is_empty());
                let decoded = qbase::frame::FrameReader::new(bytes.clone().freeze(), OneRttHeader::new(Default::default(), Default::default()).get_type())
                    .collect::<Result<Vec<_>, _>>().unwrap();
                assert!(matches!(decoded.as_slice(), [(Frame::Close(sent), _)] if sent == &frame));
                assert!(!bytes.is_empty());
            } else {
                assert!(frames.is_empty());
                assert!(bytes.is_empty());
                assert_eq!(limits.max_size(), 0);
            }
            terminator.on_rcvd_packet(Instant::now() + pto);
            terminator.recv_conn_close_frame(close_frame("again"), pto);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn closing_without_a_written_frame_preserves_send_budget() {
    for (pending, overhead) in [(false, 0), (true, 0), (false, 40), (true, 40)] {
        let terminator = ArcTerminator::no_error();
        terminator.close(local_reason(), Duration::from_secs(1));
        if pending {
            assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
        }
        let mut limits = Constraints {
            flow_ctrl: 0,
            send_quota: 2400,
            credit: 2400,
            min_size: 0,
            max_size: 1 + overhead,
            overhead,
            ..Default::default()
        };
        let mut bytes = bytes::BytesMut::new();
        let mut frames = Vec::new();
        let mut buffer = PacketBuffer::new(
            &mut bytes,
            &mut limits,
            &mut frames,
            OneRttHeader::new(Default::default(), Default::default()).get_type(),
            0,
            0,
        );
        let result = (&terminator).poll_dump(
            &mut Context::from_waker(Waker::noop()),
            &mut buffer,
        );
        if pending {
            assert!(result.is_pending());
        } else {
            assert!(matches!(result, Poll::Ready(Ok(0))));
            assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
        }
        assert!(frames.is_empty());
        assert_eq!(limits.send_quota, 2400);
        assert_eq!(limits.credit, 2400);
        assert_eq!(limits.max_size(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn closing_sends_immediately_and_again_after_five_packets() {
    let terminator = ArcTerminator::no_error();
    terminator.close(local_reason(), Duration::from_secs(1));
    assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));

    for _ in 0..4 {
        terminator.on_rcvd_packet(Instant::now());
        assert!(poll_close(&terminator, Waker::noop()).is_pending());
    }
    terminator.on_rcvd_packet(Instant::now());
    assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
}

#[tokio::test(start_paused = true)]
async fn closing_sends_again_when_a_later_packet_crosses_the_time_threshold() {
    let terminator = ArcTerminator::no_error();
    terminator.close(local_reason(), Duration::from_secs(1));
    assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
    let sent_at = Instant::now();
    terminator.on_rcvd_packet(sent_at + Duration::from_secs(1));
    assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
}

#[tokio::test(start_paused = true)]
async fn peer_close_during_closing_discards_the_local_close() {
    for sent in [false, true] {
        let terminator = ArcTerminator::no_error();
        terminator.close(local_reason(), Duration::from_secs(1));
        if sent {
            assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
        }
        terminator.recv_conn_close_frame(close_frame("peer"), Duration::from_secs(1));
        if !sent {
            assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
        }
        assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(0)));
    }
}

#[tokio::test(start_paused = true)]
async fn pending_senders_are_woken_in_normal_and_closing() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    for closing in [false, true] {
        for draining in [false, true] {
            let terminator = ArcTerminator::no_error();
            let counter = Arc::new(Counter::default());
            let waker = Waker::from(counter.clone());
            assert!(poll_close(&terminator, &waker).is_pending());
            if closing {
                terminator.close(local_reason(), Duration::from_secs(1));
                assert_eq!(counter.0.swap(0, Ordering::Relaxed), 1);
                assert_eq!(poll_close(&terminator, &waker), Poll::Ready(Ok(1)));
                assert!(poll_close(&terminator, &waker).is_pending());
            }
            if draining {
                terminator.recv_conn_close_frame(close_frame("peer"), Duration::from_secs(1));
                assert_eq!(
                    poll_close(&terminator, &waker),
                    Poll::Ready(Ok(usize::from(!closing)))
                );
                assert_eq!(poll_close(&terminator, &waker), Poll::Ready(Ok(0)));
            }
            terminator.terminate();
            assert_eq!(
                counter.0.load(Ordering::Relaxed),
                usize::from(!(closing && draining))
            );
            assert!(matches!(
                poll_close(&terminator, &waker),
                Poll::Ready(Err(_))
            ));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn terminated_returns_its_stored_error() {
    let terminator = ArcTerminator::no_error();
    let error = Error::from(close_frame("terminated"));
    terminator.close(
        CloseReason::Peer(close_frame("terminated")),
        Duration::from_secs(1),
    );
    terminator.terminate();
    terminator.close(local_reason(), Duration::from_secs(1));
    terminator.recv_conn_close_frame(close_frame("peer"), Duration::from_secs(1));
    assert_eq!(
        poll_close(&terminator, Waker::noop()),
        Poll::Ready(Err(error))
    );
}

#[tokio::test(start_paused = true)]
async fn wait_uses_the_initial_deadline_without_a_notification() {
    let pto = Duration::from_secs(10);
    let terminator = ArcTerminator::no_error();
    let start = Instant::now();
    terminator.close(local_reason(), pto);
    let waiter = tokio::spawn({
        let terminator = terminator.clone();
        async move { terminator.wait().await }
    });

    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(!waiter.is_finished());
    terminator.close(local_reason(), Duration::from_secs(20));
    terminator.recv_conn_close_frame(close_frame("peer"), pto);
    tokio::time::advance(Duration::from_secs(20)).await;
    waiter.await.unwrap();
    assert_eq!(Instant::now() - start, 3 * pto);
    assert!(terminator.now_or_never().is_some());
}

#[tokio::test(start_paused = true)]
async fn close_notifies_components_once_and_registration_after_close_is_immediate() {
    use std::sync::{Arc, Mutex};

    struct Component(Mutex<Vec<Error>>);
    impl qbase::Close for Component {
        fn close_with_error(&self, error: Error) {
            self.0.lock().unwrap().push(error);
        }
    }
    let terminator = ArcTerminator::no_error();
    let first = Arc::new(Component(Mutex::new(Vec::new())));
    terminator.register(first.clone());
    terminator.close(local_reason(), Duration::from_secs(1));
    terminator.close(
        CloseReason::Peer(close_frame("later")),
        Duration::from_secs(10),
    );
    let late = Arc::new(Component(Mutex::new(Vec::new())));
    terminator.register(late.clone());
    let expected = Error::from(QuicError::with_default_fty(ErrorKind::Internal, "local"));
    assert_eq!(*first.0.lock().unwrap(), vec![expected.clone()]);
    assert_eq!(*late.0.lock().unwrap(), vec![expected]);
    assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
    assert!(poll_close(&terminator, Waker::noop()).is_pending());
}

#[tokio::test(start_paused = true)]
async fn all_waiters_observe_only_termination_even_after_cancellation() {
    let terminator = ArcTerminator::no_error();
    let mut first = terminator.clone();
    let mut cancelled = terminator.clone();
    assert!(futures::poll!(&mut first).is_pending());
    assert!(futures::poll!(&mut cancelled).is_pending());
    terminator.close(local_reason(), Duration::from_secs(1));
    assert!(futures::poll!(&mut first).is_pending());
    drop(cancelled);
    let mut second = terminator.clone();
    assert!(futures::poll!(&mut second).is_pending());
    tokio::time::advance(Duration::from_secs(3)).await;
    let (first, second) = tokio::join!(first, second);
    assert_eq!(first, second);
    assert_eq!(first, terminator.clone().await);
    assert_eq!(first, terminator.await);
}

#[tokio::test(start_paused = true)]
async fn forced_termination_wakes_all_waiters() {
    for closing in [false, true] {
        let terminator = ArcTerminator::no_error();
        if closing {
            terminator.close(local_reason(), Duration::from_secs(1));
        }
        let first = tokio::spawn({
            let terminator = terminator.clone();
            async move { terminator.await }
        });
        let second = tokio::spawn({
            let terminator = terminator.clone();
            async move { terminator.await }
        });
        tokio::task::yield_now().await;
        assert!(!first.is_finished());
        assert!(!second.is_finished());
        let start = Instant::now();
        terminator.terminate();
        let (first, second) = tokio::time::timeout(Duration::from_millis(1), async {
            (first.await.unwrap(), second.await.unwrap())
        })
        .await
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first, terminator.await);
        assert_eq!(Instant::now(), start);
    }
}

#[tokio::test(start_paused = true)]
async fn close_notifies_and_releases_registered_components() {
    use std::sync::{Arc, Mutex};
    struct Component(Arc<Mutex<Vec<Error>>>);
    impl qbase::Close for Component {
        fn close_with_error(&self, error: Error) {
            self.0.lock().unwrap().push(error);
        }
    }
    let terminator = ArcTerminator::no_error();
    let errors = Arc::new(Mutex::new(Vec::new()));
    let component = Arc::new(Component(errors.clone()));
    let weak = Arc::downgrade(&component);
    terminator.register(component);
    terminator.close(local_reason(), Duration::from_secs(1));
    assert!(weak.upgrade().is_none());
    terminator.close(local_reason(), Duration::from_secs(1));
    terminator.terminate();
    assert_eq!(
        errors.lock().unwrap().as_slice(),
        &[Error::from(QuicError::with_default_fty(
            ErrorKind::Internal,
            "local"
        ))]
    );
}

#[tokio::test(start_paused = true)]
async fn registration_racing_close_never_misses_or_duplicates_notification() {
    use std::sync::{Arc, Barrier, Mutex};

    struct Component(Mutex<Vec<Error>>);
    impl qbase::Close for Component {
        fn close_with_error(&self, error: Error) {
            self.0.lock().unwrap().push(error);
        }
    }
    for _ in 0..32 {
        let terminator = ArcTerminator::no_error();
        let component = Arc::new(Component(Mutex::new(Vec::new())));
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                terminator.register(component.clone());
            });
            barrier.wait();
            terminator.close(local_reason(), Duration::from_secs(1));
        });
        assert_eq!(
            component.0.lock().unwrap().as_slice(),
            &[Error::from(QuicError::with_default_fty(
                ErrorKind::Internal,
                "local"
            ))]
        );
    }
}

#[tokio::test(start_paused = true)]
async fn late_components_use_the_current_state_error() {
    use std::sync::{Arc, Mutex};

    struct Component(Mutex<Option<Error>>);
    impl qbase::Close for Component {
        fn close_with_error(&self, error: Error) {
            *self.0.lock().unwrap() = Some(error);
        }
    }
    let terminator = ArcTerminator::no_error();
    terminator.close(local_reason(), Duration::from_secs(1));
    tokio::time::advance(Duration::from_secs(1)).await;
    let peer = close_frame("peer");
    terminator.recv_conn_close_frame(peer.clone(), Duration::from_secs(10));
    let late = Arc::new(Component(Mutex::new(None)));
    terminator.register(late.clone());
    assert_eq!(*late.0.lock().unwrap(), Some(peer.clone().into()));
    let start = Instant::now();
    assert_eq!(terminator.clone().await, Error::from(peer.clone()));
    assert_eq!(Instant::now() - start, Duration::from_secs(2));
    let latest = Arc::new(Component(Mutex::new(None)));
    terminator.register(latest.clone());
    assert_eq!(*latest.0.lock().unwrap(), Some(peer.into()));
}

#[tokio::test(start_paused = true)]
async fn closing_and_draining_terminate_without_waiters() {
    for peer in [false, true] {
        let terminator = ArcTerminator::no_error();
        let pto = Duration::from_secs(1);
        if peer {
            terminator.recv_conn_close_frame(close_frame("peer"), pto);
        } else {
            terminator.close(local_reason(), pto);
        }
        let error = if peer {
            Error::from(close_frame("peer"))
        } else {
            QuicError::with_default_fty(ErrorKind::Internal, "local").into()
        };
        tokio::time::advance(3 * pto - Duration::from_millis(1)).await;
        assert!(terminator.clone().now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(terminator.now_or_never(), Some(error));
    }
}

#[tokio::test(start_paused = true)]
async fn timer_wakes_all_waiters_after_one_is_cancelled() {
    let terminator = ArcTerminator::no_error();
    let first = tokio::spawn(terminator.clone());
    let second = tokio::spawn(terminator.clone());
    let cancelled = tokio::spawn(terminator.clone());
    tokio::task::yield_now().await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    let start = Instant::now();
    terminator.close(local_reason(), Duration::from_secs(1));
    assert!(!first.is_finished());
    assert!(!second.is_finished());
    let (first, second) = tokio::time::timeout(Duration::from_secs(4), async {
        (first.await.unwrap(), second.await.unwrap())
    })
    .await
    .unwrap();
    assert_eq!(Instant::now() - start, Duration::from_secs(3));
    assert_eq!(first, second);
    assert_eq!(first, terminator.await);
}
