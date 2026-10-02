use std::{
    task::{Context, Poll, Waker},
    time::Duration,
};

use qbase::{
    error::{ErrorKind, QuicError},
    frame::{ConnectionCloseFrame, Frame},
    packet::{ConstraintBuffer, Constraints, GetType, Limit, OneRttHeader, Package},
};
use tokio::time::Instant;

use crate::{
    CloseReason, Error,
    terminate::{ArcTerminator, Terminator},
};

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
    let mut buffer = ConstraintBuffer::new(
        &mut bytes,
        &mut limits,
        OneRttHeader::new(Default::default(), Default::default()).get_type(),
        0,
        0,
    );
    (&*terminator).poll_dump(&mut Context::from_waker(waker), &mut buffer, &mut frames)
}

#[test]
fn draining_writes_one_close_and_never_schedules_another() {
    for via_error in [false, true] {
        let terminator = ArcTerminator::no_error();
        let frame = close_frame("peer");
        let duration = Duration::from_secs(3);
        if via_error {
            terminator.on_error(&CloseReason::Peer(frame.clone()), duration);
        } else {
            terminator.on_rcvd_connection_close_frame(frame.clone(), duration);
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
            let mut buffer = ConstraintBuffer::new(
                &mut bytes,
                &mut limits,
                OneRttHeader::new(Default::default(), Default::default()).get_type(),
                0,
                0,
            );
            assert!(matches!(
                (&terminator).poll_dump(
                    &mut Context::from_waker(Waker::noop()),
                    &mut buffer,
                    &mut frames,
                ),
                Poll::Ready(Ok(n)) if n == expected
            ));
            if expected == 1 {
                assert!(matches!(frames.as_slice(), [Frame::Close(sent)] if sent == &frame));
                assert!(!bytes.is_empty());
            } else {
                assert!(frames.is_empty());
                assert!(bytes.is_empty());
                assert_eq!(limits.max_size(), max_size);
            }
            terminator.on_rcvd_packet(Instant::now() + duration);
            terminator.on_rcvd_connection_close_frame(close_frame("again"), duration);
        }
    }
}

#[test]
fn closing_without_a_written_frame_preserves_send_budget() {
    for (pending, overhead) in [(false, 0), (true, 0), (false, 40), (true, 40)] {
        let terminator = ArcTerminator::no_error();
        terminator.on_error(&local_reason(), Duration::from_secs(3));
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
        let mut buffer = ConstraintBuffer::new(
            &mut bytes,
            &mut limits,
            OneRttHeader::new(Default::default(), Default::default()).get_type(),
            0,
            0,
        );
        let result = (&terminator).poll_dump(
            &mut Context::from_waker(Waker::noop()),
            &mut buffer,
            &mut frames,
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
        assert_eq!(limits.max_size(), usize::from(!pending));
    }
}

#[test]
fn closing_sends_immediately_and_again_after_five_packets() {
    let terminator = ArcTerminator::no_error();
    let duration = Duration::from_secs(3);
    terminator.on_error(&local_reason(), duration);
    assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));

    for _ in 0..4 {
        terminator.on_rcvd_packet(Instant::now());
        assert!(poll_close(&terminator, Waker::noop()).is_pending());
    }
    terminator.on_rcvd_packet(Instant::now());
    assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
}

#[test]
fn closing_sends_again_when_a_later_packet_crosses_the_time_threshold() {
    let terminator = ArcTerminator::no_error();
    let duration = Duration::from_secs(3);
    terminator.on_error(&local_reason(), duration);
    assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
    let sent_at = Instant::now();
    terminator.on_rcvd_packet(sent_at + Duration::from_secs(1));
    assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
}

#[test]
fn peer_close_during_closing_discards_the_local_close() {
    for sent in [false, true] {
        let terminator = ArcTerminator::no_error();
        terminator.on_error(&local_reason(), Duration::from_secs(3));
        if sent {
            assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
        }
        terminator.on_rcvd_connection_close_frame(close_frame("peer"), Duration::from_secs(3));
        if !sent {
            assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(1)));
        }
        assert_eq!(poll_close(&terminator, Waker::noop()), Poll::Ready(Ok(0)));
    }
}

#[test]
fn pending_senders_are_woken_and_can_cancel_in_normal_and_closing() {
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
        for cancel in [false, true] {
            for draining in [false, true] {
                let terminator = ArcTerminator::no_error();
                let counter = Arc::new(Counter::default());
                let waker = Waker::from(counter.clone());
                assert!(poll_close(&terminator, &waker).is_pending());
                if closing {
                    terminator.on_error(&local_reason(), Duration::from_secs(3));
                    assert_eq!(counter.0.swap(0, Ordering::Relaxed), 1);
                    assert_eq!(poll_close(&terminator, &waker), Poll::Ready(Ok(1)));
                    assert!(poll_close(&terminator, &waker).is_pending());
                }
                if cancel {
                    <&ArcTerminator as Package<bytes::BytesMut>>::cancel(
                        &mut &terminator,
                        &waker,
                    );
                }
                if draining {
                    terminator.on_rcvd_connection_close_frame(
                        close_frame("peer"),
                        Duration::from_secs(3),
                    );
                    assert_eq!(
                        poll_close(&terminator, &waker),
                        Poll::Ready(Ok(usize::from(!closing)))
                    );
                    assert_eq!(poll_close(&terminator, &waker), Poll::Ready(Ok(0)));
                }
                terminator.terminate();
                assert_eq!(
                    counter.0.load(Ordering::Relaxed),
                    usize::from(!cancel && !(closing && draining))
                );
                assert!(matches!(
                    poll_close(&terminator, &waker),
                    Poll::Ready(Err(_))
                ));
            }
        }
    }
}

#[test]
fn terminated_returns_its_stored_error() {
    let terminator = ArcTerminator::no_error();
    let error = Error::from(close_frame("terminated"));
    *terminator.lock_guard() = Terminator::Terminated(error.clone());
    terminator.terminate();
    terminator.on_error(&local_reason(), Duration::from_secs(3));
    terminator.on_rcvd_connection_close_frame(close_frame("peer"), Duration::from_secs(3));
    assert_eq!(
        poll_close(&terminator, Waker::noop()),
        Poll::Ready(Err(error))
    );
}

#[tokio::test(start_paused = true)]
async fn wait_uses_the_initial_deadline_without_a_notification() {
    let terminator = ArcTerminator::no_error();
    let duration = Duration::from_secs(30);
    terminator.on_error(&local_reason(), duration);
    let waiter = tokio::spawn({
        let terminator = terminator.clone();
        async move { terminator.wait().await }
    });

    tokio::time::advance(Duration::from_secs(10)).await;
    terminator.on_rcvd_connection_close_frame(close_frame("peer"), duration);
    tokio::time::advance(Duration::from_secs(20)).await;
    waiter.await.unwrap();
    assert!(matches!(
        &*terminator.lock_guard(),
        Terminator::Terminated(_)
    ));
}
