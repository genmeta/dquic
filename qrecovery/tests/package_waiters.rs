use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    error::Error,
    frame::io::SendFrame,
    packet::{ConstraintBuffer, Constraints, GetType, OneRttHeader, Package},
    param::{
        ArcParameters,
        handy::{client_parameters, server_parameters},
    },
    role::Role,
    sid::handy::DemandConcurrency,
};
use qrecovery::{
    crypto::CryptoStream, journal::ArcRcvdJournal, send::CancelStream, streams::DataStreams,
};
use tokio::io::AsyncWriteExt;

#[derive(Default)]
struct Counter(AtomicUsize);

impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn poll(
    source: &mut impl Package<BytesMut>,
    quota: usize,
    waker: &Waker,
) -> Poll<Result<usize, Error>> {
    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let mut limits = Constraints {
        flow_ctrl: 100,
        send_quota: quota,
        credit: quota,
        min_size: 0,
        max_size: 128,
        ..Default::default()
    };
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    source.poll_dump(
        &mut Context::from_waker(waker),
        &mut ConstraintBuffer::new(&mut bytes, &mut limits, ty, 0, 0),
        &mut frames,
    )
}

#[tokio::test]
async fn crypto_registers_only_when_no_frame_was_written() {
    for quota in [0, 128] {
        for multipath in [false, true] {
            let stream = CryptoStream::new();
            let mut writer = stream.writer();
            writer.write_all(b"hello").await.unwrap();
            let counter = Arc::new(Counter::default());
            let waker = Waker::from(counter.clone());
            let result = if multipath {
                poll(&mut stream.multipath(), quota, &waker)
            } else {
                poll(&mut stream.outgoing(), quota, &waker)
            };
            assert_eq!(result, Poll::Ready(Ok(usize::from(quota != 0))));
            writer.write_all(b"next").await.unwrap();
            assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        }
    }
    let stream = CryptoStream::new();
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(counter.clone());
    assert!(poll(&mut stream.outgoing(), 128, &waker).is_pending());
    stream.writer().write_all(b"hello").await.unwrap();
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
}

#[derive(Clone)]
struct Broker;
impl<T> SendFrame<T> for Broker {
    fn send_frame<I: IntoIterator<Item = T>>(&self, _: I) {}
}

#[tokio::test]
async fn stream_ready_and_blocked_polls_do_not_subscribe() {
    for quota in [0, 128] {
        let mut source = DataStreams::new(
            ArcParameters::new(
                Role::Client,
                Arc::new(client_parameters()),
                Arc::new(server_parameters()),
            ),
            Box::new(DemandConcurrency),
            Broker,
            None,
        );
        let (_, mut writer) = source.open_uni().await.unwrap().unwrap();
        // Keep data queued after assembly so the stream remains ready.
        writer.write_all(&[0; 128]).await.unwrap();
        let counter = Arc::new(Counter::default());
        let waker = Waker::from(counter.clone());
        assert!(matches!(
            poll(&mut source, quota, &waker),
            Poll::Ready(Ok(n)) if (n > 0) == (quota != 0)
        ));
        writer.write_all(b"next").await.unwrap();
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        writer.cancel(0);
    }
}

#[test]
fn ack_registers_only_when_pending() {
    for queued in [false, true] {
        for quota in [0, 128] {
            for snapshot in [false, true] {
                let mut journal = ArcRcvdJournal::with_capacity(8, None);
                let received = tokio::time::Instant::now();
                if queued {
                    journal.on_rcvd_pn(0, true, Duration::ZERO);
                }
                let counter = Arc::new(Counter::default());
                let waker = Waker::from(counter.clone());
                let result = if snapshot {
                    poll(
                        &mut journal.ack_package(queued.then_some((0, received))),
                        quota,
                        &waker,
                    )
                } else {
                    poll(&mut journal, quota, &waker)
                };
                assert_eq!(result.is_pending(), !queued);
                if queued {
                    assert_eq!(result, Poll::Ready(Ok(usize::from(quota != 0))));
                }
                journal.on_rcvd_pn(1, true, Duration::ZERO);
                assert_eq!(counter.0.load(Ordering::Relaxed), usize::from(!queued));
            }
        }
    }
}
