use std::{
    future::{Future, poll_fn},
    io::IoSlice,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use qbase::net::route::{Line, Link};
use qudp::UdpSocket;
use tokio::{sync::Notify, time::timeout};

#[derive(Default)]
struct SendWake(Notify);

impl Wake for SendWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }
}

async fn all_woken(waiters: &[Arc<SendWake>]) {
    timeout(Duration::from_secs(1), async {
        for waiter in waiters {
            waiter.0.notified().await;
        }
    })
    .await
    .expect("every pending sender must receive a writable wakeup");
}

#[tokio::test(flavor = "current_thread")]
async fn fresh_socket_wakes_ready_poll_and_async_senders_together() {
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let link = Link::new(socket.local_addr().unwrap(), receiver.local_addr().unwrap());
    let line = Line::new(link, 64, None, 4);
    let polled = [IoSlice::new(b"poll")];
    let awaited = [IoSlice::new(b"send")];
    let mut sending = Box::pin(socket.send(&awaited, line));
    let waiters: [_; 3] = std::array::from_fn(|_| Arc::new(SendWake::default()));
    let wakers = waiters.each_ref().map(|waiter| Waker::from(waiter.clone()));

    // The current-thread reactor has not observed this new socket yet. Register
    // distinct task wakers before yielding, reproducing concurrent punch probes.
    assert!(
        socket
            .poll_send_ready(&mut Context::from_waker(&wakers[0]))
            .is_pending()
    );
    assert!(
        socket
            .poll_send(&mut Context::from_waker(&wakers[1]), &polled, &line)
            .is_pending()
    );
    assert!(
        sending
            .as_mut()
            .poll(&mut Context::from_waker(&wakers[2]))
            .is_pending()
    );
    all_woken(&waiters).await;

    assert!(matches!(
        socket.poll_send_ready(&mut Context::from_waker(&wakers[0])),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(
        poll_fn(|cx| socket.poll_send(cx, &polled, &line))
            .await
            .unwrap(),
        1
    );
    assert_eq!(sending.await.unwrap(), 1);
    for expected in [b"poll", b"send"] {
        let mut bytes = [0; 4];
        let (len, source) = timeout(Duration::from_secs(1), receiver.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(len, expected.len());
        assert_eq!(&bytes, expected);
        assert_eq!(source, link.src);
    }
    for waiter in &waiters {
        assert_eq!(
            Arc::strong_count(waiter),
            2,
            "completed polls must release their wakers"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_the_last_sender_does_not_strand_other_waiters() {
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let link = Link::new(socket.local_addr().unwrap(), receiver.local_addr().unwrap());
    let line = Line::new(link, 64, None, 4);
    let bytes = [IoSlice::new(b"live")];
    let mut first = Box::pin(socket.send(&bytes, line));
    let mut last = Box::pin(socket.send(&bytes, line));
    let waiters: [_; 2] = std::array::from_fn(|_| Arc::new(SendWake::default()));
    let wakers = waiters.each_ref().map(|waiter| Waker::from(waiter.clone()));
    assert!(
        first
            .as_mut()
            .poll(&mut Context::from_waker(&wakers[0]))
            .is_pending()
    );
    assert!(
        last.as_mut()
            .poll(&mut Context::from_waker(&wakers[1]))
            .is_pending()
    );
    drop(last);
    all_woken(&waiters[..1]).await;
    assert_eq!(first.await.unwrap(), 1);
    let mut received = [0; 4];
    let (len, _) = timeout(Duration::from_secs(1), receiver.recv_from(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[..len], b"live");
}
