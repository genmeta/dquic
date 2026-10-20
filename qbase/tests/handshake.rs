use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use qbase::{
    error::{ErrorKind, QuicError},
    frame::{
        HandshakeDoneFrame,
        io::{ReceiveFrame, SendFrame},
    },
    handshake::*,
};

#[derive(Debug, Default, Clone)]
struct HandshakeDoneFrameTx(Arc<Mutex<Vec<HandshakeDoneFrame>>>);

impl SendFrame<HandshakeDoneFrame> for HandshakeDoneFrameTx {
    fn send_frame<I: IntoIterator<Item = HandshakeDoneFrame>>(&self, iter: I) {
        self.0.lock().unwrap().extend(iter);
    }
}

#[derive(Default)]
struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn client_confirmation_wakes_the_latest_waiter_once() {
    let mut handshake = ArcHandshake::<HandshakeDoneFrameTx>::new_client();
    let receiver = handshake.clone();
    let first = Arc::new(WakeCounter::default());
    let second = Arc::new(WakeCounter::default());
    let first_waker = Waker::from(first.clone());
    let second_waker = Waker::from(second.clone());
    assert!(
        Pin::new(&mut handshake)
            .poll(&mut Context::from_waker(&first_waker))
            .is_pending()
    );
    let mut cx = Context::from_waker(&second_waker);
    assert!(Pin::new(&mut handshake).poll(&mut cx).is_pending());
    assert!(receiver.recv_frame(HandshakeDoneFrame).unwrap());
    assert_eq!(first.0.load(Ordering::Relaxed), 0);
    assert_eq!(second.0.load(Ordering::Relaxed), 1);
    assert!(handshake.is_handshake_done());
    assert!(matches!(
        Pin::new(&mut handshake).poll(&mut cx),
        Poll::Ready(())
    ));
    assert!(!receiver.recv_frame(HandshakeDoneFrame).unwrap());
    assert_eq!(second.0.load(Ordering::Relaxed), 1);
    assert!(matches!(
        Pin::new(&mut handshake).poll(&mut cx),
        Poll::Ready(())
    ));
}

#[tokio::test]
async fn client_confirmation_before_waiting_is_preserved_for_clones() {
    let handshake = ArcHandshake::<HandshakeDoneFrameTx>::new_client();
    assert!(handshake.recv_frame(HandshakeDoneFrame).unwrap());
    handshake.clone().await;
    handshake.await;
}

#[test]
fn client_poll_done_waits_for_confirmation() {
    let mut handshake = ClientHandshake::default();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(handshake.poll_done(&mut cx).is_pending());
    assert!(handshake.recv_handshake_done_frame(HandshakeDoneFrame));
    assert!(matches!(handshake.poll_done(&mut cx), Poll::Ready(())));
}

#[tokio::test]
#[should_panic(expected = "server handshake confirmation cannot be awaited")]
async fn server_waiting_panics() {
    ArcHandshake::new_server(HandshakeDoneFrameTx::default()).await;
}

#[tokio::test]
#[should_panic(expected = "server handshake confirmation cannot be awaited")]
async fn server_waiting_after_completion_panics() {
    let output = HandshakeDoneFrameTx::default();
    let handshake = ArcHandshake::new_server(output.clone());
    assert!(handshake.done());
    assert!(!handshake.clone().done());
    assert_eq!(output.0.lock().unwrap().len(), 1);
    handshake.await;
}

#[test]
fn test_client_handshake() {
    let handshake = ArcHandshake::<HandshakeDoneFrameTx>::new_client();
    assert!(!handshake.is_handshake_done());

    let ret = handshake.recv_frame(HandshakeDoneFrame);
    assert!(ret.is_ok());
    assert!(handshake.is_handshake_done());
}

#[test]
fn test_client_handshake_done() {
    let handshake = ArcHandshake::<HandshakeDoneFrameTx>::new_client();
    assert!(!handshake.is_handshake_done());

    assert!(handshake.recv_frame(HandshakeDoneFrame).unwrap());
    assert!(handshake.is_handshake_done());

    // recv_frame will only return `true` once when handshake first done
    assert!(!handshake.recv_frame(HandshakeDoneFrame).unwrap());
    assert!(handshake.is_handshake_done());
}

#[test]
fn test_server_handshake() {
    let handshake = ArcHandshake::new_server(HandshakeDoneFrameTx::default());
    assert!(!handshake.is_handshake_done());

    assert!(handshake.done());
    assert!(handshake.is_handshake_done());

    // same as last test
    assert!(!handshake.done());
    assert!(handshake.is_handshake_done());
}

#[test]
fn test_server_recv_handshake_done_frame() {
    let handshake = ArcHandshake::new_server(HandshakeDoneFrameTx::default());
    assert!(!handshake.is_handshake_done());

    let ret = handshake.recv_frame(HandshakeDoneFrame);
    assert_eq!(
        ret,
        Err(QuicError::with_default_fty(
            ErrorKind::ProtocolViolation,
            "Server received a HANDSHAKE_DONE frame",
        )
        .into())
    );
}

#[test]
fn test_server_send_handshake_done_frame() {
    let output = HandshakeDoneFrameTx::default();
    let handshake = ServerHandshake::new(output.clone());
    handshake.done();
    assert!(handshake.is_handshake_done());
    assert_eq!(output.0.lock().unwrap().len(), 1);
}
