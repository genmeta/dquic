use std::{
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use derive_more::{Deref, DerefMut};
use qbase::{
    error::ErrorKind,
    flow::*,
    frame::{
        DataBlockedFrame, FrameType, MaxDataFrame,
        io::{ReceiveFrame, SendFrame},
    },
};

#[derive(Clone, Debug, Default, Deref, DerefMut)]
struct SendControllerBroker(Arc<Mutex<Vec<DataBlockedFrame>>>);

impl SendFrame<DataBlockedFrame> for SendControllerBroker {
    fn send_frame<I: IntoIterator<Item = DataBlockedFrame>>(&self, iter: I) {
        self.0.lock().unwrap().extend(iter);
    }
}

#[test]
fn empty_credit_refunds_do_not_wake_the_sender() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Wake, Waker},
    };

    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let controller = ArcSendControler::new(100, SendControllerBroker::default());
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    let Poll::Ready(credit) = controller.poll_credit(&mut cx, 0) else {
        panic!("zero credit must be available");
    };
    drop(credit);
    assert_eq!(counter.0.load(Ordering::Relaxed), 0);

    let Poll::Ready(mut credit) = controller.poll_credit(&mut cx, 10) else {
        panic!("credit must be available");
    };
    credit.post_sent(10);
    drop(credit);
    assert_eq!(counter.0.load(Ordering::Relaxed), 0);

    // Returning actual credit must still wake another blocked sender.
    let credit = controller.credit(90);
    assert_eq!(controller.credit(1).available(), 0);
    drop(credit);
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
}

#[test]
fn test_send_controler() {
    let broker = SendControllerBroker::default();
    let controler = ArcSendControler::new(0, broker.clone());
    controler
        .recv_frame(MaxDataFrame::new(100u32.into()))
        .unwrap();
    let mut credit = controler.credit(200);
    assert_eq!(credit.available(), 100);
    credit.post_sent(50);
    assert_eq!(credit.available(), 50);
    credit.post_sent(50);
    assert_eq!(credit.available(), 0);
    drop(credit);

    // broker should have a DataBlockedFrame
    assert_eq!(broker.lock().unwrap().len(), 1);
    assert_eq!(broker.lock().unwrap()[0].limit(), 100);

    let credit = controler.credit(1);
    assert_eq!(credit.available(), 0);
    drop(credit);

    controler
        .recv_frame(MaxDataFrame::new(200u32.into()))
        .unwrap();

    let mut credit = controler.credit(200);
    assert_eq!(credit.available(), 100);
    credit.post_sent(50);
    assert_eq!(credit.available(), 50);
    credit.post_sent(50);
    assert_eq!(credit.available(), 0);
    drop(credit);

    // broker should have a DataBlockedFrame
    assert_eq!(broker.lock().unwrap().len(), 2);
    assert_eq!(broker.lock().unwrap()[1].limit(), 200);
}

#[derive(Clone, Debug, Default, Deref, DerefMut)]
struct RecvControllerBroker(Arc<Mutex<Vec<MaxDataFrame>>>);

impl SendFrame<MaxDataFrame> for RecvControllerBroker {
    fn send_frame<I: IntoIterator<Item = MaxDataFrame>>(&self, iter: I) {
        self.0.lock().unwrap().extend(iter);
    }
}

#[test]
fn test_recv_controller() {
    use qbase::frame::{Fin, Len, Offset};
    let broker = RecvControllerBroker::default();
    let controler = ArcRecvController::new(100, broker.clone());
    let amount = controler
        .on_new_rcvd(FrameType::Stream(Offset::Zero, Len::Omit, Fin::No), 20)
        .unwrap();
    assert_eq!(amount, 20);
    assert_eq!(broker.lock().unwrap().len(), 0);

    let amount = controler
        .on_new_rcvd(FrameType::Stream(Offset::Zero, Len::Explicit, Fin::Yes), 30)
        .unwrap();
    assert_eq!(amount, 30);
    // broker should have a MaxDataFrame
    assert_eq!(broker.lock().unwrap().len(), 1);
    assert_eq!(broker.lock().unwrap()[0].max_data(), 150);

    // test overflow
    let result = controler.on_new_rcvd(FrameType::ResetStream, 101);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::FlowControl);
}
