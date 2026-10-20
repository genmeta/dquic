use std::{
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use qbase::{
    frame::{StreamsBlockedFrame, io::SendFrame},
    net::tx::ArcSendWakers,
    role::Role,
    sid::{Dir, StreamId, local_sid::*},
    varint::VarInt,
};

#[derive(Clone, Default)]
struct StreamsBlockedFrameTx(Arc<Mutex<Vec<StreamsBlockedFrame>>>);

impl SendFrame<StreamsBlockedFrame> for StreamsBlockedFrameTx {
    fn send_frame<I: IntoIterator<Item = StreamsBlockedFrame>>(&self, iter: I) {
        self.0.lock().unwrap().extend(iter);
    }
}

#[test]
fn test_stream_id_new() {
    let sid = StreamId::new(Role::Client, Dir::Bi, 0);
    assert_eq!(sid, StreamId::from(VarInt::from_u32(0)));
    assert_eq!(sid.role(), Role::Client);
    assert_eq!(sid.dir(), Dir::Bi);
}

#[test]
fn server_can_start_with_validated_peer_stream_limits() {
    let local = ArcLocalStreamIds::new(
        Role::Server,
        1,
        1,
        StreamsBlockedFrameTx::default(),
        ArcSendWakers::default(),
    );
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert_eq!(
        local.poll_alloc_sid(&mut cx, Dir::Bi),
        Poll::Ready(Some(StreamId::from(VarInt::from_u32(1))))
    );
    assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Bi), Poll::Pending);
    assert_eq!(
        local.poll_alloc_sid(&mut cx, Dir::Uni),
        Poll::Ready(Some(StreamId::from(VarInt::from_u32(3))))
    );
    assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Uni), Poll::Pending);
}
