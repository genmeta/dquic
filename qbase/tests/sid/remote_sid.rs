use std::sync::{Arc, Mutex};

use qbase::{
    frame::{MaxStreamsFrame, io::SendFrame},
    role::Role,
    sid::{StreamId, handy::ConsistentConcurrency, remote_sid::*},
    varint::VarInt,
};

#[derive(Clone, Default)]
struct MaxStreamsFrameTx(Arc<Mutex<Vec<MaxStreamsFrame>>>);

impl SendFrame<MaxStreamsFrame> for MaxStreamsFrameTx {
    fn send_frame<I: IntoIterator<Item = MaxStreamsFrame>>(&self, iter: I) {
        self.0.lock().unwrap().extend(iter);
    }
}

#[test]
fn test_try_accept_sid() {
    let remote = ArcRemoteStreamIds::new(
        Role::Server,
        10,
        5,
        MaxStreamsFrameTx::default(),
        Box::new(ConsistentConcurrency::new(10, 5)),
    );

    for (id, expected) in [
        (21, vec![1, 5, 9, 13, 17, 21]),
        (25, vec![25]),
        (41, vec![29, 33, 37, 41]),
    ] {
        let AcceptSid::New(range) = remote
            .try_accept_sid(StreamId::from(VarInt::from_u32(id)))
            .unwrap()
        else {
            panic!("expected new stream IDs")
        };
        assert_eq!(
            range.collect::<Vec<_>>(),
            expected
                .into_iter()
                .map(|id| StreamId::from(VarInt::from_u32(id)))
                .collect::<Vec<_>>()
        );
    }
    let sid = StreamId::from(VarInt::from_u32(65));
    let error: ExceedLimitError = remote.try_accept_sid(sid).unwrap_err();
    assert_eq!(error.to_string(), format!("{sid} exceed limit: 10"));
}
