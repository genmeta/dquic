use bytes::BytesMut;
use qbase::{frame::Frame, packet::OneRttHeader};

pub(crate) fn take_frames(source: &mut impl qbase::packet::Package<BytesMut>) -> Vec<Frame> {
    use qbase::packet::{Constraints, GetType, PacketBuffer};
    let mut bytes = BytesMut::with_capacity(1200);
    let mut frames = Vec::new();
    let mut limits = Constraints {
        flow_ctrl: 1200,
        send_quota: 1200,
        credit: 1200,
        max_size: 1200,
        ..Default::default()
    };
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let result = source.poll_dump(
        &mut std::task::Context::from_waker(std::task::Waker::noop()),
        &mut PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0),
    );
    assert!(!matches!(result, std::task::Poll::Ready(Err(_))));
    frames.into_iter().map(Into::into).collect()
}
