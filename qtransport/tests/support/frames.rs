use bytes::BytesMut;
use qbase::{frame::Frame, packet::OneRttHeader};

pub(crate) fn take_frames(
    source: &mut impl for<'b> qbase::packet::Package<bytes::buf::Limit<&'b mut BytesMut>>,
) -> Vec<Frame> {
    use qbase::packet::{GetType, PacketBuffer};
    let mut bytes = BytesMut::with_capacity(1200);
    let mut frames = Vec::new();
    let limits_quota = 1200;
    let limits_length = 1200;
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let mut writer_0 = bytes::BufMut::limit(&mut bytes, limits_length);
    let result = source.poll_dump(
        &mut std::task::Context::from_waker(std::task::Waker::noop()),
        &mut PacketBuffer::new(&mut writer_0, limits_quota, &mut frames, ty, 0, 0),
    );
    assert!(!matches!(result, std::task::Poll::Ready(Err(_))));
    frames.into_iter().map(Into::into).collect()
}
