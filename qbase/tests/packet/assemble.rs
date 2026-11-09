use std::task::{Context, Poll, Waker};

use bytes::{BufMut, BytesMut};
use qbase::{
    frame::*,
    packet::{GetType, OneRttHeader, PacketNumber, assemble::*},
};

#[test]
fn metadata_accounts_for_unrecorded_frames_and_stops_after_close() {
    let mut bytes = BytesMut::new();
    let mut writer = (&mut bytes).limit(1200);
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let mut frames = Vec::new();
    let mut buffer = PacketBuffer::new(&mut writer, 1200, &mut frames, ty, 0, 0);
    let mut cx = Context::from_waker(Waker::noop());
    let mut ack = AckFrame::new(7u32.into(), 0u32.into(), 0u32.into(), vec![], None);
    assert_eq!(ack.poll_dump(&mut cx, &mut buffer), Poll::Ready(1));
    assert_eq!(buffer.meta.ack, Some(7));
    assert!(!buffer.meta.in_flight);
    assert_eq!(PaddingFrame.poll_dump(&mut cx, &mut buffer), Poll::Ready(1));
    assert!(buffer.meta.in_flight);
    assert!(!buffer.meta.content.is_ack_eliciting());
    assert_eq!(PingFrame.poll_dump(&mut cx, &mut buffer), Poll::Ready(1));
    assert_eq!(buffer.meta.content, qbase::packet::PacketContent::JustPing);
    assert!(buffer.frames.is_empty());
    let mut max_data = MaxDataFrame::new(123u32.into());
    assert_eq!(max_data.poll_dump(&mut cx, &mut buffer), Poll::Ready(1));
    assert_eq!(buffer.frames.len(), 1);
    assert_eq!(buffer.meta.content, qbase::packet::PacketContent::EffectivePayload);
    let mut close = ConnectionCloseFrame::new_app(0u32.into(), "closed");
    assert_eq!(close.poll_dump(&mut cx, &mut buffer), Poll::Ready(1));
    let written = buffer.written();
    assert_eq!(PingFrame.poll_dump(&mut cx, &mut buffer), Poll::Ready(0));
    assert_eq!(buffer.written(), written);
    assert_eq!(buffer.meta.nframes, 5);
    assert_eq!(buffer.frames.len(), 1);
}

#[test]
fn insufficient_payload_room_preserves_optional_source_and_records() {
    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let mut source = Some((CryptoFrame::new(0u32.into(), 4u32.into()), b"data".as_slice()));
    let mut cx = Context::from_waker(Waker::noop());
    let mut writer = (&mut bytes).limit(4);
    let mut buffer = PacketBuffer::new(&mut writer, 7, &mut frames, ty, 0, 0);
    assert!(matches!(source.poll_dump(&mut cx, &mut buffer), Poll::Ready(0)));
    assert!(source.is_some());
    assert!(buffer.frames.is_empty());
    assert_eq!(buffer.written(), 0);
    assert_eq!(buffer.meta.nframes, 0);
    assert!(!buffer.meta.in_flight);
    let mut writer = (&mut bytes).limit(7);
    let mut buffer = PacketBuffer::new(&mut writer, 7, &mut frames, ty, 0, 0);
    assert!(matches!(source.poll_dump(&mut cx, &mut buffer), Poll::Ready(1)));
    assert!(source.is_none());
    assert_eq!(buffer.frames.len(), 1);
}

#[test]
fn ack_bypasses_zero_quota_but_ping_charges_the_entire_packet() {
    let mut bytes = BytesMut::zeroed(11);
    let mut writer = (&mut bytes).limit(1200 - 11);
    let mut frames = Vec::new();
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let mut buffer = PacketBuffer::new(&mut writer, 0, &mut frames, ty, 11, 16);
    let mut cx = Context::from_waker(Waker::noop());
    let mut ack = AckFrame::new(0u32.into(), 0u32.into(), 0u32.into(), vec![], None);
    assert!(matches!(ack.poll_dump(&mut cx, &mut buffer), Poll::Ready(1)));
    assert!(matches!(PingFrame.poll_dump(&mut cx, &mut buffer), Poll::Ready(0)));
    assert_eq!(buffer.meta.content, qbase::packet::PacketContent::NonAckEliciting);
    assert!(!buffer.meta.in_flight);
    assert!(buffer.frames.is_empty());
    bytes.resize(16, 0);
    let mut writer = (&mut bytes).limit(1200 - 16);
    let mut buffer = PacketBuffer::new(&mut writer, 32, &mut frames, ty, 16, 16);
    assert!(matches!(PingFrame.poll_dump(&mut cx, &mut buffer), Poll::Ready(0)));
}

#[test]
fn validation_waits_for_padding_quota_before_consuming_the_frame() {
    let mut bytes = [0; 1200];
    let mut frames = Vec::new();
    let header = OneRttHeader::new(Default::default(), Default::default());
    let mut source = Some(PathChallengeFrame::random());
    let mut cx = Context::from_waker(Waker::noop());
    for quota in [1199, 1200] {
        let mut writer = bytes.as_mut_slice();
        let mut buffer = PacketBuffer::new(&mut writer, quota, &mut frames, header.get_type(), 0, 16);
        buffer.scope(1200);
        assert!(buffer.begin(&header, PacketNumber::U8(0)));
        assert_eq!(source.poll_dump(&mut cx, &mut buffer), Poll::Ready(usize::from(quota == 1200)));
        assert_eq!(source.is_none(), quota == 1200);
        assert!(buffer.frames.is_empty());
        if quota == 1200 {
            assert_eq!(buffer.min_size(), 1200);
        }
    }
}
