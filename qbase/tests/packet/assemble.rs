use std::task::{Context, Poll, Waker};

use bytes::BytesMut;
use qbase::{
    frame::*,
    packet::{GetType, OneRttHeader, assemble::*},
};

fn limits(size: usize) -> Constraints {
    Constraints {
        flow_ctrl: 0,
        send_quota: size,
        credit: size,
        min_size: 0,
        max_size: size,
        ..Default::default()
    }
}

#[test]
fn metadata_accounts_for_unrecorded_frames_and_stops_after_close() {
    let mut bytes = BytesMut::new();
    let mut limits = limits(1200);
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let mut frames = Vec::new();
    let mut buffer = PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0);
    let mut cx = Context::from_waker(Waker::noop());
    let mut ack = AckFrame::new(7u32.into(), 0u32.into(), 0u32.into(), vec![], None);
    assert_eq!(ack.poll_dump(&mut cx, &mut buffer), Poll::Ready(Ok(1)));
    assert_eq!(buffer.meta.ack, Some(7));
    assert!(!buffer.meta.in_flight);
    assert_eq!(
        PaddingFrame.poll_dump(&mut cx, &mut buffer),
        Poll::Ready(Ok(1))
    );
    assert!(buffer.meta.in_flight);
    assert!(!buffer.meta.content.is_ack_eliciting());
    assert_eq!(
        PingFrame.poll_dump(&mut cx, &mut buffer),
        Poll::Ready(Ok(1))
    );
    assert_eq!(buffer.meta.content, qbase::packet::PacketContent::JustPing);
    assert!(buffer.frames.is_empty());
    let mut max_data = MaxDataFrame::new(123u32.into());
    assert_eq!(max_data.poll_dump(&mut cx, &mut buffer), Poll::Ready(Ok(1)));
    assert_eq!(buffer.frames.len(), 1);
    assert_eq!(
        buffer.meta.content,
        qbase::packet::PacketContent::EffectivePayload
    );
    let mut close = ConnectionCloseFrame::new_app(0u32.into(), "closed");
    assert_eq!(close.poll_dump(&mut cx, &mut buffer), Poll::Ready(Ok(1)));
    let written = buffer.written();
    assert_eq!(
        PingFrame.poll_dump(&mut cx, &mut buffer),
        Poll::Ready(Ok(0))
    );
    assert_eq!(buffer.written(), written);
    assert_eq!(buffer.meta.nframes, 5);
    assert_eq!(buffer.frames.len(), 1);
}

#[test]
fn envelope_is_charged_once_and_ack_only_preserves_congestion_quota() {
    let mut limits = Constraints {
        overhead: 40,
        ..limits(2400)
    };
    limits.take(0, 0);
    assert_eq!((limits.send_quota, limits.credit), (2400, 2400));
    limits.take(0, 60);
    assert_eq!((limits.send_quota, limits.credit), (2400, 2300));
    limits.take(1160, 1160);
    assert_eq!((limits.send_quota, limits.credit), (1200, 1100));
}

#[test]
fn insufficient_payload_room_preserves_optional_source_and_records() {
    let mut bytes = BytesMut::new();
    let mut constraints = limits(4);
    let mut frames = Vec::new();
    let mut buffer = PacketBuffer::new(
        &mut bytes,
        &mut constraints,
        &mut frames,
        OneRttHeader::new(Default::default(), Default::default()).get_type(),
        0,
        0,
    );
    let mut source = Some((
        CryptoFrame::new(0u32.into(), 4u32.into()),
        b"data".as_slice(),
    ));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        source.poll_dump(&mut cx, &mut buffer),
        Poll::Ready(Ok(0))
    ));
    assert!(source.is_some());
    assert!(buffer.frames.is_empty());
    assert_eq!(buffer.written(), 0);
    assert_eq!(buffer.meta.nframes, 0);
    assert!(!buffer.meta.in_flight);
    let mut larger = limits(7);
    buffer.limits = &mut larger;
    assert!(matches!(
        source.poll_dump(&mut cx, &mut buffer),
        Poll::Ready(Ok(1))
    ));
    assert!(source.is_none());
    assert_eq!(buffer.frames.len(), 1);
}

#[test]
fn ack_bypasses_zero_quota_but_ping_charges_the_entire_packet() {
    let mut bytes = BytesMut::new();
    let mut constraints = limits(1200);
    constraints.send_quota = 0;
    let mut frames = Vec::new();
    let mut buffer = PacketBuffer::new(
        &mut bytes,
        &mut constraints,
        &mut frames,
        OneRttHeader::new(Default::default(), Default::default()).get_type(),
        11,
        16,
    );
    let mut cx = Context::from_waker(Waker::noop());
    let mut ack = AckFrame::new(0u32.into(), 0u32.into(), 0u32.into(), vec![], None);
    assert!(matches!(
        ack.poll_dump(&mut cx, &mut buffer),
        Poll::Ready(Ok(1))
    ));
    assert!(matches!(
        PingFrame.poll_dump(&mut cx, &mut buffer),
        Poll::Ready(Ok(0))
    ));
    assert_eq!(
        buffer.meta.content,
        qbase::packet::PacketContent::NonAckEliciting
    );
    assert!(!buffer.meta.in_flight);
    assert!(buffer.frames.is_empty());
    constraints.send_quota = 32;
    let mut buffer = PacketBuffer::new(
        &mut bytes,
        &mut constraints,
        &mut frames,
        OneRttHeader::new(Default::default(), Default::default()).get_type(),
        16,
        16,
    );
    assert!(matches!(
        PingFrame.poll_dump(&mut cx, &mut buffer),
        Poll::Ready(Ok(0))
    ));
}

#[test]
fn ack_waits_for_padding_quota_before_writing() {
    let mut bytes = BytesMut::new();
    let mut constraints = limits(1200);
    constraints.min_size = 1200;
    constraints.send_quota = 0;
    let mut frames = Vec::new();
    let mut buffer = PacketBuffer::new(
        &mut bytes,
        &mut constraints,
        &mut frames,
        OneRttHeader::new(Default::default(), Default::default()).get_type(),
        11,
        16,
    );
    let mut ack = AckFrame::new(0u32.into(), 0u32.into(), 0u32.into(), vec![], None);
    assert!(matches!(
        ack.poll_dump(&mut Context::from_waker(Waker::noop()), &mut buffer),
        Poll::Ready(Ok(0))
    ));
    assert!(buffer.frames.is_empty());
    assert_eq!(buffer.written(), 11);
}
