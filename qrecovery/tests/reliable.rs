use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

use bytes::BytesMut;
use qbase::{
    frame::{HandshakeDoneFrame, ReliableFrame, io::SendFrame},
    packet::{Constraints, GetType, OneRttHeader, Package, PacketBuffer},
};
use qrecovery::reliable::ArcReliableFrames;

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl std::task::Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn only_pending_polls_register_waiters() {
    for (queued, quota, expected) in [
        (1, 1, Poll::Ready(Ok(1))),
        (1, 0, Poll::Ready(Ok(0))),
        (0, 1, Poll::Pending),
    ] {
        let mut queue = ArcReliableFrames::<HandshakeDoneFrame>::with_capacity(2);
        queue.send_frame(std::iter::repeat_n(HandshakeDoneFrame, queued));
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(wakes.clone());
        let mut bytes = BytesMut::new();
        let mut frames = Vec::new();
        let mut limits = Constraints {
            flow_ctrl: 0,
            send_quota: quota,
            credit: 1,
            min_size: 0,
            max_size: 1,
            ..Default::default()
        };
        let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
        let mut buffer = PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0);
        let result = queue.poll_dump(&mut Context::from_waker(&waker), &mut buffer);
        assert_eq!(result, expected);
        queue.send_frame([HandshakeDoneFrame]);
        assert_eq!(
            wakes.0.load(Ordering::Relaxed),
            usize::from(result.is_pending())
        );
    }
}

#[test]
fn reliable_queue_preserves_content_when_only_some_frames_fit() {
    let mut queue: ArcReliableFrames<ReliableFrame> = ArcReliableFrames::with_capacity(2);
    queue.send_frame([HandshakeDoneFrame, HandshakeDoneFrame]);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..2 {
        let mut bytes = BytesMut::new();
        let mut frames = Vec::new();
        let mut limits = Constraints {
            flow_ctrl: 0,
            send_quota: 1,
            credit: 1,
            min_size: 0,
            max_size: 1,
            ..Default::default()
        };
        let mut buffer = PacketBuffer::new(
            &mut bytes,
            &mut limits,
            &mut frames,
            OneRttHeader::new(Default::default(), Default::default()).get_type(),
            0,
            0,
        );
        assert!(matches!(
            queue.poll_dump(&mut cx, &mut buffer),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(buffer.meta.nframes, 1);
        assert_eq!(&bytes[..], &[0x1e]);
    }
    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let mut limits = Constraints {
        send_quota: 1,
        credit: 1,
        max_size: 1,
        ..Default::default()
    };
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let mut buffer = PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0);
    assert!(queue.poll_dump(&mut cx, &mut buffer).is_pending());
    assert!(bytes.is_empty());
    assert!(frames.is_empty());
}
#[test]
fn concrete_frame_queue_keeps_a_blocked_frame_and_reports_empty() {
    let mut queue = ArcReliableFrames::<HandshakeDoneFrame>::with_capacity(1);
    queue.send_frame([HandshakeDoneFrame]);
    let mut bytes = BytesMut::new();
    let mut frames = Vec::new();
    let mut cx = Context::from_waker(Waker::noop());
    let ty = OneRttHeader::new(Default::default(), Default::default()).get_type();
    let mut limits = Constraints {
        flow_ctrl: 0,
        send_quota: 0,
        credit: 1,
        min_size: 0,
        max_size: 1,
        ..Default::default()
    };
    {
        let mut buffer = PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0);
        assert!(matches!(
            queue.poll_dump(&mut cx, &mut buffer),
            Poll::Ready(Ok(0))
        ));
    }
    assert!(bytes.is_empty());
    assert!(frames.is_empty());
    limits.send_quota = 1;
    let mut buffer = PacketBuffer::new(&mut bytes, &mut limits, &mut frames, ty, 0, 0);
    assert!(matches!(
        queue.poll_dump(&mut cx, &mut buffer),
        Poll::Ready(Ok(1))
    ));
    assert!(queue.poll_dump(&mut cx, &mut buffer).is_pending());
    assert_eq!(buffer.meta.nframes, 1);
    assert_eq!(&bytes[..], &[0x1e]);
}
