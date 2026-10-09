//! The reliable transmission for frames.
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use bytes::BufMut;
use qbase::{
    error::Error,
    frame::{EncodeSize, FrameFeature, io::SendFrame},
    net::tx::{ArcSendWakers, UnregisterWaker},
    packet::{Package, PacketBuffer},
};

/// A deque for data space to send reliable frames.
///
/// Like its name, it is just a queue. [`DataStreams`] or other components that need to send reliable
/// frames write frames to this queue by calling [`SendFrame::send_frame`]. The transport layer can
/// load the frames from the queue into the packet by calling [`Package::poll_dump`].
///
/// # Example
/// ```rust, no_run
/// use qbase::frame::{HandshakeDoneFrame, ReliableFrame, io::SendFrame};
/// use qrecovery::reliable::ArcReliableFrames;
/// let mut reliable_frame_deque = ArcReliableFrames::<ReliableFrame>::with_capacity(10);
/// reliable_frame_deque.send_frame([HandshakeDoneFrame]);
/// ```
///
/// [`DataStreams`]: crate::streams::DataStreams
/// [`Package::poll_dump`]: qbase::packet::Package::poll_dump
#[derive(Debug, Default)]
pub struct ArcReliableFrames<F> {
    frames: Arc<Mutex<VecDeque<F>>>,
    tx_wakers: ArcSendWakers,
}

impl<F> Clone for ArcReliableFrames<F> {
    fn clone(&self) -> Self {
        Self {
            frames: self.frames.clone(),
            tx_wakers: self.tx_wakers.clone(),
        }
    }
}

impl<F> ArcReliableFrames<F> {
    /// Create a new empty deque with at least the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            frames: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            tx_wakers: ArcSendWakers::default(),
        }
    }

    fn frames_guard(&self) -> MutexGuard<'_, VecDeque<F>> {
        self.frames.lock().unwrap()
    }
}

impl<T, F> SendFrame<T> for ArcReliableFrames<F>
where
    F: EncodeSize + FrameFeature,
    T: Into<F>,
{
    fn send_frame<I: IntoIterator<Item = T>>(&self, iter: I) {
        self.frames_guard().extend(iter.into_iter().map(Into::into));
        self.tx_wakers.wake_all();
    }
}

impl<B: BufMut + ?Sized, F: Package<B>> Package<B> for ArcReliableFrames<F> {
    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut PacketBuffer<'_, B>,
    ) -> Poll<Result<usize, Error>> {
        let mut queue = self.frames_guard();
        if queue.is_empty() {
            self.tx_wakers.register(cx.waker());
            return Poll::Pending;
        }
        let start = buffer.meta.nframes;
        while let Some(frame) = queue.front_mut() {
            match frame.poll_dump(cx, buffer) {
                Poll::Ready(Ok(n)) if n > 0 => {
                    queue.pop_front();
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending if buffer.meta.nframes == start => {
                    self.tx_wakers.register(cx.waker());
                    return Poll::Pending;
                }
                _ => break,
            }
        }
        Poll::Ready(Ok(buffer.meta.nframes - start))
    }
}

impl<F> UnregisterWaker for ArcReliableFrames<F> {
    fn unregister(&self, waker: &Waker) {
        self.tx_wakers.unregister(waker);
    }
}

#[cfg(test)]
mod tests {
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

    use super::ArcReliableFrames;

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
        assert!(queue.frames_guard().is_empty());
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
}
