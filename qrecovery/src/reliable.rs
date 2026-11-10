//! The reliable transmission for frames.
use std::{
    collections::VecDeque,
    mem,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use bytes::BufMut;
use qbase::{
    frame::{EncodeSize, FrameFeature, io::SendFrame},
    net::tx::UnregisterWaker,
    packet::{Package, PacketBuffer},
    util::WakerGroup,
};

#[derive(Debug, Default)]
struct ReliableFrames<F> {
    frames: VecDeque<F>,
    tx_wakers: WakerGroup,
}

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
pub struct ArcReliableFrames<F>(Arc<Mutex<ReliableFrames<F>>>);

impl<F> Clone for ArcReliableFrames<F> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<F> ArcReliableFrames<F> {
    /// Create a new empty deque with at least the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(ReliableFrames { frames: VecDeque::with_capacity(capacity), tx_wakers: WakerGroup::new() })))
    }

    fn frames_guard(&self) -> MutexGuard<'_, ReliableFrames<F>> {
        self.0.lock().unwrap()
    }
}

impl<T, F> SendFrame<T> for ArcReliableFrames<F>
where
    F: EncodeSize + FrameFeature,
    T: Into<F>,
{
    fn send_frame<I: IntoIterator<Item = T>>(&self, iter: I) {
        let mut queue = self.frames_guard();
        let len = queue.frames.len();
        queue.frames.extend(iter.into_iter().map(Into::into));
        if queue.frames.len() > len {
            let mut wakers = mem::take(&mut queue.tx_wakers);
            drop(queue);
            wakers.wake_all();
        }
    }
}

impl<B: BufMut + ?Sized, F: Package<B>> Package<B> for ArcReliableFrames<F> {
    fn poll_dump(&mut self, cx: &mut Context<'_>, buffer: &mut PacketBuffer<'_, B>) -> Poll<usize> {
        let mut queue = self.frames_guard();
        queue.tx_wakers.remove(cx.waker());
        if queue.frames.is_empty() {
            queue.tx_wakers.add(cx.waker());
            return Poll::Pending;
        }
        let start = buffer.meta.nframes;
        while let Some(frame) = queue.frames.front_mut() {
            match frame.poll_dump(cx, buffer) {
                Poll::Ready(n) if n > 0 => {
                    queue.frames.pop_front();
                }
                Poll::Pending if buffer.meta.nframes == start => {
                    queue.tx_wakers.add(cx.waker());
                    return Poll::Pending;
                }
                _ => break,
            }
        }
        Poll::Ready(buffer.meta.nframes - start)
    }
}

impl<F> UnregisterWaker for ArcReliableFrames<F> {
    fn unregister(&self, waker: &Waker) {
        self.frames_guard().tx_wakers.remove(waker);
    }
}
