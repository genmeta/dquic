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
