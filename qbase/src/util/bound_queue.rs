use std::{
    self,
    future::poll_fn,
    sync::{Arc, Mutex},
};

use futures::{SinkExt, StreamExt, channel::mpsc};

#[derive(Debug)]
struct BoundQueueInner<T> {
    tx: Mutex<mpsc::Sender<T>>,
    rx: Mutex<mpsc::Receiver<T>>,
}

#[derive(Debug)]
pub struct BoundQueue<T>(Arc<BoundQueueInner<T>>);

impl<T> Clone for BoundQueue<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> BoundQueue<T> {
    #[inline]
    pub fn new(size: usize) -> Self {
        let (tx, rx) = mpsc::channel(size);
        Self(Arc::new(BoundQueueInner {
            tx: tx.into(),
            rx: rx.into(),
        }))
    }

    #[inline]
    pub fn try_send(&self, item: T) -> Result<(), mpsc::TrySendError<T>> {
        self.0.tx.lock().unwrap().try_send(item)
    }

    #[inline]
    pub async fn send(&self, item: T) -> Result<(), mpsc::SendError> {
        let mut tx = self.0.tx.lock().unwrap().clone();
        tx.send(item).await
    }

    #[inline]
    pub async fn recv(&self) -> Option<T> {
        poll_fn(|cx| self.0.rx.lock().unwrap().poll_next_unpin(cx)).await
    }

    #[inline]
    pub fn close(&self) {
        self.0.tx.lock().unwrap().close_channel();
    }

    #[inline]
    pub fn is_closed(&self) -> bool {
        self.0.tx.lock().unwrap().is_closed()
    }

    #[inline]
    pub fn same_queue(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

#[cfg(test)]
mod tests {

    use tracing::Instrument as _;

    use super::*;

    #[tokio::test]
    async fn test_send_receive() {
        let queue = Arc::new(BoundQueue::new(2));

        tokio::spawn({
            let queue = queue.clone();
            async move {
                assert!(queue.send(1).await.is_ok());
                assert!(queue.send(2).await.is_ok());
            }
            .in_current_span()
        });

        assert_eq!(queue.recv().await, Some(1));
        assert_eq!(queue.recv().await, Some(2));
    }

    #[tokio::test]
    async fn try_send_remains_bounded() {
        let queue = BoundQueue::new(2);

        assert!(queue.try_send(1).is_ok());
        assert!(queue.try_send(2).is_ok());
        // futures gives each persistent sender one guaranteed slot in addition to the buffer.
        assert!(queue.try_send(3).is_ok());
        assert!(queue.try_send(4).is_err_and(|error| error.is_full()));

        assert_eq!(queue.recv().await, Some(1));
        assert_eq!(queue.recv().await, Some(2));
        assert_eq!(queue.recv().await, Some(3));
    }
}
