#![allow(clippy::all)]
//! # The QUIC base library
//!
//! The `qbase` library defines the necessary basic structures in the QUIC protocol,
//! including connection IDs, stream IDs, frames, packets, keys, parameters, error codes, etc.
//!
//! Additionally, based on these basic structures,
//! it defines components for various mechanisms in QUIC,
//! including flow control, handshake, tokens, stream ID management, connection ID management, etc.
//!
//! Finally, the `qbase` module also defines some utility functions
//! for handling common data structures in the QUIC protocol.
//!
#![allow(clippy::all)]
use std::{
    ops::{Index, IndexMut},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use futures::FutureExt;
use thiserror::Error;

/// Operations about QUIC connection IDs.
pub mod cid;
/// Non-QUIC datagram envelopes carried alongside QUIC.
pub mod datagram;
/// [QUIC errors](https://www.rfc-editor.org/rfc/rfc9000.html#name-error-codes).
pub mod error;
/// QUIC connection-level flow control.
pub mod flow;
/// QUIC frames and their codec.
pub mod frame;
/// Handshake signal for QUIC connections.
pub mod handshake;
/// QUIC connection metrics for tracking data volumes.
pub mod metric;
/// Endpoint address and Pathway.
pub mod net;
/// QUIC packets and their codec.
pub mod packet;
/// [QUIC transport parameters and their codec](https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-encodin).
pub mod param;
/// QUIC client and server roles.
pub mod role;
/// Stream id types and controllers for different roles and different directions.
pub mod sid;
/// Max idle timer and defer idle timer.
pub mod time;
/// Issuing, storing and verifing tokens operations.
pub mod token;
/// Utilities for common data structures.
pub mod util;
/// [Variable-length integers](https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc).
pub mod varint;

/// The epoch of sending, usually been seen as the index of spaces.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Epoch {
    Initial = 0,
    Handshake = 1,
    Data = 2,
}

pub trait GetEpoch {
    fn epoch(&self) -> Epoch;
}

impl Epoch {
    pub const EPOCHS: [Epoch; 3] = [Epoch::Initial, Epoch::Handshake, Epoch::Data];
    /// An iterator for the epoch of each spaces.
    ///
    /// Equals to `Epoch::EPOCHES.iter()`
    pub fn iter() -> std::slice::Iter<'static, Epoch> {
        Self::EPOCHS.iter()
    }

    /// The number of epoches.
    pub const fn count() -> usize {
        Self::EPOCHS.len()
    }
}

impl<T> Index<Epoch> for [T]
where
    T: Sized,
{
    type Output = T;

    fn index(&self, index: Epoch) -> &Self::Output {
        self.index(index as usize)
    }
}

impl<T> IndexMut<Epoch> for [T]
where
    T: Sized,
{
    fn index_mut(&mut self, index: Epoch) -> &mut Self::Output {
        self.index_mut(index as usize)
    }
}

#[derive(Debug, Default)]
pub enum Receiving<I> {
    #[default]
    Pending,
    Waiting(Waker),
    Rcvd(I),
    Read,
    Cancelled,
}

impl<I> Receiving<I> {
    fn obtain(&mut self, item: I) {
        match self {
            Self::Pending => {
                *self = Self::Rcvd(item);
            }
            Self::Waiting(_) => {
                let Self::Waiting(waker) = std::mem::replace(self, Self::Rcvd(item)) else {
                    unreachable!()
                };
                waker.wake();
            }
            _ => (),
        }
    }

    fn cancel(&mut self) {
        if let Self::Waiting(waker) = std::mem::replace(self, Self::Cancelled) {
            waker.wake();
        }
    }
}

#[derive(Debug, Error)]
#[error("Cancelled")]
pub struct Cancelled;

impl<I: Unpin> Future for Receiving<I> {
    type Output = Result<Option<I>, Cancelled>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let state = self.get_mut();
        match std::mem::replace(state, Self::Read) {
            Self::Pending => {
                *state = Self::Waiting(cx.waker().clone());
                Poll::Pending
            }
            Self::Waiting(mut waker) => {
                if !waker.will_wake(cx.waker()) {
                    waker = cx.waker().clone();
                }
                *state = Self::Waiting(waker);
                Poll::Pending
            }
            Self::Rcvd(item) => Poll::Ready(Ok(Some(item))),
            Self::Read => Poll::Ready(Ok(None)),
            Self::Cancelled => {
                *state = Self::Cancelled;
                Poll::Ready(Err(Cancelled))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArcReceiving<I>(Arc<Mutex<Receiving<I>>>);

impl<I> Default for ArcReceiving<I> {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Receiving::Pending)))
    }
}

impl<I> ArcReceiving<I> {
    pub fn obtain(&self, item: I) {
        self.0.lock().unwrap().obtain(item);
    }

    pub fn cancel(&self) {
        self.0.lock().unwrap().cancel();
    }
}

impl<I: Unpin> Future for ArcReceiving<I> {
    type Output = Result<Option<I>, Cancelled>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.lock().unwrap().poll_unpin(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };

    use super::ArcReceiving;
    //use crate::frame::io::ReceiveFrame;

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn poll<T: Unpin>(
        future: &mut ArcReceiving<T>,
        waker: &Waker,
    ) -> Poll<Result<Option<T>, super::Cancelled>> {
        Future::poll(Pin::new(future), &mut Context::from_waker(waker))
    }

    #[test]
    fn received_frame_wakes_waiter() {
        let mut receiving = ArcReceiving::<u8>::default();
        let wake_counter = Arc::new(WakeCounter::default());
        let waker = Waker::from(wake_counter.clone());

        assert!(poll(&mut receiving, &waker).is_pending());
        receiving.obtain(7);

        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 1);
        assert!(matches!(
            poll(&mut receiving, &waker),
            Poll::Ready(Ok(Some(7)))
        ));
    }

    #[test]
    fn repoll_replaces_cancelled_waiter() {
        let mut receiving = ArcReceiving::<u8>::default();
        let first_counter = Arc::new(WakeCounter::default());
        let first_waker = Waker::from(first_counter.clone());
        let second_counter = Arc::new(WakeCounter::default());
        let second_waker = Waker::from(second_counter.clone());

        assert!(poll(&mut receiving, &first_waker).is_pending());
        assert!(poll(&mut receiving, &second_waker).is_pending());
        receiving.obtain(7);

        assert_eq!(first_counter.0.load(Ordering::Relaxed), 0);
        assert_eq!(second_counter.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn duplicate_frame_does_not_discard_first_frame() {
        let mut receiving = ArcReceiving::default();
        let waker = Waker::noop();

        receiving.obtain(7);
        receiving.obtain(9);

        assert!(matches!(
            poll(&mut receiving, waker),
            Poll::Ready(Ok(Some(7)))
        ));
    }
}
