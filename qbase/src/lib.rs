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
    ops::{Deref, DerefMut},
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
/// Endpoint defination
pub mod endpoint;
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
/// Per-path address validation and anti-amplification credit.
pub mod validate;
/// [Variable-length integers](https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc).
pub mod varint;

pub use qtls::Epoch;

/// A component that stops serving application work when its connection closes.
pub trait Close: Send + Sync {
    fn close_with_error(&self, error: error::Error);
}

/// Register an owning component without retaining it through the close registry.
impl<T: Close> Close for std::sync::Weak<T> {
    fn close_with_error(&self, error: error::Error) {
        if let Some(component) = self.upgrade() {
            component.close_with_error(error);
        }
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

    fn is_received(&self) -> bool {
        matches!(self, Self::Rcvd(_) | Self::Read)
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

/// A pending assignment, submitted when the guard is dropped.
///
/// The slot starts empty and does not expose an already received value.
/// Leaving it empty does not change the receiver. No lock is held until submission.
#[must_use = "assign a value to the guard to submit it on drop"]
pub struct ReceivingGuard<'a, I> {
    receiving: &'a ArcReceiving<I>,
    item: Option<I>,
}

impl<I> Deref for ReceivingGuard<'_, I> {
    type Target = Option<I>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.item
    }
}

impl<I> DerefMut for ReceivingGuard<'_, I> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.item
    }
}

impl<I> Drop for ReceivingGuard<'_, I> {
    #[inline]
    fn drop(&mut self) {
        if let Some(item) = self.item.take() {
            self.receiving.obtain(item);
        }
    }
}

impl<I> Default for ArcReceiving<I> {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Receiving::Pending)))
    }
}

impl<I> ArcReceiving<I> {
    /// Submits the first value and wakes the waiter, if any.
    #[inline]
    pub fn obtain(&self, item: I) {
        self.0.lock().unwrap().obtain(item);
    }

    pub fn is_received(&self) -> bool {
        self.0.lock().unwrap().is_received()
    }

    /// Submits a value with the same semantics as [`Self::obtain`].
    #[inline]
    pub fn set(&self, item: I) {
        self.obtain(item);
    }

    /// Returns an empty assignment slot, submitted when its guard is dropped.
    ///
    /// ```
    /// let receiving = qbase::ArcReceiving::default();
    /// *receiving.as_mut() = Some(7);
    /// # assert_eq!(futures::executor::block_on(receiving).unwrap(), Some(7));
    /// ```
    #[inline]
    pub fn as_mut(&self) -> ReceivingGuard<'_, I> {
        ReceivingGuard {
            receiving: self,
            item: None,
        }
    }

    /// Submits a value with the same semantics as [`Self::obtain`].
    #[inline]
    pub fn with(&self, item: I) {
        self.obtain(item);
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
