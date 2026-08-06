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
pub enum Receiving<F> {
    #[default]
    Pending,
    Waiting(Waker),
    Rcvd(F),
    Read,
    Reset,
}

impl<F> Receiving<F> {
    fn recv_frame(&mut self, frame: F) {
        match std::mem::take(self) {
            Self::Pending => {
                *self = Self::Rcvd(frame);
            }
            Self::Waiting(waker) => {
                waker.wake();
                *self = Self::Rcvd(frame);
            }
            _ => (),
        }
    }

    fn reset(&mut self) {
        if let Self::Waiting(waker) = std::mem::replace(self, Self::Reset) {
            waker.wake();
        }
    }
}

#[derive(Debug, Error)]
#[error("Reset")]
pub struct ResetError;

#[derive(Debug, Default, Clone)]
pub struct ArcReceiving<F>(Arc<Mutex<Receiving<F>>>);

impl<F> ArcReceiving<F> {
    pub fn reset(&self) {
        self.0.lock().unwrap().reset();
    }
}

impl<F: Unpin> Future for ArcReceiving<F> {
    type Output = Result<Option<F>, ResetError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.lock().unwrap().poll_unpin(cx)
    }
}

#[cfg(test)]
mod tests {}
