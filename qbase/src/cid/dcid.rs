//! Shared handshake CID source and the destination CID owned by one path.
use std::{
    ops::Deref,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use super::{ArcCidCell, ArcRemoteCids, ConnectionId};
use crate::frame::{RetireConnectionIdFrame, io::SendFrame};

#[derive(Debug, Clone, Copy)]
pub enum HandshakeDcid {
    Odcid(ConnectionId),
    PeerScid(ConnectionId),
}

/// All handshake paths observe the same ODCID -> peer SCID transition.
#[derive(Debug, Clone)]
pub struct ArcHandshakeDcid(Arc<Mutex<HandshakeDcid>>);

impl ArcHandshakeDcid {
    pub fn from_odcid(cid: ConnectionId) -> Self {
        Self(Arc::new(Mutex::new(HandshakeDcid::Odcid(cid))))
    }

    pub fn from_peer_scid(cid: ConnectionId) -> Self {
        Self(Arc::new(Mutex::new(HandshakeDcid::PeerScid(cid))))
    }

    pub fn get(&self) -> HandshakeDcid {
        *self.0.lock().unwrap()
    }

    pub fn cid(&self) -> ConnectionId {
        match self.get() {
            HandshakeDcid::Odcid(cid) | HandshakeDcid::PeerScid(cid) => cid,
        }
    }

    pub(super) fn on_receive_from(&self, peer_scid: ConnectionId) -> bool {
        let mut source = self.0.lock().unwrap();
        match source.deref() {
            HandshakeDcid::Odcid(_) => {
                *source = HandshakeDcid::PeerScid(peer_scid);
                true
            }
            HandshakeDcid::PeerScid(_) => false,
        }
    }
}

#[derive(Debug)]
pub enum Dcid<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    Handshake(ArcHandshakeDcid, ArcRemoteCids<RETIRED>),
    Allocate(ArcCidCell<RETIRED>),
}

impl<RETIRED> Dcid<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    /// Upgrade once using this path's manager; later calls preserve its cell.
    pub fn upgrade(&mut self) {
        if let Self::Handshake(_, remote) = self {
            let cell = remote.allocate_cell();
            *self = Self::Allocate(cell);
        }
    }

    pub fn is_allocated(&self) -> bool {
        matches!(self, Self::Allocate(_))
    }

    /// Start one batch. Return it with [`Self::refresh`] after submission or cancellation.
    pub fn poll_borrow(&self, cx: &mut Context<'_>) -> Poll<Option<ConnectionId>> {
        match self {
            Self::Handshake(source, _) => Poll::Ready(Some(source.cid())),
            Self::Allocate(cell) => cell.poll_borrow(cx),
        }
    }

    pub fn refresh(&self) {
        if let Self::Allocate(cell) = self {
            cell.refresh();
        }
    }

    pub fn retire(&self) {
        if let Self::Allocate(cell) = self {
            cell.retire();
        }
    }
}

impl<RETIRED> Drop for Dcid<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    fn drop(&mut self) {
        self.retire();
        // No sender can still own a batch after the last path handle is dropped.
        self.refresh();
    }
}

/// Shared state for one path. Cloning does not allocate a CID for another path.
#[derive(Debug, Clone)]
pub struct ArcDcid<RETIRED>(Arc<Mutex<Dcid<RETIRED>>>)
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone;

impl<RETIRED> From<Dcid<RETIRED>> for ArcDcid<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    fn from(dcid: Dcid<RETIRED>) -> Self {
        Self(Arc::new(Mutex::new(dcid)))
    }
}

impl<RETIRED> ArcDcid<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    pub fn upgrade(&self) {
        self.0.lock().unwrap().upgrade();
    }

    pub fn is_allocated(&self) -> bool {
        self.0.lock().unwrap().is_allocated()
    }

    pub fn poll_borrow(&self, cx: &mut Context<'_>) -> Poll<Option<ConnectionId>> {
        self.0.lock().unwrap().poll_borrow(cx)
    }

    pub fn refresh(&self) {
        self.0.lock().unwrap().refresh();
    }

    pub fn retire(&self) {
        self.0.lock().unwrap().retire();
    }
}
