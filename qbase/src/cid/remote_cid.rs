use std::{
    collections::VecDeque,
    ops::Deref,
    sync::{Arc, Mutex},
    task::Poll,
};

use super::ConnectionId;
use crate::{
    error::{Error, ErrorKind, QuicError},
    frame::{
        GetFrameType, NewConnectionIdFrame, RetireConnectionIdFrame,
        io::{ReceiveFrame, SendFrame},
    },
    net::tx::ArcSendWakers,
    token::ResetToken,
    util::IndexDeque,
    varint::{VARINT_MAX, VarInt},
};

/// RemoteCids is used to manage the connection IDs issued by the peer,
/// and to send [`RetireConnectionIdFrame`] to the peer.
// TODO: support 0RTT?
#[derive(Debug)]
struct RemoteCids<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    // The cid issued by the peer, the sequence number maybe not continuous
    // since the disordered [`NewConnectionIdFrame`]
    cid_deque: IndexDeque<Option<(u64, ConnectionId, ResetToken)>, VARINT_MAX>,
    // The cell of the connection ID, which is ready in use
    ready_cells: IndexDeque<ArcCidCell<RETIRED>, VARINT_MAX>,
    // The cell of the connection ID, which needs to be assigned or reassigned
    // They can be retired before being assigned or reassigned.
    pending_cells: VecDeque<ArcCidCell<RETIRED>>,
    // The maximum number of connection IDs which is used to check if the
    // maximum number of connection IDs has been exceeded
    // when receiving a [`NewConnectionIdFrame`]
    active_cid_limit: u64,
    // The position of the cid to be used, and the position of the cell to be assigned.
    cursor: u64,
    // The retired cids, each needs send a [`RetireConnectionIdFrame`] to peer
    retired_cids: RETIRED,
}

impl<RETIRED> RemoteCids<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    /// Create a remote CID manager with the peer's Initial SCID and active CID limit.
    ///
    /// As mentioned above, the retired cids can be a deque, a channel, or any buffer,
    /// as long as it can send those [`RetireConnectionIdFrame`] to the peer finally.
    /// See [`RemoteCids`]
    fn new(initial_dcid: ConnectionId, active_cid_limit: u64, retired_cids: RETIRED) -> Self {
        let mut cid_deque = IndexDeque::default();
        cid_deque
            .push_back(Some((0, initial_dcid, ResetToken::default())))
            .expect("Initial connection ID should be inserted at the offset 0");

        Self {
            active_cid_limit,
            cid_deque,
            ready_cells: Default::default(),
            pending_cells: Default::default(),
            cursor: 0,
            retired_cids,
        }
    }

    /// Receive a [`NewConnectionIdFrame`] from peer.
    ///
    /// Add the new connection id to the deque, and retire the old cids before
    /// the retire_prior_to in the [`NewConnectionIdFrame`].
    /// Try to arrange the idle cids to the hungry cid applys if exist.
    ///
    /// Return the reset token of this [`NewConnectionIdFrame`] if it is valid.
    fn recv_new_cid_frame(
        &mut self,
        frame: NewConnectionIdFrame,
    ) -> Result<Option<ResetToken>, Error> {
        let seq = frame.sequence();
        let retire_prior_to = frame.retire_prior_to();
        // Discard frames for CIDs already retired by the peer.
        if seq < self.cid_deque.offset() {
            return Ok(None);
        }

        // Count received, non-retired CIDs after this frame's retirement boundary.
        // Empty slots, retired path cells and retransmissions consume no capacity.
        let active_len = self
            .cid_deque
            .iter()
            .flatten()
            .filter(|(sequence, _, _)| {
                *sequence >= retire_prior_to
                    && self
                        .ready_cells
                        .get(*sequence)
                        .is_none_or(|cell| !cell.is_retired())
            })
            .count() as u64
            + u64::from(self.cid_deque.get(seq).is_none_or(Option::is_none));
        if active_len > self.active_cid_limit {
            return Err(QuicError::new(
                ErrorKind::ConnectionIdLimit,
                frame.frame_type().into(),
                format!(
                    "{active_len} exceed active_cid_limit {}",
                    self.active_cid_limit
                ),
            )
            .into());
        }

        let id = *frame.connection_id();
        let token = *frame.reset_token();
        self.cid_deque.insert(seq, Some((seq, id, token))).unwrap();
        self.retire_prior_to(retire_prior_to);
        self.arrange_idle_cid();

        Ok(Some(token))
    }

    /// Arrange the idle cids to the front of the cid applys
    #[doc(hidden)]
    fn arrange_idle_cid(&mut self) {
        loop {
            let next_unalloced_cell = self.pending_cells.front();
            if next_unalloced_cell.is_none() {
                break;
            }

            let next_unalloced_cell = next_unalloced_cell.unwrap();
            let mut guard = next_unalloced_cell.0.lock().unwrap();
            if guard.is_retired {
                drop(guard);
                self.pending_cells.pop_front();
                continue;
            }

            let next_unused_cid = self.cid_deque.get(self.cursor);
            if let Some(Some((seq, cid, _))) = next_unused_cid {
                guard.assign(*seq, *cid);
                // Until an unused CID is allocated, the guard cannot be released early.
                drop(guard);

                let apply = self.pending_cells.pop_front().unwrap();
                self.ready_cells
                    .push_back(apply)
                    .expect("Sequence of new connection ID should never exceed the limit");
                self.cursor += 1;
            } else {
                break;
            }
        }
    }

    /// Eliminate the old cids and inform the peer with a
    /// [`RetireConnectionIdFrame`] for each retired connection ID.
    #[doc(hidden)]
    fn retire_prior_to(&mut self, tomb_seq: u64) {
        if tomb_seq <= self.ready_cells.offset() {
            return;
        }

        _ = self.cid_deque.drain_to(tomb_seq);
        // it is possible that the connection id that has not been used is directly retired,
        // and there is no chance to assign it, this phenomenon is called "jumping retire cid"
        self.cursor = self.cursor.max(tomb_seq);

        // reassign the cid that has been assigned to the Path but is facing retirement
        if self.ready_cells.is_empty() {
            // it is not necessary to resize the deque, because all elements will be drained
            // // self.cid_cells.resize(seq, ArcCidCell::default()).expect("");
            self.retired_cids
                .send_frame((self.ready_cells.offset()..tomb_seq).map(|seq| {
                    RetireConnectionIdFrame::new(
                        VarInt::from_u64(seq)
                            .expect("Sequence of connection id is very hard to exceed VARINT_MAX"),
                    )
                }));
            self.ready_cells.reset_offset(tomb_seq);
        } else {
            let actual_applied = self.ready_cells.largest();
            let need_reassigned = actual_applied.min(tomb_seq);
            // retire the cids before seq, including the applied and unapplied
            for _ in self.ready_cells.offset()..need_reassigned {
                let (_, cell) = self.ready_cells.pop_front().unwrap();
                let mut guard = cell.0.lock().unwrap();
                if guard.is_retired {
                    continue;
                }
                guard.invalidate();
                drop(guard);
                self.pending_cells.push_back(cell);
            }
            if actual_applied < tomb_seq {
                self.ready_cells.reset_offset(tomb_seq);
                // even the cid that has not been applied is retired right now
                self.retired_cids
                    .send_frame((actual_applied..tomb_seq).map(|seq| {
                        RetireConnectionIdFrame::new(
                            VarInt::from_u64(seq).expect(
                                "Sequence of connection id is very hard to exceed VARINT_MAX",
                            ),
                        )
                    }));
            }
        }
    }

    /// Apply for a new connection ID, and return an [`ArcCidCell`], which may be not ready state.
    fn apply_dcid(&mut self) -> ArcCidCell<RETIRED> {
        let cell = ArcCidCell::new(self.retired_cids.clone());
        self.pending_cells.push_back(cell.clone());
        self.arrange_idle_cid();
        cell
    }
}

/// Shared remote connection ID manager. Most of the time, you should use this struct.
///
/// These connection IDs will be assigned to the Path.
/// Every new path needs to apply for a new connection ID from the RemoteCids.
/// Each path may retire the old connection ID proactively, and apply for a new one.
///
/// `RETIRED` stores the [`RetireConnectionIdFrame`], which need to be sent to the peer.
/// It can be a deque, a channel, or any buffer,
/// as long as it can send those [`RetireConnectionIdFrame`] to the peer finally.
#[derive(Debug, Clone)]
pub struct ArcRemoteCids<RETIRED>(Arc<Mutex<RemoteCids<RETIRED>>>)
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone;

impl<RETIRED> ArcRemoteCids<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    /// Create a remote CID manager with the peer's Initial SCID as sequence zero.
    ///
    /// `active_cid_limit` is the limit advertised by this endpoint. `retired_cids`
    /// sends RETIRE_CONNECTION_ID frames to the peer.
    ///
    /// Construction does not request a CID cell. The first [`Self::apply_dcid`]
    /// gets sequence zero unless the peer has already retired it through a
    /// NEW_CONNECTION_ID frame's retire_prior_to field. The connection's path
    /// CID policy reserves this first cell for its selected handshake path.
    pub fn new(initial_dcid: ConnectionId, active_cid_limit: u64, retired_cids: RETIRED) -> Self {
        Self(Arc::new(Mutex::new(RemoteCids::new(
            initial_dcid,
            active_cid_limit,
            retired_cids,
        ))))
    }

    /// Apply for a CID cell when a path starts sending 1-RTT packets.
    ///
    /// Return an [`ArcCidCell`], which may be not ready state.
    pub fn apply_dcid(&self) -> ArcCidCell<RETIRED> {
        self.0.lock().unwrap().apply_dcid()
    }
}

impl<RETIRED> ReceiveFrame<NewConnectionIdFrame> for ArcRemoteCids<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    type Output = Option<ResetToken>;

    fn recv_frame(&self, frame: NewConnectionIdFrame) -> Result<Self::Output, Error> {
        self.0.lock().unwrap().recv_new_cid_frame(frame)
    }
}

#[derive(Debug)]
struct CidCell<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame>,
{
    retired_cids: RETIRED,
    allocated_cids: VecDeque<(u64, ConnectionId)>,
    waker: Option<ArcSendWakers>,
    is_retired: bool,
    is_using: bool,
    // Old allocations may remain pinned by a borrower while replacement is pending.
    is_pending: bool,
}

impl<RETIRED> CidCell<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    fn assign(&mut self, seq: u64, cid: ConnectionId) {
        assert!(!self.is_retired);
        self.allocated_cids.push_front((seq, cid));
        self.is_pending = false;
        self.release_retired_cids();

        if let Some(waker) = self.waker.take() {
            waker.wake_all();
        }
    }

    fn borrow_cid(&mut self, tx_waker: ArcSendWakers) -> Poll<Option<ConnectionId>> {
        if self.is_retired {
            return Poll::Ready(None);
        }

        if self.is_pending {
            self.waker = Some(tx_waker);
            Poll::Pending
        } else {
            let cid = self.allocated_cids[0].1;
            self.is_using = true;
            Poll::Ready(Some(cid))
        }
    }

    fn renew(&mut self) {
        assert!(self.is_using);
        self.is_using = false;
        self.release_retired_cids();
    }

    /// Stop new borrows without closing this path's binding.
    fn invalidate(&mut self) {
        self.is_pending = true;
        self.release_retired_cids();
    }

    fn release_retired_cids(&mut self) {
        if self.is_using {
            return;
        }
        let keep = usize::from(!self.is_pending && !self.is_retired);
        while self.allocated_cids.len() > keep {
            let (seq, _) = self.allocated_cids.pop_back().unwrap();
            let sequence = VarInt::try_from(seq)
                .expect("Sequence of connection id is very hard to exceed VARINT_MAX");
            self.retired_cids
                .send_frame([RetireConnectionIdFrame::new(sequence)]);
        }
    }

    fn retire(&mut self) {
        self.is_retired = true;
        self.release_retired_cids();
        if let Some(waker) = self.waker.take() {
            waker.wake_all();
        }
    }
}

/// Shared connection ID cell. Most of the time, you should use this struct.
#[derive(Debug, Clone)]
pub struct ArcCidCell<RETIRED>(Arc<Mutex<CidCell<RETIRED>>>)
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone;

impl<RETIRED> ArcCidCell<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    /// Create a new CidCell with the retired cids, the sequence number of the connection ID,
    /// and the state of the connection ID.
    ///
    /// It can be created only by the [`ArcRemoteCids::apply_dcid`] method.
    #[doc(hidden)]
    fn new(retired_cids: RETIRED) -> Self {
        Self(Arc::new(Mutex::new(CidCell {
            retired_cids,
            allocated_cids: VecDeque::with_capacity(2),
            waker: None,
            is_retired: false,
            is_using: false,
            is_pending: true,
        })))
    }

    fn is_retired(&self) -> bool {
        self.0.lock().unwrap().is_retired
    }

    /// Borrow the current CID. Returns Pending both before its first allocation
    /// and while an invalidated CID is waiting for a replacement.
    ///
    /// If the corresponding path which applied this cid is inactive,
    /// then this cid apply is retired.
    /// In this case, None will be returned.
    pub fn borrow_cid(&self, tx_waker: ArcSendWakers) -> Poll<Option<BorrowedCid<RETIRED>>> {
        self.0.lock().unwrap().borrow_cid(tx_waker).map(|cid| {
            cid.map(|cid| BorrowedCid {
                cid_cell: Some(self.0.clone()),
                cid,
            })
        })
    }

    /// When the Path is invalid, the connection id needs to be retired, and this Cell
    /// is marked as no longer in use, with a [`RetireConnectionIdFrame`] being sent to peer.
    pub fn retire(&self) {
        self.0.lock().unwrap().retire();
    }
}

/// A borrowed connection ID, which will be returned back when it is dropped.
///
/// Registry-backed borrows defer CID retirement until they are dropped. Shared
/// handshake snapshots keep the CID chosen when the batch was assembled.
pub struct BorrowedCid<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    cid: ConnectionId,
    cid_cell: Option<Arc<Mutex<CidCell<RETIRED>>>>,
}

impl<RETIRED> BorrowedCid<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    /// Snapshot of the shared handshake CID before a registry cell takes over.
    pub fn shared(cid: ConnectionId) -> Self {
        Self {
            cid,
            cid_cell: None,
        }
    }
}

impl<RETIRED> Deref for BorrowedCid<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    type Target = ConnectionId;

    fn deref(&self) -> &Self::Target {
        &self.cid
    }
}

impl<RETIRED> Drop for BorrowedCid<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    fn drop(&mut self) {
        if let Some(cell) = &self.cid_cell {
            cell.lock().unwrap().renew();
        }
    }
}
