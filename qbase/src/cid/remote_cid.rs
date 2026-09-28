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
    /// Create a new RemoteCids with the maximum number of active cids,
    /// and the retired cids.
    ///
    /// As mentioned above, the retired cids can be a deque, a channel, or any buffer,
    /// as long as it can send those [`RetireConnectionIdFrame`] to the peer finally.
    /// See [`RemoteCids`]
    fn new(active_cid_limit: u64, retired_cids: RETIRED) -> Self {
        let cid_deque = IndexDeque::default();

        Self {
            active_cid_limit,
            cid_deque,
            ready_cells: Default::default(),
            pending_cells: Default::default(),
            cursor: 0,
            retired_cids,
        }
    }

    fn apply_initial_dcid(&mut self, initial_dcid: ConnectionId, dcid_cell: &ArcCidCell<RETIRED>) {
        assert!(
            self.cid_deque.is_empty() && self.cid_deque.offset() == 0 && self.cursor == 0,
            "NewConnectionIdFrame received before the first initial packet processed"
        );

        self.cid_deque
            .push_back(Some((0, initial_dcid, ResetToken::default())))
            .expect("Initial connection ID should be inserted at the offset 0");

        let handshake_path = self
            .pending_cells
            .iter()
            .enumerate()
            .find_map(|(idx, cell)| Arc::ptr_eq(&cell.0, &dcid_cell.0).then_some(idx))
            .expect("Initial path should be in pending_cells");
        // Move the initial path to the front of the pending cells
        let handshake_path = self.pending_cells.remove(handshake_path).unwrap();
        self.pending_cells.insert(0, handshake_path);

        self.arrange_idle_cid();
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
        let active_len = seq.saturating_sub(retire_prior_to);
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

        // Discard the frame if the sequence number is less than the current offset.
        if seq < self.cid_deque.offset() {
            return Ok(None);
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
                if cell.is_retired() {
                    continue;
                }
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
    /// Create a new RemoteCids with the maximum number of active cids,
    /// and the retired cids.
    ///
    /// As mentioned above, the `retired_cids` can be a deque, a channel, or any buffer,
    /// as long as it can send those [`RetireConnectionIdFrame`] to the peer finally.
    pub fn new(active_cid_limit: u64, retired_cids: RETIRED) -> Self {
        Self(Arc::new(Mutex::new(RemoteCids::new(
            active_cid_limit,
            retired_cids,
        ))))
    }

    /// Apply initial dcid to handshake path.
    ///
    /// dquic implements multi-path handshake feature, the client creates many paths and sends initial packets.
    ///
    /// The client and server must negotiate a handshake path and assign the initial dcid to this path
    /// to prevent the unique connection ID from being obtained by an invalid path, causing the connection to fail.
    ///
    /// The client and server choose the path where they receive the first initial packet as the handshake path.
    /// The server will only return the initial packet on the handshake path to negotiate the handshake path.
    ///
    /// This method should only be called when the connection receives the first initial packet, or panic.
    /// The parameters are the Source Connection Id of the first initial packet received by the connection,
    /// and the [`ArcCidCell`] of the path that passed this packet.
    pub fn apply_initial_dcid(&self, initial_dcid: ConnectionId, dcid_cell: &ArcCidCell<RETIRED>) {
        self.0
            .lock()
            .unwrap()
            .apply_initial_dcid(initial_dcid, dcid_cell);
    }

    /// Apply for a new connection ID, which is used when the Path is created.
    ///
    /// Return an [`ArcCidCell`], which may be not ready state.
    pub fn apply_dcid(&self) -> ArcCidCell<RETIRED> {
        self.0.lock().unwrap().apply_dcid()
    }

    /// Return the latest connection ID issued by the peer.
    ///
    /// The cid is used to assemble the packet that contains a connection close frame. When the
    /// connection is closed, the connection close frame will be sent to the peer.
    pub fn latest_dcid(&self) -> Option<ConnectionId> {
        self.0
            .lock()
            .unwrap()
            .cid_deque
            .iter()
            .rev()
            .flatten()
            .next()
            .map(|(_, cid, _)| *cid)
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
}

impl<RETIRED> CidCell<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    fn assign(&mut self, seq: u64, cid: ConnectionId) {
        assert!(!self.is_retired);
        self.allocated_cids.push_front((seq, cid));
        if !self.is_using {
            while self.allocated_cids.len() > 1 {
                let (seq, _) = self.allocated_cids.pop_back().unwrap();
                let sequence = VarInt::try_from(seq)
                    .expect("Sequence of connection id is very hard to exceed VARINT_MAX");
                self.retired_cids
                    .send_frame([RetireConnectionIdFrame::new(sequence)]);
            }
        }

        if let Some(waker) = self.waker.take() {
            waker.wake_all();
        }
    }

    fn borrow_cid(&mut self, tx_waker: ArcSendWakers) -> Poll<Option<ConnectionId>> {
        if self.is_retired {
            return Poll::Ready(None);
        }

        if self.allocated_cids.is_empty() {
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
        while self.allocated_cids.len() > 1 {
            let (seq, _) = self.allocated_cids.pop_back().unwrap();
            let sequence = VarInt::try_from(seq)
                .expect("Sequence of connection id is very hard to exceed VARINT_MAX");
            self.retired_cids
                .send_frame([RetireConnectionIdFrame::new(sequence)]);
        }
    }

    fn retire(&mut self) {
        if !self.is_retired {
            self.is_retired = true;

            while let Some((seq, _)) = self.allocated_cids.pop_front() {
                let sequence = VarInt::try_from(seq)
                    .expect("Sequence of connection id is very hard to exceed VARINT_MAX");
                self.retired_cids
                    .send_frame([RetireConnectionIdFrame::new(sequence)]);
            }

            if let Some(waker) = self.waker.take() {
                waker.wake_all();
            }
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
        })))
    }

    fn is_retired(&self) -> bool {
        self.0.lock().unwrap().is_retired
    }

    /// Asynchronously get the connection ID, if it is not ready, return Pending.
    ///
    /// If the corresponding path which applied this cid is inactive,
    /// then this cid apply is retired.
    /// In this case, None will be returned.
    pub fn borrow_cid(&'_ self, tx_waker: ArcSendWakers) -> Poll<Option<BorrowedCid<'_, RETIRED>>> {
        self.0.lock().unwrap().borrow_cid(tx_waker).map(|cid| {
            cid.map(|cid| BorrowedCid {
                cid_cell: &self.0,
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
/// While the connection ID is borrowed, the retired cids will not be truly retired. The retire will be delayed until
/// the [`BorrowedCid`] is dropped, a [`RetireConnectionIdFrame`] will be sent to the peer.
pub struct BorrowedCid<'a, RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    cid: ConnectionId,
    cid_cell: &'a Mutex<CidCell<RETIRED>>,
}

impl<RETIRED> Deref for BorrowedCid<'_, RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    type Target = ConnectionId;

    fn deref(&self) -> &Self::Target {
        &self.cid
    }
}

impl<RETIRED> Drop for BorrowedCid<'_, RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    fn drop(&mut self) {
        self.cid_cell.lock().unwrap().renew();
    }
}

#[cfg(test)]
mod tests {
    use derive_more::Deref;

    use super::*;

    #[derive(Debug, Clone, Default, Deref)]
    struct RetiredCids(Arc<Mutex<Vec<RetireConnectionIdFrame>>>);

    impl SendFrame<RetireConnectionIdFrame> for RetiredCids {
        fn send_frame<I: IntoIterator<Item = RetireConnectionIdFrame>>(&self, iter: I) {
            self.0.lock().unwrap().extend(iter);
        }
    }

    #[test]
    fn test_remote_cids() {
        let retired_cids = RetiredCids::default();
        let mut remote_cids = RemoteCids::new(8, retired_cids);

        let initial_dcid = ConnectionId::random_gen(8);
        let cid_apply0 = remote_cids.apply_dcid();
        remote_cids.apply_initial_dcid(initial_dcid, &cid_apply0);

        let waker = ArcSendWakers::default();
        assert!(matches!(
            cid_apply0.borrow_cid(waker.clone()),
            Poll::Ready(Some(cid)) if *cid == initial_dcid
        ));

        // Will return Pending, because the peer hasn't issue any connection id
        let cid_apply1 = remote_cids.apply_dcid();
        assert!(matches!(
            cid_apply1.borrow_cid(waker.clone()),
            Poll::Pending
        ));

        let new_dcid = ConnectionId::random_gen(8);
        let frame = NewConnectionIdFrame::new(new_dcid, VarInt::from_u32(1), VarInt::from_u32(0));
        assert!(remote_cids.recv_new_cid_frame(frame).is_ok());
        assert_eq!(remote_cids.cid_deque.len(), 2);

        assert!(matches!(
            cid_apply0.borrow_cid(waker.clone()),
            Poll::Ready(Some(cid)) if *cid == initial_dcid
        ));
        assert!(matches!(
            cid_apply1.borrow_cid(waker.clone()),
            Poll::Ready(Some(cid)) if *cid == new_dcid
        ));

        // Additionally, a new request will be made because if the peer-issued CID is
        // insufficient, it will still return Pending.
        remote_cids.retire_prior_to(1);
        let cid_apply2 = remote_cids.apply_dcid();
        assert!(cid_apply2.borrow_cid(waker.clone()).is_pending());
        assert!(matches!(
            cid_apply0.borrow_cid(waker.clone()),
            Poll::Ready(Some(cid)) if *cid == initial_dcid
        ));
    }

    #[test]
    fn test_retire_in_remote_cids() {
        let retired_cids = RetiredCids::default();
        let remote_cids = ArcRemoteCids::new(8, retired_cids);

        let initial_dcid = ConnectionId::random_gen(8);
        let cid_apply0 = remote_cids.apply_dcid();
        remote_cids.apply_initial_dcid(initial_dcid, &cid_apply0);

        let mut guard = remote_cids.0.lock().unwrap();

        let mut cids = vec![initial_dcid];
        for seq in 1..8 {
            let cid = ConnectionId::random_gen(8);
            cids.push(cid);
            let frame = NewConnectionIdFrame::new(cid, VarInt::from_u32(seq), VarInt::from_u32(0));
            _ = guard.recv_new_cid_frame(frame);
        }

        let cid_apply1 = guard.apply_dcid();

        let waker = ArcSendWakers::default();
        assert_eq!(cid_apply0.0.lock().unwrap().allocated_cids[0].0, 0);
        assert!(matches!(
            cid_apply0.borrow_cid(waker.clone()),
            Poll::Ready(Some(cid)) if *cid == cids[0]
        ));
        assert_eq!(cid_apply1.0.lock().unwrap().allocated_cids[0].0, 1);
        assert!(matches!(
            cid_apply1.borrow_cid(waker.clone()),
            Poll::Ready(Some(cid)) if *cid == cids[1]
        ));

        guard.retire_prior_to(4);
        assert_eq!(guard.cid_deque.offset(), 4);
        assert_eq!(guard.ready_cells.offset(), 4);
        // delay retire cid
        assert_eq!(guard.retired_cids.0.lock().unwrap().len(), 2);

        assert_eq!(cid_apply0.0.lock().unwrap().allocated_cids[0].0, 0);
        assert_eq!(cid_apply1.0.lock().unwrap().allocated_cids[0].0, 1);

        assert!(matches!(
            cid_apply0.borrow_cid(waker.clone()),
            Poll::Ready(Some(cid)) if *cid == cids[0]
        ));
        assert!(matches!(
            cid_apply1.borrow_cid(waker.clone()),
            Poll::Ready(Some(cid)) if *cid == cids[1]
        ));

        guard.arrange_idle_cid();
        assert_eq!(guard.retired_cids.0.lock().unwrap().len(), 4);

        let retired_cids = [1, 0, 3, 2];
        for seq in retired_cids {
            assert_eq!(
                // like a stack, the last in the first out
                guard.retired_cids.0.lock().unwrap().pop(),
                Some(RetireConnectionIdFrame::new(VarInt::from_u32(seq)))
            );
        }

        assert!(matches!(
            cid_apply0.borrow_cid(waker.clone()),
            Poll::Ready(Some(entry)) if *entry == cids[4]
        ));
        assert!(matches!(
            cid_apply1.borrow_cid(waker.clone()),
           Poll::Ready(Some(entry)) if *entry == cids[5]
        ));

        cid_apply1.retire();
        assert_eq!(guard.retired_cids.lock().unwrap().len(), 1);
        assert_eq!(
            guard.retired_cids.0.lock().unwrap().pop(),
            Some(RetireConnectionIdFrame::new(VarInt::from_u32(5)))
        );
    }

    #[test]
    fn test_retire_without_apply() {
        let retired_cids = RetiredCids::default();
        let remote_cids = ArcRemoteCids::new(8, retired_cids);

        let initial_dcid = ConnectionId::random_gen(8);
        let cid_apply0 = remote_cids.apply_dcid();
        remote_cids.apply_initial_dcid(initial_dcid, &cid_apply0);

        let mut guard = remote_cids.0.lock().unwrap();

        let mut cids = vec![initial_dcid];
        for seq in 1..8 {
            let cid = ConnectionId::random_gen(8);
            cids.push(cid);
            let frame = NewConnectionIdFrame::new(cid, VarInt::from_u32(seq), VarInt::from_u32(0));
            _ = guard.recv_new_cid_frame(frame);
        }

        guard.retire_prior_to(4);
        assert_eq!(guard.cid_deque.offset(), 4);
        assert_eq!(guard.ready_cells.offset(), 4);
        assert_eq!(guard.retired_cids.0.lock().unwrap().len(), 3);

        let cid_apply1 = guard.apply_dcid();
        assert_eq!(cid_apply0.0.lock().unwrap().allocated_cids[0].0, 4);
        assert_eq!(cid_apply1.0.lock().unwrap().allocated_cids[0].0, 5);
        let waker = ArcSendWakers::default();
        assert!(matches!(
            cid_apply0.borrow_cid(waker.clone()),
           Poll::Ready(Some(entry)) if *entry == cids[4]
        ));
        assert!(matches!(
            cid_apply1.borrow_cid(waker.clone()),
            Poll::Ready(Some(entry)) if *entry == cids[5]
        ));
    }
}
