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
    /// Create a remote CID manager with the peer's Initial SCID as sequence zero.
    ///
    /// `active_cid_limit` is the limit advertised by this endpoint. `retired_cids`
    /// sends RETIRE_CONNECTION_ID frames to the peer.
    ///
    /// Construction does not request a CID cell. The first [`Self::apply_dcid`]
    /// gets sequence zero unless the peer has already retired it through a
    /// NEW_CONNECTION_ID frame's retire_prior_to field. With multiple paths,
    /// the selected sender must request its cell before the other senders.
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
        if self.is_retired {
            self.retire();
            return;
        }
        while self.allocated_cids.len() > 1 {
            let (seq, _) = self.allocated_cids.pop_back().unwrap();
            let sequence = VarInt::try_from(seq)
                .expect("Sequence of connection id is very hard to exceed VARINT_MAX");
            self.retired_cids
                .send_frame([RetireConnectionIdFrame::new(sequence)]);
        }
    }

    fn retire(&mut self) {
        self.is_retired = true;
        if !self.is_using {
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
    pub fn borrow_cid(&self, tx_waker: ArcSendWakers) -> Poll<Option<BorrowedCid<RETIRED>>> {
        self.0.lock().unwrap().borrow_cid(tx_waker).map(|cid| {
            cid.map(|cid| BorrowedCid {
                cid_cell: self.0.clone(),
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
pub struct BorrowedCid<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    cid: ConnectionId,
    cid_cell: Arc<Mutex<CidCell<RETIRED>>>,
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
    fn borrowed_cid_outlives_the_cell_handle_and_defers_path_retirement() {
        let retired = RetiredCids::default();
        let cid = ConnectionId::from_slice(b"client00");
        let remote = ArcRemoteCids::new(cid, 2, retired.clone());
        let cell = remote.apply_dcid();
        let Poll::Ready(Some(borrowed)) = cell.borrow_cid(ArcSendWakers::default()) else {
            panic!("initial CID is ready");
        };
        cell.retire();
        assert!(retired.lock().unwrap().is_empty());
        assert!(matches!(
            cell.borrow_cid(ArcSendWakers::default()),
            Poll::Ready(None)
        ));
        drop(cell);
        assert_eq!(*borrowed, cid);
        drop(borrowed);
        assert_eq!(retired.lock().unwrap().len(), 1);
    }

    #[test]
    fn construction_leaves_allocation_to_the_first_sender() {
        let initial = ConnectionId::from_slice(b"client00");
        let next = ConnectionId::from_slice(b"client01");
        let mut remote = RemoteCids::new(initial, 4, RetiredCids::default());
        assert_eq!(remote.cursor, 0);
        assert!(remote.ready_cells.is_empty());
        assert!(remote.pending_cells.is_empty());

        remote
            .recv_new_cid_frame(NewConnectionIdFrame::new(next, 1u32.into(), 0u32.into()))
            .unwrap();
        let selected = remote.apply_dcid();
        assert!(matches!(selected.borrow_cid(ArcSendWakers::default()),
            Poll::Ready(Some(cid)) if *cid == initial));
        let other = remote.apply_dcid();
        assert!(matches!(other.borrow_cid(ArcSendWakers::default()),
            Poll::Ready(Some(cid)) if *cid == next));
    }

    #[test]
    fn initial_cid_can_be_retired_before_any_sender_requests_a_cell() {
        let remote = ArcRemoteCids::new(
            ConnectionId::from_slice(b"client00"),
            2,
            RetiredCids::default(),
        );
        let next = ConnectionId::from_slice(b"client01");
        remote
            .recv_frame(NewConnectionIdFrame::new(next, 1u32.into(), 1u32.into()))
            .unwrap();
        let selected = remote.apply_dcid();
        assert!(matches!(selected.borrow_cid(ArcSendWakers::default()),
            Poll::Ready(Some(cid)) if *cid == next));
    }

    #[test]
    fn selected_server_limit_counts_initial_and_new_cids() {
        let initial = ConnectionId::from_slice(b"client00");
        let remote = ArcRemoteCids::new(initial, 8, RetiredCids::default());
        let cell = remote.apply_dcid();

        for seq in 1..8u32 {
            let frame = NewConnectionIdFrame::new(
                ConnectionId::from_slice(&u64::from(seq).to_be_bytes()),
                VarInt::from_u32(seq),
                VarInt::from_u32(0),
            );
            assert!(remote.recv_frame(frame).is_ok());
        }
        assert!(matches!(
            cell.borrow_cid(ArcSendWakers::default()),
            Poll::Ready(Some(cid)) if *cid == initial
        ));

        let frame = NewConnectionIdFrame::new(
            ConnectionId::from_slice(b"client08"),
            VarInt::from_u32(8),
            VarInt::from_u32(0),
        );
        assert!(matches!(remote.recv_frame(frame), Err(Error::Quic(error))
            if error.kind() == ErrorKind::ConnectionIdLimit));
    }

    #[test]
    fn test_remote_cids() {
        let retired_cids = RetiredCids::default();
        let initial_dcid = ConnectionId::random_gen(8);
        let mut remote_cids = RemoteCids::new(initial_dcid, 8, retired_cids);
        let cid_apply0 = remote_cids.apply_dcid();

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
        let initial_dcid = ConnectionId::random_gen(8);
        let remote_cids = ArcRemoteCids::new(initial_dcid, 8, retired_cids);
        let cid_apply0 = remote_cids.apply_dcid();

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
        let initial_dcid = ConnectionId::random_gen(8);
        let remote_cids = ArcRemoteCids::new(initial_dcid, 8, retired_cids);
        let cid_apply0 = remote_cids.apply_dcid();

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
