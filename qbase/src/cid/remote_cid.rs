use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use super::{ArcDcid, ArcHandshakeDcid, ConnectionId, Dcid, HandshakeDcid};
use crate::{
    error::{Error, ErrorKind, QuicError},
    frame::{
        GetFrameType, NewConnectionIdFrame, RetireConnectionIdFrame,
        io::{ReceiveFrame, SendFrame},
    },
    token::ResetToken,
    util::IndexDeque,
    varint::{VARINT_MAX, VarInt},
};

#[derive(Debug)]
enum DcidStage {
    Handshake(ArcHandshakeDcid),
    Allocate,
}

/// RemoteCids is used to manage the connection IDs issued by the peer,
/// and to send [`RetireConnectionIdFrame`] to the peer.
// TODO: support 0RTT?
#[derive(Debug)]
struct RemoteCids<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    dcid_stage: DcidStage,
    // The cid issued by the peer, the sequence number maybe not continuous
    // since the disordered [`NewConnectionIdFrame`]
    cid_deque: IndexDeque<Option<(u64, ConnectionId, ResetToken)>, VARINT_MAX>,
    // Cells indexed by their latest assigned connection ID sequence.
    ready_cells: IndexDeque<ArcCidCell<RETIRED>, VARINT_MAX>,
    // The cell of the connection ID, which needs to be assigned or reassigned
    // A replacement request keeps its previous CID usable until assignment.
    // These cells can be retired before being assigned or reassigned.
    pending_cells: VecDeque<ArcCidCell<RETIRED>>,
    // The maximum number of connection IDs which is used to check if the
    // maximum number of connection IDs has been exceeded
    // when receiving a [`NewConnectionIdFrame`]
    active_cid_limit: Option<u64>,
    // The position of the cid to be used, and the position of the cell to be assigned.
    cursor: u64,
    // The retired cids, each needs send a [`RetireConnectionIdFrame`] to peer
    retired_cids: RETIRED,
}

impl<RETIRED> RemoteCids<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    fn new(source: HandshakeDcid, retired_cids: RETIRED) -> Self {
        let mut cid_deque = IndexDeque::default();
        let source = match source {
            HandshakeDcid::Odcid(cid) => ArcHandshakeDcid::from_odcid(cid),
            HandshakeDcid::PeerScid(cid) => {
                cid_deque
                    .push_back(Some((0, cid, ResetToken::default())))
                    .expect("Initial connection ID has sequence zero");
                ArcHandshakeDcid::from_peer_scid(cid)
            }
        };
        Self {
            dcid_stage: DcidStage::Handshake(source),
            active_cid_limit: None,
            cid_deque,
            ready_cells: Default::default(),
            pending_cells: Default::default(),
            cursor: 0,
            retired_cids,
        }
    }

    fn on_receive_from(&mut self, peer_scid: ConnectionId) -> bool {
        let DcidStage::Handshake(source) = &self.dcid_stage else {
            return false;
        };
        if !source.on_receive_from(peer_scid) {
            return false;
        }
        self.cid_deque
            .insert(0, Some((0, peer_scid, ResetToken::default())))
            .expect("Initial connection ID has sequence zero");
        self.arrange_idle_cid();
        true
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
        let active_cid_limit = self
            .active_cid_limit
            .expect("local CID limit set before 1-RTT");
        if active_len > active_cid_limit {
            return Err(QuicError::new(
                ErrorKind::ConnectionIdLimit,
                frame.frame_type().into(),
                format!("{active_len} exceed active_cid_limit {}", active_cid_limit),
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

    /// Queue old path CIDs for replacement; keep them usable until reassigned.
    /// Unallocated CIDs can be retired immediately.
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
            // Queue assigned cells before the boundary for replacement.
            for _ in self.ready_cells.offset()..need_reassigned {
                let (_, cell) = self.ready_cells.pop_front().unwrap();
                if !cell.is_retired() {
                    self.pending_cells.push_back(cell);
                }
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
    fn allocate_cell(&mut self, is_using: bool) -> ArcCidCell<RETIRED> {
        let cell = ArcCidCell::new(self.retired_cids.clone(), is_using);
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
    /// Start client handshaking. ODCID is not an issued connection ID.
    pub fn client(odcid: ConnectionId, retired_cids: RETIRED) -> Self {
        Self(Arc::new(Mutex::new(RemoteCids::new(
            HandshakeDcid::Odcid(odcid),
            retired_cids,
        ))))
    }

    /// Start server handshaking with the peer's SCID as sequence zero.
    pub fn server(client_scid: ConnectionId, retired_cids: RETIRED) -> Self {
        Self(Arc::new(Mutex::new(RemoteCids::new(
            HandshakeDcid::PeerScid(client_scid),
            retired_cids,
        ))))
    }

    /// Set this endpoint's advertised limit before receiving NEW_CONNECTION_ID.
    pub fn set_limit(&self, active_cid_limit: u64) {
        self.0.lock().unwrap().active_cid_limit = Some(active_cid_limit);
    }

    /// Fix the shared peer SCID and install sequence zero only on the first response.
    pub fn on_receive_from(&self, peer_scid: ConnectionId) -> bool {
        self.0.lock().unwrap().on_receive_from(peer_scid)
    }

    /// Future paths allocate immediately; existing handshake paths upgrade separately.
    pub fn upgrade(&self) {
        let mut remote = self.0.lock().unwrap();
        if let DcidStage::Handshake(source) = &remote.dcid_stage {
            assert!(
                matches!(source.get(), HandshakeDcid::PeerScid(_)),
                "peer SCID known before handshake confirmation"
            );
            remote.dcid_stage = DcidStage::Allocate;
        }
    }

    /// Request a distinct path state using the manager's current stage.
    pub fn apply_dcid(&self) -> ArcDcid<RETIRED> {
        let mut remote = self.0.lock().unwrap();
        let dcid = match &remote.dcid_stage {
            DcidStage::Handshake(source) => Dcid::Handshake(source.clone(), self.clone()),
            DcidStage::Allocate => Dcid::Allocate(remote.allocate_cell(false)),
        };
        ArcDcid::from(dcid)
    }

    pub(super) fn allocate_cell(&self) -> ArcCidCell<RETIRED> {
        // A handshake batch may already hold the peer SCID. Keep it until refresh.
        self.0.lock().unwrap().allocate_cell(true)
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
    waker: Option<Waker>,
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
        self.release_retired_cids();

        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    fn poll_borrow(&mut self, cx: &mut Context<'_>) -> Poll<Option<ConnectionId>> {
        if self.is_retired {
            return Poll::Ready(None);
        }

        if self.allocated_cids.is_empty() {
            self.waker = Some(cx.waker().clone());
            Poll::Pending
        } else {
            let cid = self.allocated_cids[0].1;
            self.is_using = true;
            Poll::Ready(Some(cid))
        }
    }

    fn refresh(&mut self) {
        self.is_using = false;
        self.release_retired_cids();
    }

    fn release_retired_cids(&mut self) {
        if self.is_using {
            return;
        }
        let keep = usize::from(!self.is_retired);
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
            waker.wake();
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
    fn new(retired_cids: RETIRED, is_using: bool) -> Self {
        Self(Arc::new(Mutex::new(CidCell {
            retired_cids,
            allocated_cids: VecDeque::with_capacity(2),
            waker: None,
            is_retired: false,
            is_using,
        })))
    }

    fn is_retired(&self) -> bool {
        self.0.lock().unwrap().is_retired
    }

    /// Borrow the current CID, or wait if this cell has never received one.
    /// An assigned CID stays usable until a replacement is available (project policy).
    ///
    /// If the corresponding path which applied this cid is inactive,
    /// then this cid apply is retired.
    /// In this case, None will be returned.
    /// One batch per path may hold a CID until it calls [`Self::refresh`].
    pub fn poll_borrow(&self, cx: &mut Context<'_>) -> Poll<Option<ConnectionId>> {
        self.0.lock().unwrap().poll_borrow(cx)
    }

    /// Return the current batch and release CIDs awaiting retirement.
    /// Keep the current CID until a replacement is assigned or this cell is closed.
    /// Calling this without an outstanding borrow is harmless.
    pub fn refresh(&self) {
        self.0.lock().unwrap().refresh();
    }

    /// When the Path is invalid, the connection id needs to be retired, and this Cell
    /// is marked as no longer in use, with a [`RetireConnectionIdFrame`] being sent to peer.
    pub fn retire(&self) {
        self.0.lock().unwrap().retire();
    }
}
