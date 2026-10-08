use std::sync::{Arc, Mutex};

use super::{ConnectionId, GenUniqueCid, RetireCid};
use crate::{
    error::{Error, ErrorKind, QuicError},
    frame::{
        FrameType, GetFrameType, NewConnectionIdFrame, RetireConnectionIdFrame,
        io::{ReceiveFrame, SendFrame},
    },
    role::Role,
    token::ResetToken,
    util::IndexDeque,
    varint::{VARINT_MAX, VarInt},
};

/// Local connection ID management.
#[derive(Debug)]
struct LocalCids<ISSUED>
where
    ISSUED: GenUniqueCid + RetireCid + SendFrame<NewConnectionIdFrame>,
{
    role: Role,
    odcid: ConnectionId,
    // If the item in cid_deque is None, it means the connection ID has been retired.
    cid_deque: IndexDeque<Option<(ConnectionId, ResetToken)>, VARINT_MAX>,
    // Each issued connection ID will be written into this issued_cids.
    // The frames in issued_cids should be able to enter the QUIC sending channel
    // and be reliably sent to the peer finally.
    issued_cids: ISSUED,
    // This is an integer value specifying the maximum number of active connection
    // IDs limited by peer.
    // While the client does not know the server's parameters at the beginning,
    // it can be set to None and will be reset.
    // If this transport parameter is absent, a default of 2 is assumed.
    active_cid_limit: Option<u64>,
}

impl<ISSUED> LocalCids<ISSUED>
where
    ISSUED: GenUniqueCid + RetireCid + SendFrame<NewConnectionIdFrame>,
{
    /// Create a new local connection ID manager.
    fn new(role: Role, odcid: ConnectionId, scid: ConnectionId, issued_cids: ISSUED) -> Self {
        let mut cid_deque = IndexDeque::default();
        cid_deque
            .push_back(Some((scid, ResetToken::default())))
            .unwrap();

        let new_cid = issued_cids.gen_unique_cid();
        let new_cid_frame =
            NewConnectionIdFrame::new(new_cid, VarInt::from_u32(1), VarInt::from_u32(0));
        issued_cids.send_frame([new_cid_frame]);
        cid_deque
            .push_back(Some((
                *new_cid_frame.connection_id(),
                *new_cid_frame.reset_token(),
            )))
            .unwrap();
        Self {
            role,
            odcid,
            cid_deque,
            issued_cids,
            active_cid_limit: None,
        }
    }

    fn initial_scid(&self) -> Option<ConnectionId> {
        self.cid_deque.get(0)?.map(|(cid, _)| cid)
    }

    /// Set the maximum number of active connection IDs.
    ///
    /// The value of the active_connection_id_limit parameter MUST be at least 2.
    /// An endpoint that receives a value less than 2 MUST close the connection
    /// with an error of type TRANSPORT_PARAMETER_ERROR.
    fn set_limit(&mut self, active_cid_limit: u64) -> Result<(), Error> {
        debug_assert!(self.active_cid_limit.is_none());
        if active_cid_limit < 2 {
            return Err(QuicError::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto.into(),
                format!("active connection id limit {active_cid_limit} < 2"),
            )
            .into());
        }
        for _ in self.cid_deque.largest()..active_cid_limit {
            self.issue_new_cid();
        }
        self.active_cid_limit = Some(active_cid_limit);
        Ok(())
    }

    /// Issue a new connection ID, for internal used only.
    fn issue_new_cid(&mut self) {
        let seq = VarInt::from_u64(self.cid_deque.largest()).unwrap();
        let retire_prior_to = VarInt::from_u64(self.cid_deque.offset()).unwrap();
        let new_cid = self.issued_cids.gen_unique_cid();
        let new_cid_frame = NewConnectionIdFrame::new(new_cid, seq, retire_prior_to);
        self.issued_cids.send_frame([new_cid_frame]);
        self.cid_deque.push_back(Some((*new_cid_frame.connection_id(), *new_cid_frame.reset_token())))
            .expect("it's very very hard to issue a new connection ID whose sequence excceeds VARINT_MAX");
    }

    /// Receive a [`RetireConnectionIdFrame`] from the peer,
    /// retire the connection IDs of the sequence in [`RetireConnectionIdFrame`].
    fn recv_retire_cid_frame(&mut self, frame: RetireConnectionIdFrame) -> Result<(), Error> {
        let seq = frame.sequence();
        if seq >= self.cid_deque.largest() {
            return Err(QuicError::new(
                ErrorKind::ConnectionIdLimit,
                frame.frame_type().into(),
                format!(
                    "Sequence({seq}) in RetireConnectionIdFrame exceeds the largest one({}) issued by us",
                    self.cid_deque.largest().saturating_sub(1)
                ),
            ).into());
        }

        if let Some(value) = self.cid_deque.get_mut(seq) {
            if let Some((cid, _)) = value.take() {
                let n = self.cid_deque.iter().take_while(|v| v.is_none()).count();
                self.cid_deque.advance(n);

                // generates a new connection ID while retiring an old one.
                self.issue_new_cid();
                self.issued_cids.retire_cid(cid);
            }
        }
        Ok(())
    }

    fn clear(&mut self) {
        for (cid, _reset_token) in self.cid_deque.drain_to(self.cid_deque.largest()).flatten() {
            self.issued_cids.retire_cid(cid);
        }
        if self.role == Role::Server {
            self.issued_cids.retire_cid(self.odcid);
        }
    }
}

impl<ISSUED> Drop for LocalCids<ISSUED>
where
    ISSUED: GenUniqueCid + RetireCid + SendFrame<NewConnectionIdFrame>,
{
    fn drop(&mut self) {
        self.clear();
    }
}

/// Shared local connection ID manager. Most times, you should use this struct.
///
/// Responsible for generating and issuing connection IDs to the peer.
/// The number of active connection IDs is limited by the peer's active_cid_limit.
///
/// - `ISSUED`: is a struct that can generate unique connection id and finally send the new
///   issued connection ID frame to the peer.
///   It can be a channel, a queue, or a buffer. Whatever, it must be able to send the
///   [`NewConnectionIdFrame`] to the peer.
///
/// ## Note
///
/// The generated connection ID will be added to the packet reception routing table,
/// which is shared with other QUIC connections.
/// Therefore, the generated connection ID must not duplicate other local connection IDs,
/// including connection IDs of other connections,
/// and those issued to the peer and have not been retired,
/// otherwise routing conflicts will occur.
#[derive(Debug, Clone)]
pub struct ArcLocalCids<ISSUED>(Arc<Mutex<LocalCids<ISSUED>>>)
where
    ISSUED: GenUniqueCid + RetireCid + SendFrame<NewConnectionIdFrame>;

impl<ISSUED> ArcLocalCids<ISSUED>
where
    ISSUED: GenUniqueCid + RetireCid + SendFrame<NewConnectionIdFrame>,
{
    /// Create a new share local connection ID manager.
    ///
    /// - `odcid` is the destination CID in the client's first Initial packet.
    ///   Servers retain its route until this manager is cleared or dropped.
    /// - `scid` is set initially, whether it is a client or a server,
    ///   they both get their early `scid` externally.
    /// - `issued_cids` is responsible for generating CIDs that do not conflict
    ///   in the packet reception routing table and will also be responsible for
    ///   eventually sending the [`NewConnectionIdFrame`] to the peer.
    pub fn new(role: Role, odcid: ConnectionId, scid: ConnectionId, issued_cids: ISSUED) -> Self {
        let raw_local_cids = LocalCids::new(role, odcid, scid, issued_cids);
        Self(Arc::new(Mutex::new(raw_local_cids)))
    }

    pub fn role(&self) -> Role {
        self.0.lock().unwrap().role
    }

    pub fn origin_dcid(&self) -> ConnectionId {
        self.0.lock().unwrap().odcid
    }

    /// Get the initial source connection ID.
    ///
    /// 0-RTT packets in the first flight use the same Destination Connection ID
    /// and Source Connection ID values as the client's first Initial packet.
    /// see [Section 7.2.6](https://datatracker.ietf.org/doc/html/rfc9000#section-7.2-6)
    /// of [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000).
    ///
    /// Once a client has received a valid Initial packet from the server,
    /// it MUST discard any subsequent packet it receives on that connection
    /// with a different Source Connection ID,
    /// see [Section 7.2.7](https://datatracker.ietf.org/doc/html/rfc9000#section-7.2-7)
    /// of [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000).
    ///
    /// Any further changes to the Destination Connection ID are only permitted
    /// if the values are taken from NEW_CONNECTION_ID frames;
    /// if subsequent Initial packets include a different Source Connection ID,
    /// they MUST be discarded,
    /// see [Section 7.2.8](https://datatracker.ietf.org/doc/html/rfc9000#section-7.2-8)
    /// of [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000) for more details.
    ///
    /// It means that the initial source connection ID is the only one that can be used
    /// to send the Initial, 0Rtt and Handshake packets.
    /// Changing the scid is like issuing a new connection ID to the peer,
    /// without specifying a sequence number or Stateless Reset Token.
    /// Changing the scid during the Handshake phase is meaningless and harmful.
    ///
    /// For the server, even though the server provides the preferred address
    /// as the first connection ID, and even though the server can use this
    /// connection ID as the scid in the Handshake packet, it is not necessary.
    /// The client could not eliminate the zero connection ID before entering 1RTT.
    /// When the client actually eliminates the zero connection ID,
    /// it means that 1RTT packets have already started to be transmitted,
    /// and all subsequent transmissions should be through 1RTT packets.
    ///
    /// Return None if the initial source connection ID has been retired,
    /// which indicates that the connection has been established,
    /// and only the short header packet should be used.
    pub fn initial_scid(&self) -> Option<ConnectionId> {
        self.0.lock().unwrap().initial_scid()
    }

    /// Unilaterally no longer use all local connection IDs, including the server's ODCID route.
    ///
    /// No longer used means that packets sent by the peer to that connection ID are no
    /// longer accepted. This method is called when the Termination event occurs and `LocalCids`
    /// dropped, to clean up the state of the connection after the connection ends.
    ///
    /// In some rare cases, there are still connection IDs issued after the Termination event occurs,
    /// resulting in incomplete cleaning of the connection status.
    /// After externally receiving the Termination event, the connection instance should be dropped
    /// as early as possible to trigger another cleanup in the [`Drop`] implementation to
    /// completely clean up connection's state.
    pub fn clear(&self) {
        self.0.lock().unwrap().clear();
    }

    /// Set the maximum number of active connection IDs.
    ///
    /// After fully obtaining the peer's connection parameters, extract the peer's
    /// active_cid_limit parameter and set it through this method.
    pub fn set_limit(&self, active_cid_limit: u64) -> Result<(), Error> {
        self.0.lock().unwrap().set_limit(active_cid_limit)
    }
}

impl<ISSUED> ReceiveFrame<RetireConnectionIdFrame> for ArcLocalCids<ISSUED>
where
    ISSUED: GenUniqueCid + RetireCid + SendFrame<NewConnectionIdFrame>,
{
    type Output = ();

    /// Receive a [`RetireConnectionIdFrame`] from the peer,
    /// retire the connection IDs of the sequence in [`RetireConnectionIdFrame`].
    fn recv_frame(
        &self,
        frame: RetireConnectionIdFrame,
    ) -> Result<Self::Output, crate::error::Error> {
        self.0.lock().unwrap().recv_retire_cid_frame(frame)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::MutexGuard};

    use super::*;

    #[derive(Default)]
    struct IssuedCids {
        frames: Mutex<Vec<NewConnectionIdFrame>>,
        active_cids: Mutex<HashMap<ConnectionId, ResetToken>>,
    }

    impl IssuedCids {
        fn frames(&self) -> MutexGuard<'_, Vec<NewConnectionIdFrame>> {
            self.frames.lock().unwrap()
        }

        fn active_cids(&self) -> MutexGuard<'_, HashMap<ConnectionId, ResetToken>> {
            self.active_cids.lock().unwrap()
        }
    }

    impl GenUniqueCid for IssuedCids {
        fn gen_unique_cid(&self) -> ConnectionId {
            let mut local_cids = self.active_cids.lock().unwrap();
            let unique_cid =
                core::iter::from_fn(|| Some(ConnectionId::random_gen_with_mark(8, 0x80, 0x7F)))
                    .find(|cid| !local_cids.contains_key(cid))
                    .unwrap();

            local_cids.insert(unique_cid, ResetToken::default());
            unique_cid
        }
    }

    impl RetireCid for IssuedCids {
        fn retire_cid(&self, cid: ConnectionId) {
            self.active_cids.lock().unwrap().remove(&cid);
        }
    }

    impl SendFrame<NewConnectionIdFrame> for IssuedCids {
        fn send_frame<I: IntoIterator<Item = NewConnectionIdFrame>>(&self, iter: I) {
            self.frames.lock().unwrap().extend(iter);
        }
    }

    #[test]
    fn test_issue_cid() {
        let initial_scid = ConnectionId::random_gen(8);
        let local_cids = ArcLocalCids::new(
            Role::Client,
            ConnectionId::random_gen(8),
            initial_scid,
            IssuedCids::default(),
        );
        let mut local_cids = local_cids.0.lock().unwrap();

        assert_eq!(local_cids.cid_deque.len(), 2);

        local_cids.set_limit(3).unwrap();
        assert_eq!(local_cids.cid_deque.len(), 3);
    }

    #[test]
    fn test_recv_retire_cid_frame() {
        let initial_scid = ConnectionId::random_gen(8);
        let mut local_cids = LocalCids::new(
            Role::Client,
            ConnectionId::random_gen(8),
            initial_scid,
            IssuedCids::default(),
        );

        assert_eq!(local_cids.cid_deque.len(), 2);
        assert_eq!(local_cids.issued_cids.frames().len(), 1);

        let issued_cid2 = *local_cids.issued_cids.frames()[0].connection_id();

        let retire_frame = RetireConnectionIdFrame::new(VarInt::from_u32(1));
        let cid2 = local_cids.recv_retire_cid_frame(retire_frame);
        assert!(cid2.is_ok());
        assert!(
            !local_cids
                .issued_cids
                .active_cids()
                .contains_key(&issued_cid2)
        );
        assert_eq!(local_cids.cid_deque.get(1), Some(&None));
        // issued new cid while retiring an old one
        assert_eq!(local_cids.cid_deque.len(), 3);
        assert_eq!(local_cids.issued_cids.frames().len(), 2);

        let retire_frame = RetireConnectionIdFrame::new(VarInt::from_u32(0));
        let cid1 = local_cids.recv_retire_cid_frame(retire_frame);
        assert!(cid1.is_ok());
        assert!(
            !local_cids
                .issued_cids
                .active_cids()
                .contains_key(&initial_scid)
        );
        assert_eq!(local_cids.cid_deque.get(0), None); // have been slided out

        assert_eq!(local_cids.cid_deque.len(), 2);
        assert_eq!(local_cids.issued_cids.frames().len(), 3);

        let retire_frame = RetireConnectionIdFrame::new(VarInt::from_u32(2));
        let cid3 = local_cids.recv_retire_cid_frame(retire_frame);
        assert!(cid3.is_ok());
    }
}
