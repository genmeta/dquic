use std::sync::{Arc, Mutex};

use thiserror::Error;

use super::{ControlStreamsConcurrency, Dir, Role, StreamId};
use crate::{
    frame::{
        MaxStreamsFrame, StreamsBlockedFrame,
        io::{ReceiveFrame, SendFrame},
    },
    varint::VarInt,
};

/// Exceed the maximum stream ID limit error,
/// similar with [`ErrorKind::StreamLimit`](`crate::error::ErrorKind::StreamLimit`).
///
/// This error occurs when the stream ID in the received stream-related frames
/// exceeds the maximum stream ID limit.
#[derive(Debug, PartialEq, Error)]
#[error("{0} exceed limit: {1}")]
pub struct ExceedLimitError(StreamId, u64);

/// Accept the stream ID received from peer,
/// returned by [`ArcRemoteStreamIds::try_accept_sid`].
#[derive(Debug, PartialEq)]
pub enum AcceptSid {
    /// Indicates that the stream ID is already exist.
    Old,
    /// Indicates that the stream ID is new and need to create.
    /// The `NeedCreate` inside indicates the range of stream IDs that need to be created together.
    New(NeedCreate),
}

/// The range of stream IDs that need to be created,
/// see [`ArcRemoteStreamIds::try_accept_sid`] and [`AcceptSid::New`].
#[derive(Debug, PartialEq)]
pub struct NeedCreate {
    start: StreamId,
    end: StreamId,
}

impl Iterator for NeedCreate {
    type Item = StreamId;
    fn next(&mut self) -> Option<Self::Item> {
        if self.start > self.end {
            None
        } else {
            // Safety: Since being generated from "StreamIds", they could not overflow.
            let id = self.start;
            self.start = unsafe { self.start.next_unchecked() };
            Some(id)
        }
    }
}

/// Remote stream IDs management.
#[derive(Debug)]
struct RemoteStreamIds<MAX> {
    role: Role,                               // The role of the peer
    max: [u64; 2],                            // The maximum stream ID that limit peer to create
    unallocated: [StreamId; 2],               // The stream ID that peer has not used
    ctrl: Box<dyn ControlStreamsConcurrency>, // The strategy to control the concurrency of streams
    max_tx: MAX,                              // The channel to send the MAX_STREAMS frame to peer
}

impl<MAX> RemoteStreamIds<MAX>
where
    MAX: SendFrame<MaxStreamsFrame> + Clone + Send + 'static,
{
    /// Create a new [`RemoteStreamIds`] with the given role,
    /// and maximum number of streams that can be created by peer in each [`Dir`].
    fn new(
        role: Role,
        max_bi: u64,
        max_uni: u64,
        max_tx: MAX,
        ctrl: Box<dyn ControlStreamsConcurrency>,
    ) -> Self {
        Self {
            role,
            max: [max_bi, max_uni],
            unallocated: [
                StreamId::new(role, Dir::Bi, 0),
                StreamId::new(role, Dir::Uni, 0),
            ],
            ctrl,
            max_tx,
        }
    }

    /// Returns the role of the peer.
    fn role(&self) -> Role {
        self.role
    }

    fn try_accept_sid(&mut self, sid: StreamId) -> Result<AcceptSid, ExceedLimitError> {
        debug_assert_eq!(sid.role(), self.role);
        let idx = sid.dir() as usize;
        if sid.id() > self.max[idx] {
            return Err(ExceedLimitError(sid, self.max[idx]));
        }
        let cur = &mut self.unallocated[idx];
        if sid < *cur {
            Ok(AcceptSid::Old)
        } else {
            let start = *cur;
            *cur = unsafe { sid.next_unchecked() };
            if let Some(max_streams) = self.ctrl.on_accept_streams(sid.dir(), sid.id()) {
                self.max[idx] = max_streams;
                self.max_tx.send_frame([MaxStreamsFrame::with(
                    sid.dir(),
                    VarInt::from_u64(max_streams)
                        .expect("max_streams must be less than VARINT_MAX"),
                )]);
            }
            Ok(AcceptSid::New(NeedCreate { start, end: sid }))
        }
    }

    fn on_end_of_stream(&mut self, sid: StreamId) {
        if sid.role() != self.role {
            return;
        }

        if let Some(max_streams) = self.ctrl.on_end_of_stream(sid.dir(), sid.id()) {
            self.max[sid.dir() as usize] = max_streams;
            self.max_tx.send_frame([MaxStreamsFrame::with(
                sid.dir(),
                VarInt::from_u64(max_streams).expect("max_streams must be less than VARINT_MAX"),
            )]);
        }
    }

    fn recv_streams_blocked_frame(&mut self, frame: StreamsBlockedFrame) {
        let (dir, max_streams) = match frame {
            StreamsBlockedFrame::Bi(max) => (Dir::Bi, max.into_u64()),
            StreamsBlockedFrame::Uni(max) => (Dir::Uni, max.into_u64()),
        };
        if let Some(max_streams) = self.ctrl.on_streams_blocked(dir, max_streams) {
            self.max[dir as usize] = max_streams;
            self.max_tx.send_frame([MaxStreamsFrame::with(
                dir,
                VarInt::from_u64(max_streams).expect("max_streams must be less than VARINT_MAX"),
            )]);
        }
    }
}

/// Shared remote stream IDs, mainly controls and monitors the stream IDs
/// in the received stream-related frames from peer.
///
/// Checks whether the stream IDs exceed the limit ,and creates them if necessary.
/// And sends a [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`)
/// to the peer to update the maximum stream ID limit in time.
///
/// # Note
///
/// After receiving the peer's stream-related frames,
/// due to possible out-of-order reception issues,
/// the stream IDs in these frames may have gaps,
/// i.e., they may not be continuous with the previous stream ID of the same type.
/// So before a stream is created,
/// all streams of the same type with lower-numbered stream IDs MUST be created.
/// This ensures that the creation order for streams is consistent on both endpoints
#[derive(Debug, Clone)]
pub struct ArcRemoteStreamIds<MAX>(Arc<Mutex<RemoteStreamIds<MAX>>>);

impl<MAX> ArcRemoteStreamIds<MAX>
where
    MAX: SendFrame<MaxStreamsFrame> + Clone + Send + 'static,
{
    /// Create a new [`ArcRemoteStreamIds`] with the given role,
    /// and maximum number of streams that can be created by peer in each direction.
    ///
    /// The maximum number of streams that can be created by peer in each direction
    /// are `initial_max_streams_bidi` and `initial_max_sterams_uni`
    /// in local [`Parameters`](`crate::param::Parameters`).
    /// See [section-18.2-4.21](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.21)
    /// and [section-18.2-4.23](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.23)
    /// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
    pub fn new(
        role: Role,
        max_bi: u64,
        max_uni: u64,
        max_tx: MAX,
        ctrl: Box<dyn ControlStreamsConcurrency>,
    ) -> Self {
        Self(Arc::new(Mutex::new(RemoteStreamIds::new(
            role, max_bi, max_uni, max_tx, ctrl,
        ))))
    }

    /// Returns the role of the peer.
    pub fn role(&self) -> Role {
        self.0.lock().unwrap().role()
    }

    /// Try to accept the stream ID received from peer.
    ///
    /// Only if this stream ID must be created by peer, this function needs to be called.
    ///
    /// This stream ID may belong to an already existing stream or a new stream that does not yet exist.
    /// If it is the latter, a new stream needs to be created.
    /// Before a stream is created, all streams of the same type
    /// with lower-numbered stream IDs MUST be created.
    /// See [section-3.2-6](https://www.rfc-editor.org/rfc/rfc9000.html#section-3.2-6)
    /// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
    ///
    /// # Return
    ///
    /// - Return [`ExceedLimitError`] if the stream ID exceeds the maximum stream ID limit.
    /// - Return [`AcceptSid::Old`] if the stream ID is already exist.
    /// - Return [`AcceptSid::New`] if the stream ID is new and need to create.
    ///   The `NeedCreate` inside indicates the range of stream IDs that need to be created.
    pub fn try_accept_sid(&self, sid: StreamId) -> Result<AcceptSid, ExceedLimitError> {
        self.0.lock().unwrap().try_accept_sid(sid)
    }

    #[inline]
    pub fn on_end_of_stream(&self, sid: StreamId) {
        self.0.lock().unwrap().on_end_of_stream(sid);
    }

    #[inline]
    pub fn recv_streams_blocked_frame(&self, frame: StreamsBlockedFrame) {
        self.0.lock().unwrap().recv_streams_blocked_frame(frame);
    }
}

impl<MAX> ReceiveFrame<StreamsBlockedFrame> for ArcRemoteStreamIds<MAX>
where
    MAX: SendFrame<MaxStreamsFrame> + Clone + Send + 'static,
{
    type Output = ();

    fn recv_frame(&self, frame: StreamsBlockedFrame) -> Result<Self::Output, crate::error::Error> {
        self.recv_streams_blocked_frame(frame);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sid::handy::ConsistentConcurrency;

    #[derive(Clone, Default)]
    struct MaxStreamsFrameTx(Arc<Mutex<Vec<MaxStreamsFrame>>>);

    impl SendFrame<MaxStreamsFrame> for MaxStreamsFrameTx {
        fn send_frame<I: IntoIterator<Item = MaxStreamsFrame>>(&self, iter: I) {
            self.0.lock().unwrap().extend(iter);
        }
    }

    #[test]
    fn test_try_accept_sid() {
        let remote = ArcRemoteStreamIds::new(
            Role::Server,
            10,
            5,
            MaxStreamsFrameTx::default(),
            Box::new(ConsistentConcurrency::new(10, 5)),
        );
        let result = remote.try_accept_sid(StreamId(21));
        assert_eq!(
            result,
            Ok(AcceptSid::New(NeedCreate {
                start: StreamId(1),
                end: StreamId(21)
            }))
        );
        assert_eq!(remote.0.lock().unwrap().unallocated[0], StreamId(25));

        let result = remote.try_accept_sid(StreamId(25));
        assert_eq!(
            result,
            Ok(AcceptSid::New(NeedCreate {
                start: StreamId(25),
                end: StreamId(25)
            }))
        );
        assert_eq!(remote.0.lock().unwrap().unallocated[0], StreamId(29));

        let result = remote.try_accept_sid(StreamId(41));
        assert_eq!(
            result,
            Ok(AcceptSid::New(NeedCreate {
                start: StreamId(29),
                end: StreamId(41)
            }))
        );
        assert_eq!(remote.0.lock().unwrap().unallocated[0], StreamId(45));
        if let Ok(AcceptSid::New(mut range)) = result {
            assert_eq!(range.next(), Some(StreamId(29)));
            assert_eq!(range.next(), Some(StreamId(33)));
            assert_eq!(range.next(), Some(StreamId(37)));
            assert_eq!(range.next(), Some(StreamId(41)));
            assert_eq!(range.next(), None);
        }

        let result = remote.try_accept_sid(StreamId(65));
        assert_eq!(result, Err(ExceedLimitError(StreamId(65), 10)));
    }
}
