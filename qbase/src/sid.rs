use std::fmt;

use super::{
    frame::MaxStreamsFrame,
    varint::{VarInt, WriteVarInt, be_varint},
};
use crate::{
    frame::{StreamsBlockedFrame, io::SendFrame},
    net::tx::ArcSendWakers,
    role::Role,
};

/// Sum type for stream directions.
///
/// Streams can be unidirectional or bidirectional.
/// Unidirectional streams carry data in one direction: from the initiator of the stream to its peer.
/// Bidirectional streams allow for data to be sent in both directions.
/// See [section-2.1-1](https://www.rfc-editor.org/rfc/rfc9000.html#section-2.1-1)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html).
///
/// The second least significant bit (0x02) of the [`StreamId`] distinguishes between
/// bidirectional streams (with the bit set to 0) and unidirectional streams (with the bit set to 1).
/// See [section-2.1-4](https://www.rfc-editor.org/rfc/rfc9000.html#section-2.1-4)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Dir {
    /// Data flows in both directions
    Bi = 0,
    /// Data flows only from the stream's initiator
    Uni = 1,
}

impl fmt::Display for Dir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match *self {
            Self::Bi => "bidirectional",
            Self::Uni => "unidirectional",
        })
    }
}

/// Streams are identified within a connection by a numeric value,
/// referred to as the stream ID.
///
/// A stream ID is a 62-bit integer (0 to 262-1) that is unique for all streams on a connection.
/// Stream IDs are encoded as [`VarInt`].
/// A QUIC endpoint MUST NOT reuse a stream ID within a connection.
///
/// There are four types of streams in QUIC, divided according to the role and direction of the stream.
/// See [Stream ID Types](https://www.rfc-editor.org/rfc/rfc9000.html#name-stream-id-types)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StreamId(u64);

/// Maximum ID for each type of stream.
///
/// [`StreamId`] is encoded with [`VarInt`].
/// After removing the lowest 2 bits for direction and role,
/// the remaining 60 bits are used to represent the actual ID for each type of stream,
/// so its maximum range cannot exceed 2^60.
pub const MAX_STREAMS_LIMIT: u64 = (1 << 60) - 1;

impl StreamId {
    /// Create a new stream ID with the given role, direction, and ID.
    ///
    /// It is prohibited to directly create a StreamId from external sources.
    /// StreamId can only be allocated incrementally by proactively creating new streams locally.
    /// or accepting new streams opened by peer.
    pub fn new(role: Role, dir: Dir, id: u64) -> Self {
        assert!(id <= MAX_STREAMS_LIMIT);
        Self((((id << 1) | (dir as u64)) << 1) | (role as u64))
    }

    /// Returns the role of this stream ID.
    pub fn role(&self) -> Role {
        if self.0 & 0x1 == 0 {
            Role::Client
        } else {
            Role::Server
        }
    }

    /// Returns the direction of this stream ID.
    pub fn dir(&self) -> Dir {
        if self.0 & 2 == 0 { Dir::Bi } else { Dir::Uni }
    }

    /// Get the actual ID of this stream, removing the lowest 2 bits for direction and role.
    pub fn id(&self) -> u64 {
        self.0 >> 2
    }

    unsafe fn next_unchecked(&self) -> Self {
        Self(self.0 + 4)
    }

    /// Return the encoding size of this stream ID.
    pub fn encoding_size(&self) -> usize {
        VarInt::from(*self).encoding_size()
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} side {} stream {}",
            self.role(),
            self.dir(),
            self.id()
        )
    }
}

impl From<VarInt> for StreamId {
    fn from(v: VarInt) -> Self {
        Self(v.into_u64())
    }
}

impl From<StreamId> for VarInt {
    fn from(s: StreamId) -> Self {
        VarInt::from_u64(s.0).expect("stream id must be less than VARINT_MAX")
    }
}

impl From<StreamId> for u64 {
    fn from(s: StreamId) -> Self {
        s.0
    }
}

/// Parse a stream ID from the input bytes,
/// [nom](https://docs.rs/nom/6.2.1/nom/) parser style.
pub fn be_streamid(input: &[u8]) -> nom::IResult<&[u8], StreamId> {
    use nom::{Parser, combinator::map};
    map(be_varint, StreamId::from).parse(input)
}

/// A BufMut extension trait for writing a stream ID.
pub trait WriteStreamId: bytes::BufMut {
    /// Write a stream ID to the buffer.
    fn put_streamid(&mut self, stream_id: &StreamId);
}

impl<T: bytes::BufMut> WriteStreamId for T {
    fn put_streamid(&mut self, stream_id: &StreamId) {
        self.put_varint(&(*stream_id).into());
    }
}

/// Controls the concurrency of unidirectional and bidirectional streams created by the peer,
/// primarily through [`StreamsBlockedFrame`] and [`MaxStreamsFrame`].
///
/// [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)
/// leaves implementations to decide when and how many streams should be
/// advertised to a peer via MAX_STREAMS. Implementations might choose to
/// increase limits as streams are closed, to keep the number of streams
/// available to peers roughly consistent.
///
/// Implementations might also choose to increase limits as long as the
/// peer needs to create new streams.
///
/// See [controlling concurrency](https://www.rfc-editor.org/rfc/rfc9000.html#name-controlling-concurrency).
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
pub trait ControlStreamsConcurrency: fmt::Debug + Send + Sync {
    /// Called back upon accepting a new `dir` direction streams with stream id `sid` from peer,
    /// all previous inexistent `dir` direction streams should be opened by peer will also be created.
    ///
    /// Returns whether to increase the maximum stream ID limit,
    /// which will be communicated to the peer via a MAX_STREAMS frame in the future.
    /// If None is returned, it means there is no need to
    /// increase the MAX_STREAMS for the time being.
    #[must_use]
    fn on_accept_streams(&mut self, dir: Dir, sid: u64) -> Option<u64>;

    /// Called back upon a `dir` directional stream is ended,
    /// whether it is closed normally or reset abnormally.
    ///
    /// The `sid` is the stream ID of the ended `dir` direction stream.
    ///
    /// Returns whether to increase the maximum stream ID limit,
    /// which will be communicated to the peer via a MAX_STREAMS frame in the future.
    /// If None is returned, it means there is no need to
    /// increase the MAX_STREAMS for the time being.
    fn on_end_of_stream(&mut self, dir: Dir, sid: u64) -> Option<u64>;

    /// Called back upon receiving the StreamsBlocked frame,
    /// which indicates that the peer is limited to create more `dir` direction streams.
    ///
    /// It may optionally return an increased value for the `max_streams`
    /// for the `dir` directional streams.
    /// If None is returned, it means there is no need to increase
    /// the MAX_STREAMS for the time being.
    fn on_streams_blocked(&mut self, dir: Dir, max_streams: u64) -> Option<u64>;
}

impl<C: ?Sized + ControlStreamsConcurrency> ControlStreamsConcurrency for Box<C> {
    fn on_accept_streams(&mut self, dir: Dir, sid: u64) -> Option<u64> {
        self.as_mut().on_accept_streams(dir, sid)
    }

    fn on_end_of_stream(&mut self, dir: Dir, sid: u64) -> Option<u64> {
        self.as_mut().on_end_of_stream(dir, sid)
    }

    fn on_streams_blocked(&mut self, dir: Dir, max_streams: u64) -> Option<u64> {
        self.as_mut().on_streams_blocked(dir, max_streams)
    }
}

pub trait ProductStreamsConcurrencyController: Send + Sync {
    fn init(
        &self,
        init_max_bidi_streams: u64,
        init_max_uni_streams: u64,
    ) -> Box<dyn ControlStreamsConcurrency>;
}

impl<F, C> ProductStreamsConcurrencyController for F
where
    F: Fn(u64, u64) -> C + Send + Sync,
    C: ControlStreamsConcurrency + 'static,
{
    #[inline]
    fn init(
        &self,
        init_max_bidi_streams: u64,
        init_max_uni_streams: u64,
    ) -> Box<dyn ControlStreamsConcurrency> {
        Box::new((self)(init_max_bidi_streams, init_max_uni_streams))
    }
}

pub mod handy;

pub mod local_sid;
pub use local_sid::ArcLocalStreamIds;

pub mod remote_sid;
pub use remote_sid::ArcRemoteStreamIds;

/// Stream IDs management, including an [`ArcLocalStreamIds`] as local,
/// and an [`ArcRemoteStreamIds`] as remote.
#[derive(Debug, Clone)]
pub struct StreamIds<BLOCKED, MAX> {
    pub local: ArcLocalStreamIds<BLOCKED>,
    pub remote: ArcRemoteStreamIds<MAX>,
}

impl<T> StreamIds<T, T>
where
    T: SendFrame<MaxStreamsFrame> + SendFrame<StreamsBlockedFrame> + Clone + Send + 'static,
{
    /// Create a new [`StreamIds`] with the given role, and maximum number of streams of each direction.
    ///
    /// The troublesome part is that the maximum number of streams that can be created locally
    /// is restricted by the peer's `initial_max_streams_uni` and `initial_max_streams_bidi` transport
    /// parameters, which are unknown at the beginning.
    /// Therefore, peer's `initial_max_streams_xx` can be set to 0 initially,
    /// and then updated later after obtaining the peer's `initial_max_streams_xx` setting.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: Role,
        local_max_bi: u64,
        local_max_uni: u64,
        remote_max_bi: u64,
        remote_max_uni: u64,
        sid_frames_tx: T,
        ctrl: Box<dyn ControlStreamsConcurrency>,
        tx_wakers: ArcSendWakers,
    ) -> Self {
        // 缺省为0
        let local = ArcLocalStreamIds::new(
            role,
            remote_max_bi,
            remote_max_uni,
            sid_frames_tx.clone(),
            tx_wakers,
        );
        let remote =
            ArcRemoteStreamIds::new(!role, local_max_bi, local_max_uni, sid_frames_tx, ctrl);
        Self { local, remote }
    }

    #[inline]
    pub fn on_conn_error(&self) {
        self.local.on_conn_error();
    }
}
