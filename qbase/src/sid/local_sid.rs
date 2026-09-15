use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use super::{Dir, Role, StreamId};
use crate::{
    frame::{
        MaxStreamsFrame, StreamsBlockedFrame,
        io::{ReceiveFrame, SendFrame},
    },
    net::tx::{ArcSendWakers, Signals},
    sid::MAX_STREAMS_LIMIT,
    varint::VarInt,
};

/// Local stream IDs management.
#[derive(Debug)]
struct LocalStreamIds<BLOCKED> {
    /// Our role
    role: Role,
    max: [u64; 2],
    unallocated: [u64; 2],
    /// Used for waiting for the MaxStream frame notification from peer when we have exhausted the creation of stream IDs
    wakers: [VecDeque<Waker>; 2],
    /// The StreamsBlocked frames that will be sent to peer
    blocked: BLOCKED,
    tx_wakers: ArcSendWakers,
}

impl<BLOCKED> LocalStreamIds<BLOCKED>
where
    BLOCKED: SendFrame<StreamsBlockedFrame> + Clone + Send + 'static,
{
    /// Create a new [`LocalStreamIds`] with the given role,
    /// and maximum number of streams that can be created in each [`Dir`].
    fn new(
        role: Role,
        init_max_bi_streams: u64,
        init_max_uni_streams: u64,
        blocked: BLOCKED,
        tx_wakers: ArcSendWakers,
    ) -> Self {
        // These may be remembered client limits or already validated peer
        // limits when a server creates its data components after negotiation.
        Self {
            role,
            max: [init_max_bi_streams, init_max_uni_streams],
            unallocated: [0, 0],
            wakers: [VecDeque::with_capacity(2), VecDeque::with_capacity(2)],
            blocked,
            tx_wakers,
        }
    }

    /// Returns local role.
    fn role(&self) -> Role {
        self.role
    }

    /// Returns the number of opened streams in the `dir` direction.
    fn opened_streams(&self, dir: Dir) -> u64 {
        self.unallocated[dir as usize]
    }

    /// Receive the [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`) from peer,
    /// update the maximum stream ID that can be opened locally in the given direction.
    fn recv_max_streams_frame(&mut self, frame: MaxStreamsFrame) {
        let (dir, val) = match frame {
            MaxStreamsFrame::Bi(max) => (Dir::Bi, max.into_u64()),
            MaxStreamsFrame::Uni(max) => (Dir::Uni, max.into_u64()),
        };
        self.increase_limit(dir, val);
    }

    fn increase_limit(&mut self, dir: Dir, val: u64) {
        assert!(val <= MAX_STREAMS_LIMIT);
        let max_streams = &mut self.max[dir as usize];
        // RFC9000: MAX_STREAMS frames that do not increase the stream limit MUST be ignored.
        if *max_streams < val {
            // The rejected 0rtt stream can be sent again, as if new data was written.
            if *max_streams < self.unallocated[dir as usize] {
                self.tx_wakers.wake_all_by(Signals::WRITTEN);
            }
            for waker in self.wakers[dir as usize].drain(..) {
                waker.wake();
            }
            *max_streams = val;
        }
    }

    fn poll_alloc_sid(&mut self, cx: &mut Context<'_>, dir: Dir) -> Poll<Option<StreamId>> {
        let idx = dir as usize;
        let max = self.max[idx];
        let unallocated = self.unallocated[idx];
        if unallocated > MAX_STREAMS_LIMIT {
            Poll::Ready(None)
        } else if unallocated < max {
            self.unallocated[idx] += 1;
            Poll::Ready(Some(StreamId::new(self.role, dir, unallocated)))
        } else {
            // waiting for MAX_STREAMS frame from peer
            self.wakers[idx].push_back(cx.waker().clone());
            // if Poll::Pending is returned, connection can send a STREAMS_BLOCKED frame to peer
            self.blocked.send_frame([StreamsBlockedFrame::with(
                dir,
                VarInt::from_u64(max).expect("max_streams limit must be less than VARINT_MAX"),
            )]);
            Poll::Pending
        }
    }

    pub fn revise_max_streams(
        &mut self,
        zero_rtt_rejected: bool,
        max_stream_bidi: u64,
        max_stream_uni: u64,
    ) {
        if zero_rtt_rejected {
            self.max = [0, 0];
        }
        self.increase_limit(Dir::Bi, max_stream_bidi);
        self.increase_limit(Dir::Uni, max_stream_uni);
    }
}

/// Management of stream IDs that can ben allowed to use locally.
///
/// The maximum stream ID that can be created is limited by the
/// [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`) from the peer.
///
/// When the stream IDs in the `dir` direction are exhausted,
/// a [`StreamsBlockedFrame`](`crate::frame::StreamsBlockedFrame`) will be sent to the peer.
/// The generic parameter `BLOCKED` is the container of the [`StreamsBlockedFrame`]
/// that will be sent to peer, it can be a channel, a queue, or a buffer,
/// as long as it can send the [`StreamsBlockedFrame`] to peer.
#[derive(Debug, Clone)]
pub struct ArcLocalStreamIds<BLOCKED>(Arc<Mutex<LocalStreamIds<BLOCKED>>>);

impl<BLOCKED> ArcLocalStreamIds<BLOCKED>
where
    BLOCKED: SendFrame<StreamsBlockedFrame> + Clone + Send + 'static,
{
    /// Create a new [`ArcLocalStreamIds`] with the given role,
    /// and maximum number of streams that can be created in each direction,
    /// the `blocked` contains the [`StreamsBlockedFrame`] that will be sent to peer.
    pub fn new(
        role: Role,
        max_bidi: u64,
        max_uni: u64,
        blocked: BLOCKED,
        tx_wakers: ArcSendWakers,
    ) -> Self {
        Self(Arc::new(Mutex::new(LocalStreamIds::new(
            role, max_bidi, max_uni, blocked, tx_wakers,
        ))))
    }

    /// Returns local role
    pub fn role(&self) -> Role {
        self.0.lock().unwrap().role()
    }

    /// Returns the number of opened streams in the `dir` direction.
    ///
    /// If `is_0rtt` is true, this will return the stream open in 0rtt phase.
    ///
    /// If `is_0rtt` is false, the return value will not be greater than max_streams,
    /// that is, if 0rtt is rejected, the return value may be less than the number of open streams.
    /// This is the number of streams that can actually be sent in the 1rtt space.
    pub fn opened_streams(&self, dir: Dir) -> u64 {
        self.0.lock().unwrap().opened_streams(dir)
    }

    /// Receive the [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`) from peer,
    /// and then update the maximum stream ID that can be allowed to use locally.
    ///
    /// The maximum stream ID that can be allowed to use is limited by peer.
    /// Therefore, it mainly depends on the peer's attitude
    /// and is subject to the [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`)
    /// received from peer.
    pub fn recv_max_streams_frame(&self, frame: MaxStreamsFrame) {
        self.0.lock().unwrap().recv_max_streams_frame(frame);
    }

    /// Asynchronously allocate the next new [`StreamId`] in the `dir` direction.
    ///
    /// Return a bool indicating whether the stream is opened in 0rtt phase.
    ///
    /// When the application layer wants to proactively open a new stream,
    /// it needs to first apply to allocate the next unused [`StreamId`].
    /// Note that streams on a QUIC connection usually have a maximum concurrency limit,
    /// so when requesting a [`StreamId`], it may not be possible to obtain one due to
    /// reaching the maximum concurrency limit.
    /// However, this is temporary. When the active current streams end,
    /// the peer will expand the maximum stream ID limit through a
    /// [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`),
    /// allowing the allocation of the [`StreamId`] meanwhile.
    ///
    /// Return Pending when the stream IDs in the `dir` direction are exhausted,
    /// until receiving the [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`) from peer.
    ///
    /// Return None if the stream IDs in the `dir` direction finally exceed 2^60,
    /// but it is very very hard to happen.
    pub fn poll_alloc_sid(&self, cx: &mut Context<'_>, dir: Dir) -> Poll<Option<StreamId>> {
        self.0.lock().unwrap().poll_alloc_sid(cx, dir)
    }

    /// Wake all blocked stream allocation requests after the owner records the connection error.
    pub fn on_conn_error(&self) {
        let mut guard = self.0.lock().unwrap();
        for waker in guard.wakers.iter_mut().flat_map(|queue| queue.drain(..)) {
            waker.wake();
        }
    }

    pub fn revise_max_streams(
        &self,
        zero_rtt_rejected: bool,
        max_stream_bidi: u64,
        max_stream_uni: u64,
    ) {
        self.0.lock().unwrap().revise_max_streams(
            zero_rtt_rejected,
            max_stream_bidi,
            max_stream_uni,
        );
    }
}

impl<BLOCKED> ReceiveFrame<MaxStreamsFrame> for ArcLocalStreamIds<BLOCKED>
where
    BLOCKED: SendFrame<StreamsBlockedFrame> + Clone + Send + 'static,
{
    type Output = ();

    fn recv_frame(&self, frame: MaxStreamsFrame) -> Result<Self::Output, crate::error::Error> {
        self.recv_max_streams_frame(frame);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use derive_more::Deref;

    use super::*;
    use crate::util::ArcAsyncDeque;

    #[derive(Clone, Deref, Default)]
    struct StreamsBlockedFrameTx(ArcAsyncDeque<StreamsBlockedFrame>);

    impl SendFrame<StreamsBlockedFrame> for StreamsBlockedFrameTx {
        fn send_frame<I: IntoIterator<Item = StreamsBlockedFrame>>(&self, iter: I) {
            (&self.0).extend(iter);
        }
    }

    #[test]
    fn test_stream_id_new() {
        let sid = StreamId::new(Role::Client, Dir::Bi, 0);
        assert_eq!(sid, StreamId(0));
        assert_eq!(sid.role(), Role::Client);
        assert_eq!(sid.dir(), Dir::Bi);
    }

    #[test]
    fn server_can_start_with_validated_peer_stream_limits() {
        let local = ArcLocalStreamIds::new(
            Role::Server,
            1,
            1,
            StreamsBlockedFrameTx::default(),
            ArcSendWakers::default(),
        );
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Bi),
            Poll::Ready(Some(StreamId(1)))
        );
        assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Bi), Poll::Pending);
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Uni),
            Poll::Ready(Some(StreamId(3)))
        );
        assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Uni), Poll::Pending);
    }

    #[test]
    fn test_recv_max_stream_frames() {
        let local = ArcLocalStreamIds::new(
            Role::Client,
            0,
            0,
            StreamsBlockedFrameTx::default(),
            ArcSendWakers::default(),
        );
        local.recv_max_streams_frame(MaxStreamsFrame::Bi(VarInt::from_u32(0)));
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Bi), Poll::Pending,);
        assert!(!local.0.lock().unwrap().wakers[0].is_empty());

        local.recv_max_streams_frame(MaxStreamsFrame::Bi(VarInt::from_u32(1)));
        let _ = local.0.lock().unwrap().wakers[0].pop_front();
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Bi),
            Poll::Ready(Some(StreamId(0)))
        );
        assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Bi), Poll::Pending);
        assert!(!local.0.lock().unwrap().wakers[0].is_empty());

        local.recv_max_streams_frame(MaxStreamsFrame::Uni(VarInt::from_u32(2)));
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Uni),
            Poll::Ready(Some(StreamId(2)))
        );
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Uni),
            Poll::Ready(Some(StreamId(6)))
        );
        assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Uni), Poll::Pending);
        assert!(!local.0.lock().unwrap().wakers[1].is_empty());
    }
}
