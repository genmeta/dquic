//! Polling frame sources and packet-wide send limits.
use std::task::{Context, Poll, Waker};

use bytes::{BufMut, buf::UninitSlice};

use crate::{
    error::Error,
    frame::{
        ContainSpec, EncodeSize, Frame, FrameFeature, FrameType, GetFrameType, Len, Spec,
        io::WriteFrame, *,
    },
    packet::Type,
};

pub trait Limit {
    fn flow_ctrl(&self) -> usize;
    fn send_quota(&self) -> usize;
    fn credit(&self) -> usize;
    fn min_size(&self) -> usize;
    fn max_size(&self) -> usize;
    /// Bound this packet's write window without consuming credit.
    fn set_max_size(&mut self, size: usize);
    fn fresh(&mut self, amount: usize);
    /// Consume encoded packet bytes; the limit also charges any reserved envelope.
    fn take(&mut self, send_quota: usize, credit: usize);
}

/// Burst balances and current datagram size limits, including envelope overhead.
#[derive(Debug, Clone, Default)]
pub struct Constraints {
    pub flow_ctrl: usize,
    pub send_quota: usize,
    pub credit: usize,
    pub min_size: usize,
    pub max_size: usize,
    /// Datagram envelope bytes reserved outside the encoded QUIC packet.
    pub overhead: usize,
    /// Congestion allowance for the current PTO probe; does not replenish the burst.
    pub probe_quota: usize,
}

pub struct ConstraintBuffer<'a, B: ?Sized> {
    buffer: &'a mut B,
    pub limits: &'a mut dyn Limit,
    pub packet_type: Type,
    tag_len: usize,
    written: usize,
    end: usize,
}

pub trait Package<B: BufMut + ?Sized> {
    /// No data: register the task and return Pending. Data that cannot fit: Ready(Ok(0)).
    /// Record each written frame in `frames` and return the number written.
    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ConstraintBuffer<'_, B>,
        frames: &mut Vec<Frame>,
    ) -> Poll<Result<usize, Error>>;

    fn cancel(&mut self, _waker: &Waker) {}
}

pub trait Assemble<const N: usize> {
    type Buffer: BufMut;
    fn assemble(
        &mut self,
        cx: &mut Context<'_>,
        sources: [&mut dyn Package<Self::Buffer>; N],
        frames: &mut Vec<Frame>,
    ) -> Poll<Result<usize, Error>>;
}

impl Limit for Constraints {
    fn flow_ctrl(&self) -> usize {
        self.flow_ctrl
    }

    fn send_quota(&self) -> usize {
        self.send_quota
            .max(self.probe_quota)
            .saturating_sub(self.overhead)
    }

    fn credit(&self) -> usize {
        self.credit.saturating_sub(self.overhead)
    }

    fn min_size(&self) -> usize {
        self.min_size.saturating_sub(self.overhead)
    }

    fn max_size(&self) -> usize {
        self.max_size.saturating_sub(self.overhead)
    }

    fn set_max_size(&mut self, size: usize) {
        self.max_size = size.saturating_add(self.overhead);
    }

    fn fresh(&mut self, amount: usize) {
        self.flow_ctrl -= amount;
    }

    fn take(&mut self, send_quota: usize, credit: usize) {
        if send_quota > 0 {
            let sent = send_quota + self.overhead;
            self.send_quota = self.send_quota.saturating_sub(sent);
            self.probe_quota = self.probe_quota.saturating_sub(sent);
        }
        if credit > 0 {
            self.credit -= credit + self.overhead;
        }
    }
}

impl<'a, B: BufMut + ?Sized> ConstraintBuffer<'a, B> {
    pub fn new(
        buffer: &'a mut B,
        limits: &'a mut dyn Limit,
        packet_type: Type,
        written: usize,
        tag_len: usize,
    ) -> Self {
        let end = limits
            .max_size()
            .min(limits.credit())
            .saturating_sub(tag_len);
        Self {
            buffer,
            limits,
            packet_type,
            tag_len,
            written,
            end,
        }
    }

    /// TODO: 这个 for_frame 到底有啥用？？？？
    pub fn for_frame(&mut self, frame_type: FrameType, frames: &[Frame]) {
        if !frame_type.belongs_to(self.packet_type)
            || frames.last().is_some_and(|f| {
                matches!(
                    f.frame_type(),
                    FrameType::Stream(_, Len::Omit, _) | FrameType::Datagram(0)
                )
            })
        {
            self.end = self.written;
            return;
        }
        let limit = self
            .limits
            .max_size()
            .min(self.limits.credit())
            .min(self.written.saturating_add(self.buffer.remaining_mut()));
        let limit = if in_flight(frames) || !frame_type.specs().contain(Spec::CongestionControlFree)
        {
            limit.min(self.limits.send_quota())
        } else {
            limit
        };
        self.end = if limit < self.limits.min_size() {
            self.written
        } else {
            limit.saturating_sub(self.tag_len)
        };
    }

    pub fn written(&self) -> usize {
        self.written
    }

    /// Padding needed to reach the minimum size consumes congestion quota too.
    pub fn can_fit(&self, size: usize) -> bool {
        size <= self.remaining_mut()
            && (self
                .written
                .saturating_add(size)
                .saturating_add(self.tag_len)
                >= self.limits.min_size()
                || self.limits.send_quota() >= self.limits.min_size())
    }
}

unsafe impl<B: BufMut + ?Sized> BufMut for ConstraintBuffer<'_, B> {
    fn remaining_mut(&self) -> usize {
        self.end
            .saturating_sub(self.written)
            .min(self.buffer.remaining_mut())
    }

    unsafe fn advance_mut(&mut self, count: usize) {
        assert!(count <= self.remaining_mut());
        unsafe {
            self.buffer.advance_mut(count);
        }
        self.written += count;
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        let remaining = self.remaining_mut();
        let chunk = self.buffer.chunk_mut();
        let len = remaining.min(chunk.len());
        &mut chunk[..len]
    }
}

/// TODO: trait From<&[Frame]>
/// Submission properties are derived from exactly the frames written in this packet.
pub fn content(frames: &[Frame]) -> super::PacketContent {
    let mut content = super::PacketContent::default();
    for frame in frames {
        content += super::PacketContent::from(frame.frame_type());
    }
    content
}

pub fn in_flight(frames: &[Frame]) -> bool {
    frames
        .iter()
        .any(|f| !f.frame_type().specs().contain(Spec::CongestionControlFree))
}

impl<B: BufMut + ?Sized, P: Package<B> + ?Sized> Package<B> for &mut P {
    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ConstraintBuffer<'_, B>,
        frames: &mut Vec<Frame>,
    ) -> Poll<Result<usize, Error>> {
        (**self).poll_dump(cx, buffer, frames)
    }

    fn cancel(&mut self, waker: &Waker) {
        (**self).cancel(waker);
    }
}

impl<B: BufMut + ?Sized, P: Package<B>> Package<B> for Option<P> {
    fn poll_dump(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ConstraintBuffer<'_, B>,
        frames: &mut Vec<Frame>,
    ) -> Poll<Result<usize, Error>> {
        let Some(source) = self.as_mut() else {
            return Poll::Pending;
        };
        let result = source.poll_dump(cx, buffer, frames);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            *self = None;
        }
        result
    }

    fn cancel(&mut self, waker: &Waker) {
        if let Some(source) = self {
            source.cancel(waker);
        }
    }
}

macro_rules! frame_packages {
    ($($ty:ty),* $(,)?) => {$ (
        impl<B: BufMut + ?Sized> Package<B> for $ty {
            fn poll_dump(&mut self, _: &mut Context<'_>, buffer: &mut ConstraintBuffer<'_, B>, frames: &mut Vec<Frame>) -> Poll<Result<usize, Error>> {
                if !self.frame_type().belongs_to(buffer.packet_type) { return Poll::Ready(Err(crate::error::QuicError::with_default_fty(crate::error::ErrorKind::Internal, "frame does not belong to packet type").into())); }
                buffer.for_frame(self.frame_type(), frames);
                if !buffer.can_fit(self.encoding_size()) { return Poll::Ready(Ok(0)); }
                let frame: Frame = self.clone().into();
                buffer.put_frame(&frame);
                frames.push(frame);
                Poll::Ready(Ok(1))
            }
        }
    )*};
}

frame_packages!(
    PaddingFrame,
    PingFrame,
    AckFrame,
    ConnectionCloseFrame,
    NewTokenFrame,
    MaxDataFrame,
    DataBlockedFrame,
    HandshakeDoneFrame,
    PathChallengeFrame,
    PathResponseFrame,
    StreamCtlFrame,
    ReliableFrame,
    PunchHelloFrame,
    PunchDoneFrame,
    NewConnectionIdFrame,
    RetireConnectionIdFrame,
    AddAddressFrame,
    RemoveAddressFrame,
    PunchMeNowFrame
);

macro_rules! data_packages {
    ($($ty:ident => $variant:ident),* $(,)?) => {$ (
        impl<B: BufMut + ?Sized, D: crate::util::Buffer + Clone> Package<B> for ($ty, D)
        where for<'a, 'b> &'a mut ConstraintBuffer<'b, B>: crate::util::WriteData<D> {
            fn poll_dump(&mut self, _: &mut Context<'_>, buffer: &mut ConstraintBuffer<'_, B>, frames: &mut Vec<Frame>) -> Poll<Result<usize, Error>> {
                if !self.0.frame_type().belongs_to(buffer.packet_type) { return Poll::Ready(Err(crate::error::QuicError::with_default_fty(crate::error::ErrorKind::Internal, "frame does not belong to packet type").into())); }
                buffer.for_frame(self.0.frame_type(), frames);
                if !buffer.can_fit(self.0.encoding_size().saturating_add(self.1.len())) { return Poll::Ready(Ok(0)); }
                buffer.put_frame(&Frame::$variant(self.0, self.1.clone()));
                frames.push(Frame::$variant(self.0, ()));
                Poll::Ready(Ok(1))
            }
        }
    )*};
}

data_packages!(StreamFrame => Stream, CryptoFrame => Crypto, DatagramFrame => Datagram);

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;
    use crate::packet::{GetType, OneRttHeader};

    fn limits(size: usize) -> Constraints {
        Constraints {
            flow_ctrl: 0,
            send_quota: size,
            credit: size,
            min_size: 0,
            max_size: size,
            ..Default::default()
        }
    }

    #[test]
    fn envelope_is_charged_once_and_ack_only_preserves_congestion_quota() {
        let mut limits = Constraints {
            overhead: 40,
            ..limits(2400)
        };
        limits.take(0, 0);
        assert_eq!((limits.send_quota, limits.credit), (2400, 2400));
        limits.take(0, 60);
        assert_eq!((limits.send_quota, limits.credit), (2400, 2300));
        limits.take(1160, 1160);
        assert_eq!((limits.send_quota, limits.credit), (1200, 1100));
    }

    #[test]
    fn insufficient_payload_room_preserves_optional_source_and_records() {
        let mut bytes = BytesMut::new();
        let mut constraints = limits(4);
        let mut buffer = ConstraintBuffer::new(
            &mut bytes,
            &mut constraints,
            OneRttHeader::new(Default::default(), Default::default()).get_type(),
            0,
            0,
        );
        let mut source = Some((
            CryptoFrame::new(0u32.into(), 4u32.into()),
            b"data".as_slice(),
        ));
        let mut frames = Vec::new();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            source.poll_dump(&mut cx, &mut buffer, &mut frames),
            Poll::Ready(Ok(0))
        ));
        assert!(source.is_some());
        assert!(frames.is_empty());
        assert_eq!(buffer.written(), 0);
        let mut larger = limits(7);
        buffer.limits = &mut larger;
        assert!(matches!(
            source.poll_dump(&mut cx, &mut buffer, &mut frames),
            Poll::Ready(Ok(1))
        ));
        assert!(source.is_none());
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn ack_bypasses_zero_quota_but_ping_charges_the_entire_packet() {
        let mut bytes = BytesMut::new();
        let mut constraints = limits(1200);
        constraints.send_quota = 0;
        let mut buffer = ConstraintBuffer::new(
            &mut bytes,
            &mut constraints,
            OneRttHeader::new(Default::default(), Default::default()).get_type(),
            11,
            16,
        );
        let mut frames = Vec::new();
        let mut cx = Context::from_waker(Waker::noop());
        let mut ack = AckFrame::new(0u32.into(), 0u32.into(), 0u32.into(), vec![], None);
        assert!(matches!(
            ack.poll_dump(&mut cx, &mut buffer, &mut frames),
            Poll::Ready(Ok(1))
        ));
        assert!(matches!(
            PingFrame.poll_dump(&mut cx, &mut buffer, &mut frames),
            Poll::Ready(Ok(0))
        ));
        assert_eq!(
            content(&frames),
            super::super::PacketContent::NonAckEliciting
        );
        assert!(!in_flight(&frames));
        drop(buffer);
        constraints.send_quota = 32;
        let mut buffer = ConstraintBuffer::new(
            &mut bytes,
            &mut constraints,
            OneRttHeader::new(Default::default(), Default::default()).get_type(),
            16,
            16,
        );
        assert!(matches!(
            PingFrame.poll_dump(&mut cx, &mut buffer, &mut frames),
            Poll::Ready(Ok(0))
        ));
    }

    #[test]
    fn ack_waits_for_padding_quota_before_writing() {
        let mut bytes = BytesMut::new();
        let mut constraints = limits(1200);
        constraints.min_size = 1200;
        constraints.send_quota = 0;
        let mut buffer = ConstraintBuffer::new(
            &mut bytes,
            &mut constraints,
            OneRttHeader::new(Default::default(), Default::default()).get_type(),
            11,
            16,
        );
        let mut frames = Vec::new();
        let mut ack = AckFrame::new(0u32.into(), 0u32.into(), 0u32.into(), vec![], None);
        assert!(matches!(
            ack.poll_dump(
                &mut Context::from_waker(Waker::noop()),
                &mut buffer,
                &mut frames
            ),
            Poll::Ready(Ok(0))
        ));
        assert!(frames.is_empty());
        assert_eq!(buffer.written(), 11);
    }
}

macro_rules! stream_control_packages {
    ($($ty:ty),* $(,)?) => {$ (
        impl<B: BufMut + ?Sized> Package<B> for $ty {
            fn poll_dump(&mut self, cx: &mut Context<'_>, buffer: &mut ConstraintBuffer<'_, B>, frames: &mut Vec<Frame>) -> Poll<Result<usize, Error>> {
                StreamCtlFrame::from(*self).poll_dump(cx, buffer, frames)
            }
        }
    )*};
}
stream_control_packages!(
    ResetStreamFrame,
    StopSendingFrame,
    MaxStreamDataFrame,
    MaxStreamsFrame,
    StreamDataBlockedFrame,
    StreamsBlockedFrame
);
