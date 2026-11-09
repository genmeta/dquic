//! Polling frame sources and packet-wide send limits.
use std::task::{Context, Poll};

use bytes::{BufMut, buf::UninitSlice};

use crate::{
    frame::{ContainSpec, EncodeSize, Frame, FrameFeature, FrameType, GetFrameType, Len, Spec, io::WriteFrame, *},
    packet::{PacketContent, Type},
};

/// Packet metadata collected during assembly and finalized after sealing.
#[derive(Debug, Clone, Copy)]
pub struct Metadata {
    pub pn: u64,
    /// Final packet length including padding and the authentication tag; set after sealing.
    pub pktlen: usize,
    pub pktype: Type,
    pub nframes: usize,
    pub content: super::PacketContent,
    pub in_flight: bool,
    pub ack: Option<u64>,
}

impl Metadata {
    pub fn epoch(&self) -> crate::Epoch {
        use super::r#type::long::{Type as Long, Ver1};
        match self.pktype {
            Type::Long(Long::V1(Ver1::INITIAL)) => crate::Epoch::Initial,
            Type::Long(Long::V1(Ver1::HANDSHAKE)) => crate::Epoch::Handshake,
            Type::Long(Long::V1(Ver1::ZERO_RTT)) | Type::Short(_) => crate::Epoch::Data,
            _ => unreachable!("only data packets have assembly metadata"),
        }
    }

    pub fn new(pktype: Type) -> Self {
        Self { pn: 0, pktlen: 0, pktype, nframes: 0, content: Default::default(), in_flight: false, ack: None }
    }

    pub fn record(&mut self, frame: &Frame) {
        let ty = frame.frame_type();
        self.nframes += 1;
        self.content += ty;
        self.in_flight |= !ty.specs().contain(Spec::CongestionControlFree);
        if let Frame::Ack(frame) = frame {
            self.ack = self.ack.max(Some(frame.largest()));
        }
    }
}

pub struct PacketBuffer<'a, B: ?Sized> {
    buffer: &'a mut B,
    credit: usize,
    pub frames: &'a mut Vec<GuaranteedFrame>,
    tag_len: usize,
    nwrote: usize,
    end: usize,
    pub meta: Metadata,
    min_size: usize,
    validation_min_size: usize,
    pn_offset: usize,
    finished: bool,
}

pub trait Package<B: BufMut + ?Sized> {
    /// Content class of this source, used to filter it before polling.
    fn content(&self) -> PacketContent {
        PacketContent::EffectivePayload
    }

    fn belongs_to(&self, _packet_type: Type) -> bool {
        true
    }

    fn priority(&self) -> u32 {
        0
    }

    /// No data: register the task and return Pending. Data that cannot fit: Ready(0).
    /// Closed sources return Ready(0); their stored close error belongs to application I/O.
    /// Retain recovery descriptors in `buffer.frames`; return the number of all frames written.
    fn poll_dump(&mut self, cx: &mut Context<'_>, buffer: &mut PacketBuffer<'_, B>) -> Poll<usize>;
}

pub trait Assemble {
    type Buffer: BufMut + ?Sized;
    /// Poll sources up to `packet_content`; metadata records only the frames actually written.
    fn assemble(
        &mut self,
        cx: &mut Context<'_>,
        packet_content: PacketContent,
        sources: &mut [&mut dyn Package<Self::Buffer>],
    ) -> Poll<usize>;
}

impl<B: BufMut + ?Sized> Assemble for PacketBuffer<'_, B> {
    type Buffer = B;

    fn assemble(&mut self, cx: &mut Context<'_>, packet_content: PacketContent, sources: &mut [&mut dyn Package<B>]) -> Poll<usize> {
        if self.finished {
            return Poll::Ready(0);
        }
        let packet_type = self.meta.pktype;
        // Preserve input order at equal priority.
        sources.sort_by_key(|source| std::cmp::Reverse(source.priority()));
        let start = self.meta.nframes;
        let mut result = Poll::Pending;
        for source in sources.iter_mut().filter(|source| source.belongs_to(packet_type) && source.content() <= packet_content) {
            if self.finished {
                break;
            }
            if source.poll_dump(cx, self).is_ready() {
                result = Poll::Ready(0);
            }
        }
        if self.meta.nframes > start {
            Poll::Ready(self.meta.nframes - start)
        } else {
            result
        }
    }
}

impl<'a, B: BufMut + ?Sized> PacketBuffer<'a, B> {
    pub fn new(
        buffer: &'a mut B,
        credit: usize,
        frames: &'a mut Vec<GuaranteedFrame>,
        packet_type: Type,
        nwrote: usize,
        tag_len: usize,
    ) -> Self {
        let end = nwrote.saturating_add(buffer.remaining_mut()).saturating_sub(tag_len);
        Self {
            buffer,
            credit,
            frames,
            tag_len,
            nwrote,
            end,
            meta: Metadata::new(packet_type),
            min_size: 0,
            validation_min_size: 0,
            pn_offset: 0,
            finished: false,
        }
    }

    /// Minimum packet size when this datagram contains path-validation frames.
    pub fn scope(&mut self, validation_min_size: usize) {
        self.validation_min_size = validation_min_size;
    }

    /// Encode a header and PN, remembering the layout without retaining the header.
    pub fn begin<H: super::HeaderSize + super::GetType>(&mut self, header: &H, pn: super::PacketNumber) -> bool
    where
        for<'b> &'b mut Self: super::header::io::WriteHeader<H>,
    {
        use super::{WritePacketNumber, header::io::WriteHeader};
        self.meta.pktype = header.get_type();
        let long = matches!(self.meta.pktype, Type::Long(_));
        self.pn_offset = header.size() + if long { 2 } else { 0 };
        self.min_size = self.pn_offset + 4 + 16;
        if self.pn_offset + pn.size() > self.remaining_mut() || self.nwrote.saturating_add(self.buffer.remaining_mut()) < self.min_size {
            return false;
        }
        let mut writer = self;
        WriteHeader::put_header(&mut writer, header);
        if long {
            writer.put_u16(0);
        }
        writer.put_packet_number(pn);
        true
    }

    pub fn pn_offset(&self) -> usize {
        self.pn_offset
    }

    /// Restrict a candidate frame by its packet's budget and datagram requirements.
    pub fn for_frame(&mut self, frame_type: FrameType) {
        if !frame_type.belongs_to(self.meta.pktype) || self.finished {
            self.end = self.nwrote;
            return;
        }
        let limit = self.nwrote.saturating_add(self.buffer.remaining_mut());
        let limit = if self.meta.in_flight || !frame_type.specs().contain(Spec::CongestionControlFree) {
            limit.min(self.credit)
        } else {
            limit
        };
        let mut min_size = self.min_size;
        if matches!(frame_type, FrameType::PathChallenge | FrameType::PathResponse) {
            min_size = min_size.max(self.validation_min_size);
        }
        self.end = if limit < min_size {
            self.nwrote
        } else {
            limit.saturating_sub(self.tag_len)
        };
    }

    /// Account for a written frame, retaining only descriptors that need recovery.
    pub fn record(&mut self, frame: Frame) {
        self.meta.record(&frame);
        match frame.frame_type() {
            FrameType::PathChallenge | FrameType::PathResponse => {
                self.min_size = self.min_size.max(self.validation_min_size);
            }
            FrameType::ConnectionClose(_) | FrameType::Stream(_, Len::Omit, _) | FrameType::Datagram(0) => {
                self.finished = true;
            }
            _ => {}
        }
        if let Ok(frame) = frame.try_into() {
            self.frames.push(frame);
        }
    }

    pub fn finish(&mut self) {
        self.finished = true;
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn min_size(&self) -> usize {
        self.min_size
    }

    pub fn written(&self) -> usize {
        self.nwrote
    }

    /// Padding needed to reach the minimum size consumes congestion quota too.
    pub fn can_fit(&self, size: usize) -> bool {
        size <= self.remaining_mut()
            && (self.nwrote.saturating_add(size).saturating_add(self.tag_len) >= self.min_size || self.credit >= self.min_size)
    }
}

unsafe impl<B: BufMut + ?Sized> BufMut for PacketBuffer<'_, B> {
    fn remaining_mut(&self) -> usize {
        self.end.saturating_sub(self.nwrote).min(self.buffer.remaining_mut())
    }

    unsafe fn advance_mut(&mut self, count: usize) {
        assert!(count <= self.remaining_mut());
        unsafe {
            self.buffer.advance_mut(count);
        }
        self.nwrote += count;
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
impl<B: BufMut + ?Sized, P: Package<B> + ?Sized> Package<B> for &mut P {
    fn content(&self) -> PacketContent {
        (**self).content()
    }

    fn belongs_to(&self, packet_type: Type) -> bool {
        (**self).belongs_to(packet_type)
    }

    fn priority(&self) -> u32 {
        (**self).priority()
    }

    fn poll_dump(&mut self, cx: &mut Context<'_>, buffer: &mut PacketBuffer<'_, B>) -> Poll<usize> {
        (**self).poll_dump(cx, buffer)
    }
}

impl<B: BufMut + ?Sized, P: Package<B>> Package<B> for Option<P> {
    fn content(&self) -> PacketContent {
        self.as_ref().map_or(PacketContent::default(), Package::content)
    }

    fn belongs_to(&self, packet_type: Type) -> bool {
        self.as_ref().is_some_and(|source| source.belongs_to(packet_type))
    }

    fn priority(&self) -> u32 {
        self.as_ref().map_or(0, Package::priority)
    }

    fn poll_dump(&mut self, cx: &mut Context<'_>, buffer: &mut PacketBuffer<'_, B>) -> Poll<usize> {
        let Some(source) = self.as_mut() else {
            return Poll::Pending;
        };
        let result = source.poll_dump(cx, buffer);
        if matches!(result, Poll::Ready(n) if n > 0) {
            *self = None;
        }
        result
    }
}

/// Restrict a source to one packet-number space without duplicating its state.
impl<B: BufMut + ?Sized, P: Package<B>> Package<B> for (crate::Epoch, P) {
    fn content(&self) -> PacketContent {
        self.1.content()
    }

    fn belongs_to(&self, packet_type: Type) -> bool {
        use super::r#type::long::{Type as Long, Ver1};
        let epoch = match packet_type {
            Type::Long(Long::V1(Ver1::INITIAL)) => crate::Epoch::Initial,
            Type::Long(Long::V1(Ver1::HANDSHAKE)) => crate::Epoch::Handshake,
            Type::Long(Long::V1(Ver1::ZERO_RTT)) | Type::Short(_) => crate::Epoch::Data,
            _ => return false,
        };
        self.0 == epoch && self.1.belongs_to(packet_type)
    }

    fn priority(&self) -> u32 {
        self.1.priority()
    }

    fn poll_dump(&mut self, cx: &mut Context<'_>, buffer: &mut PacketBuffer<'_, B>) -> Poll<usize> {
        self.1.poll_dump(cx, buffer)
    }
}

macro_rules! frame_packages {
    ($($ty:ty),* $(,)?) => {$ (
        impl<B: BufMut + ?Sized> Package<B> for $ty {
            fn content(&self) -> PacketContent {
                self.frame_type().into()
            }
            fn belongs_to(&self, packet_type: Type) -> bool {
                self.frame_type().belongs_to(packet_type)
            }
            fn poll_dump(&mut self, _: &mut Context<'_>, buffer: &mut PacketBuffer<'_, B>) -> Poll<usize> {
                if !self.frame_type().belongs_to(buffer.meta.pktype) { return Poll::Ready(0); }
                buffer.for_frame(self.frame_type());
                if !buffer.can_fit(self.encoding_size()) { return Poll::Ready(0); }
                let frame: Frame = self.clone().into();
                buffer.put_frame(&frame);
                buffer.record(frame);
                Poll::Ready(1)
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
        where for<'a, 'b> &'a mut PacketBuffer<'b, B>: crate::util::WriteData<D> {
            fn belongs_to(&self, packet_type: Type) -> bool {
                self.0.frame_type().belongs_to(packet_type)
            }
            fn poll_dump(&mut self, _: &mut Context<'_>, buffer: &mut PacketBuffer<'_, B>) -> Poll<usize> {
                if !self.0.frame_type().belongs_to(buffer.meta.pktype) { return Poll::Ready(0); }
                buffer.for_frame(self.0.frame_type());
                if !buffer.can_fit(self.0.encoding_size().saturating_add(self.1.len())) { return Poll::Ready(0); }
                buffer.put_frame(&Frame::$variant(self.0, self.1.clone()));
                buffer.record(Frame::$variant(self.0, ()));
                Poll::Ready(1)
            }
        }
    )*};
}

data_packages!(StreamFrame => Stream, CryptoFrame => Crypto, DatagramFrame => Datagram);

macro_rules! stream_control_packages {
    ($($ty:ty),* $(,)?) => {$ (
        impl<B: BufMut + ?Sized> Package<B> for $ty {
            fn belongs_to(&self, packet_type: Type) -> bool {
                self.frame_type().belongs_to(packet_type)
            }
            fn poll_dump(&mut self, cx: &mut Context<'_>, buffer: &mut PacketBuffer<'_, B>) -> Poll<usize> {
                StreamCtlFrame::from(*self).poll_dump(cx, buffer)
            }
        }
    )*};
}
stream_control_packages!(
    MaxDataFrame,
    DataBlockedFrame,
    ResetStreamFrame,
    StopSendingFrame,
    MaxStreamDataFrame,
    MaxStreamsFrame,
    StreamDataBlockedFrame,
    StreamsBlockedFrame
);
