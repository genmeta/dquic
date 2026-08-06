use bytes::BufMut;
use derive_more::Deref;
use qbase::{
    frame::{ContainSpec, FrameFeature, Spec},
    net::tx::Signals,
    packet::{
        AssemblePacket, PacketInfo, PacketWriter as BasePacketWriter, RecordFrame,
        header::{GetType, HeaderSize, io::WriteHeader, long::LongHeader, short::OneRttHeader},
        keys::DirectionalKeys,
        signal::KeyPhaseBit,
    },
    util::ContinuousData,
};
use qevent::packet::PacketWriter as QEventPacketWriter;
use qrecovery::journal::{ArcSentJournal, NewPacketGuard};
use tokio::time::Duration;

#[derive(Deref)]
pub struct PacketWriter<'b, 's, F> {
    #[deref]
    writer: QEventPacketWriter<'b>,
    // 不同空间的send guard类型不一样
    clerk: NewPacketGuard<'s, F>,
    retran_timeout: Duration,
    expire_timeout: Duration,
}

impl<'b, F> AsRef<BasePacketWriter<'b>> for PacketWriter<'b, '_, F> {
    #[inline]
    fn as_ref(&self) -> &BasePacketWriter<'b> {
        &self.writer
    }
}

impl<'b, F> AsRef<QEventPacketWriter<'b>> for PacketWriter<'b, '_, F> {
    #[inline]
    fn as_ref(&self) -> &QEventPacketWriter<'b> {
        &self.writer
    }
}

impl<'b, 's, F> PacketWriter<'b, 's, F> {
    pub fn new_long<S>(
        header: LongHeader<S>,
        buffer: &'b mut [u8],
        keys: DirectionalKeys,
        journal: &'s ArcSentJournal<F>,
        retran_timeout: Duration,
        expire_timeout: Duration,
    ) -> Result<Self, Signals>
    where
        S: HeaderSize + 'static,
        LongHeader<S>: GetType,
        for<'a> &'a mut [u8]: WriteHeader<LongHeader<S>>,
    {
        let clerk = journal.new_packet();
        let pn = clerk.pn();
        Ok(Self {
            clerk,
            writer: QEventPacketWriter::new_long(&header, buffer, pn, keys)?,
            expire_timeout,
            retran_timeout,
        })
    }

    pub fn new_short(
        header: OneRttHeader,
        buffer: &'b mut [u8],
        keys: DirectionalKeys,
        key_phase: KeyPhaseBit,
        journal: &'s ArcSentJournal<F>,
        retran_timeout: Duration,
        expire_timeout: Duration,
    ) -> Result<Self, Signals> {
        let clerk = journal.new_packet();
        let pn = clerk.pn();
        Ok(Self {
            clerk,
            writer: QEventPacketWriter::new_short(&header, buffer, pn, keys, key_phase)?,
            expire_timeout,
            retran_timeout,
        })
    }
}

unsafe impl<'b, 's, F> BufMut for PacketWriter<'b, 's, F> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.writer.remaining_mut()
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        unsafe { self.writer.advance_mut(cnt) };
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        self.writer.chunk_mut()
    }

    // steam/datagram可能会手动padding，padding也要被记录，所以这里不能用默认实现
    #[inline]
    fn put_bytes(&mut self, val: u8, cnt: usize) {
        self.writer.put_bytes(val, cnt);
    }
}

impl<F> AssemblePacket for PacketWriter<'_, '_, F> {
    #[inline]
    fn encrypt_and_protect_packet(self) -> (usize, PacketInfo) {
        self.clerk
            .build_with_time(self.retran_timeout, self.expire_timeout);
        self.writer.encrypt_and_protect_packet()
    }
}

impl<'b, GF, F, D: ContinuousData> RecordFrame<F, D> for PacketWriter<'b, '_, GF>
where
    QEventPacketWriter<'b>: RecordFrame<F, D>,
    for<'f> &'f F: TryInto<GF>,
{
    #[inline]
    fn record_frame(&mut self, frame: &F) {
        if let Ok(frame) = frame.try_into() {
            self.clerk.record_frame(frame);
        } else {
            self.clerk.record_trivial();
        }

        self.writer.record_frame(frame);
    }
}

#[derive(Deref)]
pub struct TrivialPacketWriter<'b, 's, F> {
    #[deref]
    writer: QEventPacketWriter<'b>,
    // 不同空间的send guard类型不一样
    clerk: NewPacketGuard<'s, F>,
}

impl<'b, F> AsRef<BasePacketWriter<'b>> for TrivialPacketWriter<'b, '_, F> {
    #[inline]
    fn as_ref(&self) -> &BasePacketWriter<'b> {
        &self.writer
    }
}

impl<'b, F> AsRef<QEventPacketWriter<'b>> for TrivialPacketWriter<'b, '_, F> {
    #[inline]
    fn as_ref(&self) -> &QEventPacketWriter<'b> {
        &self.writer
    }
}

impl<'b, 's, F> TrivialPacketWriter<'b, 's, F> {
    #[inline]
    pub fn new_long<S>(
        header: LongHeader<S>,
        buffer: &'b mut [u8],
        keys: DirectionalKeys,
        journal: &'s ArcSentJournal<F>,
    ) -> Result<Self, Signals>
    where
        S: HeaderSize + 'static,
        LongHeader<S>: GetType,
        for<'a> &'a mut [u8]: WriteHeader<LongHeader<S>>,
    {
        let clerk = journal.new_packet();
        let pn = clerk.pn();
        Ok(Self {
            clerk,
            writer: QEventPacketWriter::new_long(&header, buffer, pn, keys)?,
        })
    }

    #[inline]
    pub fn new_short(
        header: OneRttHeader,
        buffer: &'b mut [u8],
        keys: DirectionalKeys,
        key_phase: KeyPhaseBit,
        journal: &'s ArcSentJournal<F>,
    ) -> Result<Self, Signals> {
        let clerk = journal.new_packet();
        let pn = clerk.pn();
        Ok(Self {
            clerk,
            writer: QEventPacketWriter::new_short(&header, buffer, pn, keys, key_phase)?,
        })
    }
}

unsafe impl<'b, 's, F> BufMut for TrivialPacketWriter<'b, 's, F> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.writer.remaining_mut()
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        unsafe { self.writer.advance_mut(cnt) };
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        self.writer.chunk_mut()
    }

    // steam/datagram可能会手动padding，padding也要被记录，所以这里不能用默认实现
    #[inline]
    fn put_bytes(&mut self, val: u8, cnt: usize) {
        self.writer.put_bytes(val, cnt);
    }
}

impl<F> AssemblePacket for TrivialPacketWriter<'_, '_, F> {
    #[inline]
    fn encrypt_and_protect_packet(self) -> (usize, PacketInfo) {
        self.clerk.build_trivial();
        self.writer.encrypt_and_protect_packet()
    }
}

impl<'b, GF, F, D: ContinuousData> RecordFrame<F, D> for TrivialPacketWriter<'b, '_, GF>
where
    F: FrameFeature,
    QEventPacketWriter<'b>: RecordFrame<F, D>,
{
    #[inline]
    fn record_frame(&mut self, frame: &F) {
        // however, this will be checked again in NewPacketGuard::build_trivial
        debug_assert!(
            frame.specs().contain(Spec::NonAckEliciting),
            "Frame is not non-ack eliciting {}",
            std::any::type_name::<F>()
        );
        self.clerk.record_trivial();
        self.writer.record_frame(frame);
    }
}
