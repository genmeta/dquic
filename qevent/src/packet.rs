use bytes::{BufMut, buf::UninitSlice};
use derive_more::Deref;
use qbase::{
    net::tx::Signals,
    packet::{
        RecordFrame,
        header::{
            HeaderSize, GetDcid, GetScid, GetType, io::WriteHeader, long::LongHeader,
            short::OneRttHeader,
        },
        io::{AssemblePacket, PacketInfo, PacketWriter as BasePacketWriter},
        keys::DirectionalKeys,
        number::PacketNumber,
        signal::KeyPhaseBit,
    },
    util::ContinuousData,
};

use crate::{
    RawInfo,
    quic::{
        PacketHeader as QEventPacketHeader, PacketHeaderBuilder as QEventPacketHeaderBuilder,
        QuicFrame as QEventFrame, QuicFramesCollector, transport::PacketSent,
    },
};

struct PacketLogger {
    header: QEventPacketHeaderBuilder,
    frames: QuicFramesCollector<PacketSent>,
}

impl PacketLogger {
    pub fn record_frame(&mut self, frame: impl Into<QEventFrame>) {
        self.frames.extend([frame]);
    }

    pub fn log_sent(mut self, packet: &BasePacketWriter) {
        // TODO: 如果以后涉及到组装VN，Retry，这里的逻辑得改
        if !packet.is_short_header() {
            self.header.length((packet.payload_len()) as u16);
        }

        crate::event!(PacketSent {
            header: self.header.build(),
            frames: self.frames,
            raw: RawInfo {
                length: packet.packet_len() as u64,
                payload_length: packet.payload_len() as u64,
                data: packet.buffer(),
            },
            // TODO: trigger
        })
    }
}

#[derive(Deref)]
pub struct PacketWriter<'b> {
    #[deref]
    writer: BasePacketWriter<'b>,
    logger: PacketLogger,
}

impl<'b> AsRef<BasePacketWriter<'b>> for PacketWriter<'b> {
    #[inline]
    fn as_ref(&self) -> &BasePacketWriter<'b> {
        &self.writer
    }
}

impl<'b> PacketWriter<'b> {
    pub fn new_long<S>(
        header: &LongHeader<S>,
        buffer: &'b mut [u8],
        pn: (u64, PacketNumber),
        keys: DirectionalKeys,
    ) -> Result<Self, Signals>
    where
        S: HeaderSize,
        LongHeader<S>: GetType,
        for<'a> &'a mut [u8]: WriteHeader<LongHeader<S>>,
    {
        Ok(Self {
            writer: BasePacketWriter::new_long(header, buffer, pn, keys)?,
            logger: PacketLogger {
                header: {
                    let mut builder = QEventPacketHeader::builder();
                    builder
                        .packet_type(header.get_type())
                        .packet_number(pn.0)
                        .scil(header.scid().len() as u8)
                        .scid(*header.scid())
                        .dcil(header.dcid().len() as u8)
                        .dcid(*header.dcid());
                    builder
                },
                frames: QuicFramesCollector::new(),
            },
        })
    }

    pub fn new_short(
        header: &OneRttHeader,
        buffer: &'b mut [u8],
        pn: (u64, PacketNumber),
        keys: DirectionalKeys,
        key_phase: KeyPhaseBit,
    ) -> Result<Self, Signals> {
        Ok(Self {
            writer: BasePacketWriter::new_short(header, buffer, pn, keys, key_phase)?,
            logger: PacketLogger {
                header: {
                    let mut builder = QEventPacketHeader::builder();
                    builder
                        .packet_type(header.get_type())
                        .packet_number(pn.0)
                        .dcil(header.dcid().len() as u8)
                        .dcid(*header.dcid());
                    builder
                },
                frames: QuicFramesCollector::new(),
            },
        })
    }
}

unsafe impl<'b> BufMut for PacketWriter<'b> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.writer.remaining_mut()
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        unsafe { self.writer.advance_mut(cnt) }
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        self.writer.chunk_mut()
    }

    #[inline]
    fn put_bytes(&mut self, val: u8, cnt: usize) {
        if cnt > 0 {
            self.logger.record_frame(QEventFrame::Padding {
                length: Some(cnt as _),
                payload_length: cnt as _,
            });
            self.writer.put_bytes(val, cnt);
        }
    }
}

impl<'b, F, D: ContinuousData> RecordFrame<F, D> for PacketWriter<'b>
where
    for<'f> &'f F: Into<QEventFrame>,
    BasePacketWriter<'b>: RecordFrame<F, D>,
{
    #[inline]
    fn record_frame(&mut self, frame: &F) {
        self.logger.record_frame(frame);
        self.writer.record_frame(frame);
    }
}

impl<'b> AssemblePacket for PacketWriter<'b> {
    #[inline]
    fn encrypt_and_protect_packet(self) -> (usize, PacketInfo) {
        self.logger.log_sent(&self.writer);
        self.writer.encrypt_and_protect_packet()
    }
}
