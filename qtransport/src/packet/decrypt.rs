use bytes::{Bytes, BytesMut};
use derive_more::Deref;
use qbase::packet::{PacketNumber, header::long::InitialHeader};
use qevent::quic::{
    PacketHeader, PacketHeaderBuilder, QuicFrame,
    transport::{PacketDropped, PacketDroppedTrigger, PacketReceived},
};

pub trait LogPacketHeader {
    fn qlog_header(&self) -> PacketHeader;
    fn qlog_header_with_pn(&self, pn: u64) -> PacketHeader;
}

impl<H> LogPacketHeader for H
where
    PacketHeaderBuilder: for<'a> From<&'a H>,
{
    fn qlog_header(&self) -> PacketHeader {
        PacketHeaderBuilder::from(self).build()
    }

    fn qlog_header_with_pn(&self, pn: u64) -> PacketHeader {
        PacketHeaderBuilder::from(self).packet_number(pn).build()
    }
}

#[derive(Debug, Deref)]
pub struct CipherPacket<H> {
    #[deref]
    header: H,
    payload: BytesMut,
    offset: usize,
}

impl<H> CipherPacket<H> {
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// Transfer the header and packet bytes to the receiving pipeline.
    pub fn split(self) -> (H, BytesMut, usize) {
        (self.header, self.payload, self.offset)
    }
}

impl<H> CipherPacket<H>
where
    H: LogPacketHeader,
{
    pub fn new(header: H, payload: BytesMut, offset: usize) -> Self {
        Self { header, payload, offset }
    }

    pub fn header(&self) -> &H {
        &self.header
    }

    fn qlog_header(&self) -> PacketHeader {
        self.header.qlog_header()
    }

    pub fn drop_on_key_unavailable(self) {
        qevent::event!(PacketDropped {
            header: self.qlog_header(),
            raw: self.payload.freeze(),
            trigger: PacketDroppedTrigger::KeyUnavailable
        })
    }

    pub fn drop_on_decryption_failure(self, pn: Option<u64>, error: impl ToString) {
        self.drop_with_error(pn, error, PacketDroppedTrigger::DecryptionFailure);
    }

    pub fn drop_on_invalid(self, pn: Option<u64>, error: impl ToString) {
        self.drop_with_error(pn, error, PacketDroppedTrigger::Invalid);
    }

    fn drop_with_error(self, pn: Option<u64>, error: impl ToString, trigger: PacketDroppedTrigger) {
        qevent::event!(
            PacketDropped {
                header: pn.map_or_else(|| self.header.qlog_header(), |pn| self.header.qlog_header_with_pn(pn)),
                raw: self.payload.freeze(),
                trigger,
            },
            details = Map { reason: error.to_string() },
        )
    }
}

impl CipherPacket<InitialHeader> {
    pub fn drop_on_scid_unmatch(self) {
        qevent::event!(
            PacketDropped { header: self.qlog_header(), raw: self.payload.freeze(), trigger: PacketDroppedTrigger::Rejected },
            details = Map { reason: "different scid with first initial packet" },
        )
    }
}

#[derive(Deref)]
pub struct PlainPacket<H> {
    #[deref]
    header: H,
    decoded_pn: u64,
    undecoded_pn: PacketNumber,
    plain: Bytes,
    offset: usize,
    body_len: usize,
}

impl<H> PlainPacket<H> {
    /// Assemble an authenticated packet after in-place opening and validation.
    pub fn new(header: H, decoded_pn: u64, undecoded_pn: PacketNumber, plain: Bytes, offset: usize, body_len: usize) -> Self {
        Self { header, decoded_pn, undecoded_pn, plain, offset, body_len }
    }

    pub fn size(&self) -> usize {
        self.plain.len()
    }

    pub fn pn(&self) -> u64 {
        self.decoded_pn
    }

    pub fn payload_len(&self) -> usize {
        self.undecoded_pn.size() + self.body_len
    }

    pub fn body(&self) -> Bytes {
        let packet_offset = self.offset + self.undecoded_pn.size();
        self.plain.slice(packet_offset..packet_offset + self.body_len)
    }

    pub fn raw_info(&self) -> qevent::RawInfo {
        qevent::build!(qevent::RawInfo { length: self.plain.len() as u64, payload_length: self.payload_len() as u64, data: &self.plain })
    }
}

impl<H> PlainPacket<H>
where
    H: LogPacketHeader,
{
    pub fn qlog_header(&self) -> PacketHeader {
        self.header.qlog_header_with_pn(self.decoded_pn)
    }

    pub fn drop_on_interface_not_found(self) {
        qevent::event!(
            PacketDropped { header: self.qlog_header(), raw: self.raw_info(), trigger: PacketDroppedTrigger::Genera },
            details = Map { reason: "interface not found" }
        )
    }

    pub fn drop_on_conenction_closed(self) {
        qevent::event!(
            PacketDropped { header: self.qlog_header(), raw: self.raw_info(), trigger: PacketDroppedTrigger::Genera },
            details = Map { reason: "connection closed" }
        )
    }

    pub fn log_received(&self, frames: impl Into<Vec<QuicFrame>>) {
        qevent::event!(PacketReceived { header: self.qlog_header(), frames, raw: self.raw_info() })
    }
}
