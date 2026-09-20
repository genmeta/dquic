use bytes::{Bytes, BytesMut};
use derive_more::Deref;
use qbase::{
    error::QuicError,
    packet::{
        GetPacketNumberLength, KeyPhaseBit, LongSpecificBits, ShortSpecificBits,
        header::long::InitialHeader,
        number::{InvalidPacketNumber, PacketNumber, take_pn_len},
    },
};
use qevent::quic::{
    PacketHeader, PacketHeaderBuilder, QuicFrame,
    transport::{PacketDropped, PacketDroppedTrigger, PacketReceived},
};

pub mod channel;

pub trait RcvdPacketHeader {
    fn qlog_header(&self) -> PacketHeader;
    fn qlog_header_with_pn(&self, pn: u64) -> PacketHeader;
}

impl<H> RcvdPacketHeader for H
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
    payload_offset: usize,
}

impl<H> CipherPacket<H> {
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    fn remove_header_protection(&mut self, key: &qtls::HeaderProtectionKey) -> bool {
        let sample_offset = self.payload_offset.saturating_add(4);
        if self.payload_offset == 0
            || sample_offset.saturating_add(key.sample_len()) > self.payload.len()
        {
            return false;
        }
        let (header, sample) = self.payload.split_at_mut(sample_offset);
        let (prefix, packet_number) = header.split_at_mut(self.payload_offset);
        key.unprotect(&sample[..key.sample_len()], &mut prefix[0], packet_number)
            .is_ok()
    }
}

impl<H> CipherPacket<H>
where
    H: RcvdPacketHeader,
{
    pub fn new(header: H, payload: BytesMut, payload_offset: usize) -> Self {
        Self {
            header,
            payload,
            payload_offset,
        }
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

    fn drop_on_remove_header_protection_failure(self) {
        qevent::event!(
            PacketDropped {
                header: self.qlog_header(),
                raw: self.payload.freeze(),
                trigger: PacketDroppedTrigger::DecryptionFailure
            },
            details = Map {
                reason: "remove header protection failure"
            }
        );
    }

    fn drop_on_decryption_failure(self, error: impl ToString, pn: u64) {
        qevent::event!(
            PacketDropped {
                header: { self.header.qlog_header_with_pn(pn) },
                raw: self.payload.freeze(),
                trigger: PacketDroppedTrigger::DecryptionFailure
            },
            details = Map {
                reason: "decryption failure",
                error: error.to_string(),
            },
        )
    }

    fn drop_on_reverse_bit_error(self, error: &qbase::packet::error::Error) {
        qevent::event!(
            PacketDropped {
                header: self.qlog_header(),
                raw: self.payload.freeze(),
                trigger: PacketDroppedTrigger::Invalid,
            },
            details = Map {
                reason: "reverse bit error",
                error: error.to_string()
            },
        )
    }

    fn drop_on_invalid_pn(self, invalid_pn: InvalidPacketNumber) {
        qevent::event!(
            PacketDropped {
                header: self.qlog_header(),
                raw: self.payload.freeze(),
                trigger: PacketDroppedTrigger::Invalid,
            },
            details = Map {
                reason: "invalid packet number",
                invalid_pn: invalid_pn.to_string()
            },
        )
    }

    pub fn decrypt_long_packet(
        mut self,
        keys: &qtls::DirectionalKeys,
        pn_decoder: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
    ) -> Option<Result<PlainPacket<H>, QuicError>> {
        if !self.remove_header_protection(&keys.header) {
            self.drop_on_remove_header_protection_failure();
            return None;
        }
        let first = self.payload[0];
        let pn_len = (first & 3) + 1;
        let (_, undecoded_pn) = take_pn_len(pn_len)(&self.payload[self.payload_offset..]).ok()?;
        let decoded_pn = match pn_decoder(undecoded_pn) {
            Ok(pn) => pn,
            Err(invalid_packet_number) => {
                self.drop_on_invalid_pn(invalid_packet_number);
                return None;
            }
        };
        let body_offset = self.payload_offset + undecoded_pn.size();
        let (header, body) = self.payload.split_at_mut(body_offset);
        let body_length = match keys.packet.open(decoded_pn, header, body) {
            Ok(plain) => plain.len(),
            Err(error) => {
                self.drop_on_decryption_failure(error, decoded_pn);
                return None;
            }
        };
        if let Err(error) = LongSpecificBits::from(first).pn_len() {
            self.drop_on_reverse_bit_error(&error);
            return Some(Err(error.into()));
        }

        Some(Ok(PlainPacket {
            header: self.header,
            plain: self.payload.freeze(),
            payload_offset: self.payload_offset,
            undecoded_pn,
            decoded_pn,
            body_len: body_length,
        }))
    }

    pub fn decrypt_short_packet(
        mut self,
        header_key: &qtls::HeaderProtectionKey,
        pn_decoder: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
        decrypt: impl FnOnce(u64, KeyPhaseBit, &[u8], &mut [u8]) -> Result<Option<usize>, crate::Error>,
    ) -> Result<Option<PlainPacket<H>>, crate::Error> {
        if !self.remove_header_protection(header_key) {
            self.drop_on_remove_header_protection_failure();
            return Ok(None);
        }
        let first = self.payload[0];
        let specific_bits = ShortSpecificBits::from(first);
        let pn_len = (first & 3) + 1;
        let Some((_, undecoded_pn)) =
            take_pn_len(pn_len)(&self.payload[self.payload_offset..]).ok()
        else {
            self.drop_on_remove_header_protection_failure();
            return Ok(None);
        };
        let decoded_pn = match pn_decoder(undecoded_pn) {
            Ok(pn) => pn,
            Err(invalid_pn) => {
                self.drop_on_invalid_pn(invalid_pn);
                return Ok(None);
            }
        };
        let body_offset = self.payload_offset + undecoded_pn.size();
        let (header, body) = self.payload.split_at_mut(body_offset);
        let Some(body_length) = decrypt(decoded_pn, specific_bits.key_phase(), header, body)?
        else {
            self.drop_on_decryption_failure("packet authentication failed", decoded_pn);
            return Ok(None);
        };
        if let Err(error) = specific_bits.pn_len() {
            self.drop_on_reverse_bit_error(&error);
            return Err(QuicError::from(error).into());
        }

        Ok(Some(PlainPacket {
            header: self.header,
            plain: self.payload.freeze(),
            payload_offset: self.payload_offset,
            undecoded_pn,
            decoded_pn,
            body_len: body_length,
        }))
    }
}

impl CipherPacket<InitialHeader> {
    pub fn drop_on_scid_unmatch(self) {
        qevent::event!(
            PacketDropped {
                header: self.qlog_header(),
                raw: self.payload.freeze(),
                trigger: PacketDroppedTrigger::Rejected
            },
            details = Map {
                reason: "different scid with first initial packet"
            },
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
    payload_offset: usize,
    body_len: usize,
}

impl<H> PlainPacket<H> {
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
        let packet_offset = self.payload_offset + self.undecoded_pn.size();
        self.plain
            .slice(packet_offset..packet_offset + self.body_len)
    }

    pub fn raw_info(&self) -> qevent::RawInfo {
        qevent::build!(qevent::RawInfo {
            length: self.plain.len() as u64,
            payload_length: self.payload_len() as u64,
            data: &self.plain,
        })
    }
}

impl<H> PlainPacket<H>
where
    H: RcvdPacketHeader,
{
    pub fn qlog_header(&self) -> PacketHeader {
        self.header.qlog_header_with_pn(self.decoded_pn)
    }

    pub fn drop_on_interface_not_found(self) {
        qevent::event!(
            PacketDropped {
                header: self.qlog_header(),
                raw: self.raw_info(),
                trigger: PacketDroppedTrigger::Genera
            },
            details = Map {
                reason: "interface not found"
            }
        )
    }

    pub fn drop_on_conenction_closed(self) {
        qevent::event!(
            PacketDropped {
                header: self.qlog_header(),
                raw: self.raw_info(),
                trigger: PacketDroppedTrigger::Genera
            },
            details = Map {
                reason: "connection closed"
            }
        )
    }

    pub fn log_received(&self, frames: impl Into<Vec<QuicFrame>>) {
        qevent::event!(PacketReceived {
            header: self.qlog_header(),
            frames,
            raw: self.raw_info(),
        })
    }
}
