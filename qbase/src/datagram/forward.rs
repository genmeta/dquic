use bytes::BytesMut;

use crate::{
    datagram::{Error, GetDatagramType, Type as DatagramType, WriteDatagramType, r#type::v0},
    net::{
        AddrFamily,
        route::{Pathway, WritePathway},
    },
};

pub type Header = Pathway;

impl GetDatagramType for Header {
    fn get_datagram_type(&self) -> DatagramType {
        DatagramType::V0(v0::Type::Forward(
            self.local().family(),
            self.local().kind(),
            self.remote().kind(),
        ))
    }
}

/// The backing bytes of a Forward datagram and its encapsulated raw payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Payload {
    bytes: BytesMut,
    raw_offset: usize,
}

impl Payload {
    /// Writes a Forward header into the headroom before a raw datagram.
    pub fn from_raw(
        pathway: &Pathway,
        mut bytes: BytesMut,
        raw_offset: usize,
    ) -> Result<Self, Error> {
        if raw_offset >= bytes.len() {
            return Err(Error::InvalidForwardDatagram);
        }
        let source = pathway.local();
        let destination = pathway.remote();
        let family = source.family();
        if source.addr().family() != family
            || destination.family() != family
            || destination.addr().family() != family
        {
            return Err(Error::InvalidForwardDatagram);
        }
        let header_len = 2 + source.encoding_size() + destination.encoding_size();
        if raw_offset < header_len {
            return Err(Error::InvalidForwardDatagram);
        }

        let raw = bytes.split_off(raw_offset);
        let mut bytes = bytes.split_off(raw_offset - header_len);
        let mut header = bytes.as_mut();
        header.put_datagram_type(&pathway.get_datagram_type());
        header.put_pathway(pathway);
        debug_assert!(header.is_empty());
        bytes.unsplit(raw);
        Ok(Self {
            bytes,
            raw_offset: header_len,
        })
    }

    /// Removes the Forward header and returns the complete raw datagram.
    pub fn into_raw(mut self) -> BytesMut {
        self.bytes.split_off(self.raw_offset)
    }

    pub(super) fn raw(&self) -> &[u8] {
        &self.bytes[self.raw_offset..]
    }

    pub(crate) fn new(bytes: BytesMut, raw_offset: usize) -> Self {
        debug_assert!(raw_offset < bytes.len());
        Self { bytes, raw_offset }
    }
}

impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
