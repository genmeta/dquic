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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        datagram::{Datagram as OuterDatagram, be_datagram},
        net::addr::EndpointAddr,
    };

    fn pathway() -> Pathway {
        Pathway::new(
            EndpointAddr::with_agent(
                "198.51.100.1:3478".parse().unwrap(),
                "192.0.2.1:50000".parse().unwrap(),
            ),
            EndpointAddr::direct("203.0.113.1:4433".parse().unwrap()),
        )
    }

    fn round_trip(raw: &[u8]) {
        let raw = BytesMut::from(raw);
        let header_len = 2 + pathway().local().encoding_size() + pathway().remote().encoding_size();
        let raw_offset = header_len + 17;
        let mut bytes = BytesMut::zeroed(raw_offset + raw.len());
        bytes[raw_offset..].copy_from_slice(&raw);
        let raw_ptr = bytes[raw_offset..].as_ptr();
        let encoded = Payload::from_raw(&pathway(), bytes, raw_offset).unwrap();
        assert_eq!(encoded.as_ref()[0] & 0b1110_0000, 0b0110_0000);
        assert_eq!(encoded.raw_offset, header_len);
        assert_eq!(encoded.as_ref().len(), header_len + raw.len());
        assert_eq!(&encoded.as_ref()[encoded.raw_offset..], raw.as_ref());
        assert_eq!(encoded.as_ref()[encoded.raw_offset..].as_ptr(), raw_ptr);

        let mut written = BytesMut::new();
        written.extend_from_slice(encoded.as_ref());
        assert_eq!(written.as_ref(), encoded.as_ref());

        let OuterDatagram::Forward(decoded_pathway, decoded) = be_datagram(written).unwrap() else {
            panic!("expected Forward datagram");
        };
        assert_eq!(decoded_pathway, pathway());
        assert_eq!(decoded.into_raw(), raw);
    }

    #[test]
    fn raw_long_datagram_round_trips() {
        round_trip(&[0xc1, 0, 0, 0, 1, 1, 2, 3]);
    }

    #[test]
    fn raw_short_datagram_round_trips() {
        round_trip(&[0x45, 1, 2, 3]);
    }

    #[test]
    fn empty_raw_datagram_is_rejected() {
        assert_eq!(
            Payload::from_raw(&pathway(), BytesMut::zeroed(128), 128),
            Err(Error::InvalidForwardDatagram)
        );
    }

    #[test]
    fn insufficient_headroom_is_rejected() {
        assert_eq!(
            Payload::from_raw(&pathway(), BytesMut::zeroed(2), 1),
            Err(Error::InvalidForwardDatagram)
        );
    }
}
