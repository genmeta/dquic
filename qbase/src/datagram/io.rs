use bytes::{BufMut, BytesMut};

use super::{
    Error, forward,
    stun::{self, WriteStunMessage, WriteTransactionId},
    r#type::{GetDatagramType, Type, WriteDatagramType, v0},
};
use crate::net::route::{Pathway, WritePathway, be_pathway};

/// A classified UDP datagram.
#[derive(Debug, Clone, PartialEq)]
pub enum Datagram {
    Stun(stun::TransactionId, stun::Message),
    Forward(Pathway, forward::Payload),
    Raw(BytesMut),
}

impl GetDatagramType for Datagram {
    fn get_datagram_type(&self) -> Type {
        match self {
            Self::Stun(_, message) => message.get_datagram_type(),
            Self::Forward(pathway, _) => pathway.get_datagram_type(),
            Self::Raw(_) => Type::Raw,
        }
    }
}

/// Classifies and decodes one complete UDP datagram.
pub fn be_datagram(bytes: BytesMut) -> Result<Datagram, Error> {
    let (input, ty) = super::be_datagram_type(&bytes).map_err(|_| Error::InvalidDatagramType)?;
    match ty {
        Type::V0(v0::Type::Stun(ty)) => {
            let (input, transaction_id) =
                stun::be_transaction_id(input).map_err(|_| Error::InvalidStunMessage)?;
            let (remain, message) =
                stun::be_stun_message(ty, input).map_err(|_| Error::InvalidStunMessage)?;
            if !remain.is_empty() {
                return Err(Error::InvalidStunMessage);
            }
            Ok(Datagram::Stun(transaction_id, message))
        }
        Type::V0(v0::Type::Forward(family, source, destination)) => {
            let (raw_offset, pathway) = {
                let (raw, pathway) = be_pathway(input, family, source, destination)
                    .map_err(|_| Error::InvalidForwardDatagram)?;
                if raw.is_empty() {
                    return Err(Error::InvalidForwardDatagram);
                }
                (bytes.len() - raw.len(), pathway)
            };
            let payload = forward::Payload::new(bytes, raw_offset);
            Ok(Datagram::Forward(pathway, payload))
        }
        Type::Raw => Ok(Datagram::Raw(bytes)),
    }
}

pub trait WriteDatagram: BufMut {
    fn put_datagram(&mut self, datagram: &Datagram) -> Result<(), Error>;
}

impl<T: BufMut> WriteDatagram for T {
    fn put_datagram(&mut self, datagram: &Datagram) -> Result<(), Error> {
        match datagram {
            Datagram::Stun(transaction_id, message) => {
                self.put_datagram_type(&message.get_datagram_type());
                self.put_transaction_id(transaction_id);
                self.put_stun_message(message);
                Ok(())
            }
            Datagram::Forward(pathway, payload) => {
                self.put_datagram_type(&pathway.get_datagram_type());
                self.put_pathway(pathway);
                self.put_slice(payload.raw());
                Ok(())
            }
            Datagram::Raw(bytes) => {
                self.put_slice(bytes);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        datagram::stun::{Attribute, BindingRequest, BindingResponse, Message, TransactionId},
        net::addr::EndpointAddr,
    };

    fn pathway() -> Pathway {
        Pathway::new(
            EndpointAddr::direct("203.0.113.1:4433".parse().unwrap()),
            EndpointAddr::mediate(
                "198.51.100.1:3478".parse().unwrap(),
                "192.0.2.1:50000".parse().unwrap(),
            ),
        )
    }

    fn round_trip(datagram: Datagram) {
        let mut bytes = BytesMut::new();
        bytes.put_datagram(&datagram).unwrap();
        assert_eq!(be_datagram(bytes).unwrap(), datagram);
    }

    fn forward_payload(pathway: &Pathway, raw: &[u8]) -> forward::Payload {
        let raw_offset = 2 + pathway.local().encoding_size() + pathway.remote().encoding_size();
        let mut bytes = BytesMut::zeroed(raw_offset + raw.len());
        bytes[raw_offset..].copy_from_slice(raw);
        forward::Payload::from_raw(pathway, bytes, raw_offset).unwrap()
    }

    #[test]
    fn stun_request_round_trips() {
        round_trip(Datagram::Stun(
            TransactionId::random(),
            Message::Request(BindingRequest::change_ip_and_port()),
        ));
    }

    #[test]
    fn stun_response_round_trips() {
        let mapped = "203.0.113.1:4433".parse().unwrap();
        round_trip(Datagram::Stun(
            TransactionId::random(),
            Message::Response(BindingResponse::with(vec![Attribute::MappedAddress(
                mapped,
            )])),
        ));
    }

    fn forward_round_trip(pathway: Pathway, raw: &[u8]) {
        let payload = forward_payload(&pathway, raw);
        let mut bytes = BytesMut::new();
        bytes
            .put_datagram(&Datagram::Forward(pathway, payload))
            .unwrap();

        let Datagram::Forward(decoded_pathway, decoded_payload) = be_datagram(bytes).unwrap()
        else {
            panic!("expected Forward datagram");
        };
        assert_eq!(decoded_pathway, pathway);
        assert_eq!(decoded_payload.into_raw(), raw);
    }

    #[test]
    fn forward_round_trips_raw_long_datagram() {
        let pathway = pathway();
        forward_round_trip(pathway, &[0xc1, 0, 0, 0, 1, 1, 2, 3]);
    }

    #[test]
    fn forward_round_trips_raw_short_datagram() {
        let pathway = pathway();
        forward_round_trip(pathway, &[0x45, 1, 2, 3]);
    }

    #[test]
    fn forward_writer_uses_the_datagram_pathway() {
        let payload_pathway = pathway();
        let datagram_pathway = Pathway::new(
            EndpointAddr::direct("192.0.2.10:50000".parse().unwrap()),
            EndpointAddr::direct("192.0.2.20:4433".parse().unwrap()),
        );
        let raw = [0x45, 1, 2, 3];
        let payload = forward_payload(&payload_pathway, &raw);
        let mut bytes = BytesMut::new();
        bytes
            .put_datagram(&Datagram::Forward(datagram_pathway, payload))
            .unwrap();

        let Datagram::Forward(decoded_pathway, decoded_payload) = be_datagram(bytes).unwrap()
        else {
            panic!("expected Forward datagram");
        };
        assert_eq!(decoded_pathway, datagram_pathway);
        assert_eq!(decoded_payload.into_raw(), raw.as_slice());
    }

    #[test]
    fn raw_round_trips() {
        round_trip(Datagram::Raw(BytesMut::from(&[0x40, 1, 2, 3][..])));
    }

    #[test]
    fn raw_long_datagrams_are_preserved() {
        for input in [
            &[0xc0, 0, 0, 0, 0, 0xaa, 0xbb][..],
            &[0xe0, 0, 0, 0, 1, 0xaa, 0xbb][..],
        ] {
            let bytes = BytesMut::from(input);
            assert_eq!(be_datagram(bytes.clone()), Ok(Datagram::Raw(bytes)));
        }
    }

    #[test]
    fn invalid_type_is_rejected_before_payload_parsing() {
        assert_eq!(
            be_datagram(BytesMut::from(&[0x20, 0][..])),
            Err(Error::InvalidDatagramType)
        );
        assert_eq!(
            be_datagram(BytesMut::from(&[0xe2, 0, 0, 0, 0, 0, 0, 0, 0][..])),
            Err(Error::InvalidDatagramType)
        );
    }

    #[test]
    fn truncated_stun_datagram_is_rejected() {
        let mut bytes = BytesMut::new();
        bytes.put_datagram_type(&Type::V0(v0::Type::Stun(stun::Type::BindingRequest)));
        bytes.put_slice(&[0; 15]);
        assert_eq!(be_datagram(bytes), Err(Error::InvalidStunMessage));
    }

    #[test]
    fn legacy_stun_request_is_rejected_without_panicking() {
        // The legacy layout encoded a separate u16 message type between the
        // nine-byte camouflage header and the transaction ID. The current
        // layout carries the message type in the camouflage header itself.
        let mut bytes = BytesMut::from(&[0xc2, 0, 0, 0, 0, 0, 0, 0, 0][..]);
        bytes.put_u16(1);
        bytes.put_slice(&[0; 16]);

        assert_eq!(bytes.len(), 27);
        assert_eq!(be_datagram(bytes), Err(Error::InvalidStunMessage));
    }
}
