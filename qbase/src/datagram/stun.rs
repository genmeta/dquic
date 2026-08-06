use std::{io, net::SocketAddr};

use bytes::BufMut;
use nom::{
    Err, IResult, Parser,
    bytes::streaming::take,
    combinator::map,
    error::{Error, ErrorKind},
    multi::many0,
    number::streaming::be_u8,
};
use rand::RngExt;
use thiserror::Error;

pub use super::r#type::stun::{Type, WriteStunType, be_stun_type};
use super::r#type::{GetDatagramType, Type as OuterType, v0};
use crate::net::{AddrFamily, Family, WriteSocketAddr, be_socket_addr};
pub type MessageType = Type;

pub const CHANGE_PORT: u8 = 0x01;
pub const CHANGE_IP: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionId([u8; 16]);

impl AsRef<[u8]> for TransactionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TransactionId {
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut id = [0; 16];
        id.copy_from_slice(slice);
        Self(id)
    }

    pub fn random() -> Self {
        let mut id = [0; 16];
        rand::rng().fill(&mut id);
        Self(id)
    }
}

pub fn be_transaction_id(input: &[u8]) -> IResult<&[u8], TransactionId> {
    take(16usize).map(TransactionId::from_slice).parse(input)
}

pub trait WriteTransactionId: BufMut {
    fn put_transaction_id(&mut self, transaction_id: &TransactionId);
}

impl<T: BufMut> WriteTransactionId for T {
    fn put_transaction_id(&mut self, transaction_id: &TransactionId) {
        self.put_slice(transaction_id.as_ref());
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Attribute {
    MappedAddress(SocketAddr),
    ResponseAddress(SocketAddr),
    ChangeRequest(u8),
    SourceAddress(SocketAddr),
    ChangedAddress(SocketAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeType {
    MappedAddress(Family),
    ResponseAddress(Family),
    ChangeRequest(u8),
    SourceAddress(Family),
    ChangedAddress(Family),
}

#[derive(Debug, Error)]
#[error("invalid STUN attribute type: {0}")]
pub struct InvalidAttributeType(u8);

impl From<AttributeType> for u8 {
    fn from(value: AttributeType) -> Self {
        match value {
            AttributeType::MappedAddress(Family::V4) => 0,
            AttributeType::MappedAddress(Family::V6) => 1,
            AttributeType::ResponseAddress(Family::V4) => 2,
            AttributeType::ResponseAddress(Family::V6) => 3,
            AttributeType::SourceAddress(Family::V4) => 4,
            AttributeType::SourceAddress(Family::V6) => 5,
            AttributeType::ChangedAddress(Family::V4) => 6,
            AttributeType::ChangedAddress(Family::V6) => 7,
            AttributeType::ChangeRequest(flags) => 8 | flags,
        }
    }
}

impl TryFrom<u8> for AttributeType {
    type Error = InvalidAttributeType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::MappedAddress(Family::V4)),
            1 => Ok(Self::MappedAddress(Family::V6)),
            2 => Ok(Self::ResponseAddress(Family::V4)),
            3 => Ok(Self::ResponseAddress(Family::V6)),
            4 => Ok(Self::SourceAddress(Family::V4)),
            5 => Ok(Self::SourceAddress(Family::V6)),
            6 => Ok(Self::ChangedAddress(Family::V4)),
            7 => Ok(Self::ChangedAddress(Family::V6)),
            8..12 => Ok(Self::ChangeRequest(value & 0x03)),
            _ => Err(InvalidAttributeType(value)),
        }
    }
}

impl Attribute {
    pub fn attribute_type(&self) -> AttributeType {
        match self {
            Self::MappedAddress(addr) => AttributeType::MappedAddress(addr.family()),
            Self::ResponseAddress(addr) => AttributeType::ResponseAddress(addr.family()),
            Self::ChangeRequest(flags) => AttributeType::ChangeRequest(*flags),
            Self::SourceAddress(addr) => AttributeType::SourceAddress(addr.family()),
            Self::ChangedAddress(addr) => AttributeType::ChangedAddress(addr.family()),
        }
    }

    fn be_attr(input: &[u8]) -> IResult<&[u8], Self> {
        if input.is_empty() {
            return Err(Err::Error(Error::new(input, ErrorKind::Eof)));
        }
        let original = input;
        let (input, ty) = be_u8(input)?;
        let ty = AttributeType::try_from(ty)
            .map_err(|_| Err::Error(Error::new(original, ErrorKind::Alt)))?;
        match ty {
            AttributeType::MappedAddress(family) => {
                map(|input| be_socket_addr(input, family), Self::MappedAddress).parse(input)
            }
            AttributeType::ResponseAddress(family) => {
                map(|input| be_socket_addr(input, family), Self::ResponseAddress).parse(input)
            }
            AttributeType::SourceAddress(family) => {
                map(|input| be_socket_addr(input, family), Self::SourceAddress).parse(input)
            }
            AttributeType::ChangedAddress(family) => {
                map(|input| be_socket_addr(input, family), Self::ChangedAddress).parse(input)
            }
            AttributeType::ChangeRequest(flags) => Ok((input, Self::ChangeRequest(flags))),
        }
    }
}

trait WriteAttribute: BufMut {
    fn put_attribute(&mut self, attribute: &Attribute);
}

impl<T: BufMut> WriteAttribute for T {
    fn put_attribute(&mut self, attribute: &Attribute) {
        self.put_u8(attribute.attribute_type().into());
        match attribute {
            Attribute::MappedAddress(addr)
            | Attribute::ResponseAddress(addr)
            | Attribute::SourceAddress(addr)
            | Attribute::ChangedAddress(addr) => self.put_socket_addr(addr),
            Attribute::ChangeRequest(_) => {}
        }
    }
}

/// The attributes of a STUN Binding Request.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct BindingRequest(Vec<Attribute>);

impl BindingRequest {
    pub fn attributes(&self) -> &[Attribute] {
        &self.0
    }

    pub fn change_ip_and_port() -> Self {
        Self(vec![Attribute::ChangeRequest(CHANGE_IP | CHANGE_PORT)])
    }

    pub fn change_port() -> Self {
        Self(vec![Attribute::ChangeRequest(CHANGE_PORT)])
    }

    pub fn add_response_address(&mut self, addr: SocketAddr) -> &mut Self {
        self.0.push(Attribute::ResponseAddress(addr));
        self
    }

    pub fn with_response_addr(addr: SocketAddr) -> Self {
        Self(vec![Attribute::ResponseAddress(addr)])
    }

    pub fn change_request(&self) -> Option<u8> {
        self.0.iter().find_map(|attribute| match attribute {
            Attribute::ChangeRequest(flags) => Some(*flags),
            _ => None,
        })
    }

    pub fn response_address(&self) -> Option<&SocketAddr> {
        self.0.iter().find_map(|attribute| match attribute {
            Attribute::ResponseAddress(addr) => Some(addr),
            _ => None,
        })
    }
}

impl GetDatagramType for BindingRequest {
    fn get_datagram_type(&self) -> OuterType {
        OuterType::V0(v0::Type::Stun(Type::BindingRequest))
    }
}

/// The attributes of a STUN Binding Response.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct BindingResponse(Vec<Attribute>);

impl BindingResponse {
    pub fn with(attributes: Vec<Attribute>) -> Self {
        Self(attributes)
    }

    pub fn attributes(&self) -> &[Attribute] {
        &self.0
    }

    pub fn map_addr(&self) -> io::Result<SocketAddr> {
        self.0
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::MappedAddress(addr) => Some(*addr),
                _ => None,
            })
            .ok_or_else(|| io::Error::other("No mapped address found in response"))
    }

    pub fn changed_addr(&self) -> io::Result<SocketAddr> {
        self.0
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::ChangedAddress(addr) => Some(*addr),
                _ => None,
            })
            .ok_or_else(|| io::Error::other("No changed address found in response"))
    }

    pub fn source_addr(&self) -> io::Result<SocketAddr> {
        self.0
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::SourceAddress(addr) => Some(*addr),
                _ => None,
            })
            .ok_or_else(|| io::Error::other("No source address found in response"))
    }
}

impl GetDatagramType for BindingResponse {
    fn get_datagram_type(&self) -> OuterType {
        OuterType::V0(v0::Type::Stun(Type::BindingResponse))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Request(BindingRequest),
    Response(BindingResponse),
}

impl GetDatagramType for Message {
    fn get_datagram_type(&self) -> OuterType {
        match self {
            Self::Request(req) => req.get_datagram_type(),
            Self::Response(resp) => resp.get_datagram_type(),
        }
    }
}

pub fn be_stun_message(ty: Type, input: &[u8]) -> IResult<&[u8], Message> {
    let (remain, attr) = many0(Attribute::be_attr).parse(input)?;
    match ty {
        Type::BindingRequest => Ok((remain, Message::Request(BindingRequest(attr)))),
        Type::BindingResponse => Ok((remain, Message::Response(BindingResponse(attr)))),
    }
}

pub trait WriteStunMessage: BufMut {
    fn put_stun_message(&mut self, message: &Message);
}

impl<T: BufMut> WriteStunMessage for T {
    fn put_stun_message(&mut self, message: &Message) {
        let attributes = match message {
            Message::Request(req) => req.attributes(),
            Message::Response(resp) => resp.attributes(),
        };
        for attribute in attributes {
            self.put_attribute(attribute);
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;

    #[test]
    fn binding_messages_report_their_outer_datagram_type() {
        assert_eq!(
            BindingRequest::default().get_datagram_type(),
            OuterType::V0(v0::Type::Stun(Type::BindingRequest))
        );
        assert_eq!(
            BindingResponse::default().get_datagram_type(),
            OuterType::V0(v0::Type::Stun(Type::BindingResponse))
        );
    }

    #[test]
    fn binding_request_message_round_trips() {
        let message = Message::Request(BindingRequest::change_ip_and_port());
        let mut bytes = BytesMut::new();
        bytes.put_stun_message(&message);

        let (remain, decoded) = be_stun_message(Type::BindingRequest, &bytes).unwrap();
        assert!(remain.is_empty());
        assert_eq!(decoded, message);
    }

    #[test]
    fn binding_response_message_round_trips() {
        let mapped = "203.0.113.1:4433".parse().unwrap();
        let message = Message::Response(BindingResponse::with(vec![Attribute::MappedAddress(
            mapped,
        )]));
        let mut bytes = BytesMut::new();
        bytes.put_stun_message(&message);

        let (remain, decoded) = be_stun_message(Type::BindingResponse, &bytes).unwrap();
        assert!(remain.is_empty());
        assert_eq!(decoded, message);
    }
}
