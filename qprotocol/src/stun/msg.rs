use std::{io, net::SocketAddr};

use bytes::BufMut;
use nom::{
    Err, IResult, Parser,
    bytes::streaming::take,
    combinator::map,
    error::{Error, ErrorKind},
    multi::many0,
    number::streaming::{be_u8, be_u16},
};
use qbase::net::{AddrFamily, Family, WriteSocketAddr, be_socket_addr};
use rand::RngExt;
use thiserror::Error;

pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_RESPONSE: u16 = 0x0101;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionId([u8; 16]);

impl AsRef<[u8]> for TransactionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TransactionId {
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut id = [0u8; 16];
        id.copy_from_slice(slice);
        TransactionId(id)
    }

    pub fn random() -> Self {
        let mut id = [0u8; 16];
        rand::rng().fill(&mut id);
        TransactionId(id)
    }
}

#[derive(Debug)]
pub enum Packet {
    Request(Request),
    Response(Response),
}

/// STUN数据包中的Attr类型：
#[derive(Debug, Clone, PartialEq)]
pub enum Attr {
    // 由服务器返回的外网映射地址
    MappedAddress(SocketAddr),
    // 客户端发起请求携带的指定响应地址
    ResponseAddress(SocketAddr),
    // 由客户端请求转发时，携带变换Ip:Port响应的指示
    ChangeRequest(u8),
    // 由服务器返回的Response消息的源地址，即服务器的地址
    SourceAddress(SocketAddr),
    // 由服务器返回的另一台的STUN服务器地址，
    // 包括不同端口，供后续参考使用
    ChangedAddress(SocketAddr),
}

#[derive(Debug)]
pub enum AttrType {
    MappedAddress(Family),
    ResponseAddress(Family),
    // 由客户端请求转发时，携带变换Ip:Port响应的指示
    ChangeRequest(u8),
    // 由服务器返回的Response消息的源地址，即服务器的地址
    SourceAddress(Family),
    // 由服务器返回的另一台的STUN服务器地址，
    // 包括不同端口，供后续参考使用
    ChangedAddress(Family),
}

#[derive(Debug, Error)]
#[error("Invalid attribute type: {0}")]
pub struct InvalidAttrType(u8);

impl From<AttrType> for u8 {
    fn from(value: AttrType) -> Self {
        match value {
            AttrType::MappedAddress(Family::V4) => 0,
            AttrType::MappedAddress(Family::V6) => 1,
            AttrType::ResponseAddress(Family::V4) => 2,
            AttrType::ResponseAddress(Family::V6) => 3,
            AttrType::SourceAddress(Family::V4) => 4,
            AttrType::SourceAddress(Family::V6) => 5,
            AttrType::ChangedAddress(Family::V4) => 6,
            AttrType::ChangedAddress(Family::V6) => 7,
            AttrType::ChangeRequest(flag_set) => 8 | flag_set,
        }
    }
}

impl TryFrom<u8> for AttrType {
    type Error = InvalidAttrType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AttrType::MappedAddress(Family::V4)),
            1 => Ok(AttrType::MappedAddress(Family::V6)),
            2 => Ok(AttrType::ResponseAddress(Family::V4)),
            3 => Ok(AttrType::ResponseAddress(Family::V6)),
            4 => Ok(AttrType::SourceAddress(Family::V4)),
            5 => Ok(AttrType::SourceAddress(Family::V6)),
            6 => Ok(AttrType::ChangedAddress(Family::V4)),
            7 => Ok(AttrType::ChangedAddress(Family::V6)),
            8..12 => Ok(AttrType::ChangeRequest(value & 0x3)),
            _ => Err(InvalidAttrType(value)),
        }
    }
}

trait WriteAttr {
    fn put_attr(&mut self, attr: &Attr);
}

impl<T: BufMut> WriteAttr for T {
    fn put_attr(&mut self, attr: &Attr) {
        let typ: u8 = attr.typ().into();
        match attr {
            Attr::MappedAddress(socket_addr) => {
                self.put_u8(typ);
                self.put_socket_addr(socket_addr);
            }
            Attr::ResponseAddress(socket_addr) => {
                self.put_u8(typ);
                self.put_socket_addr(socket_addr);
            }
            Attr::ChangeRequest(flag) => {
                self.put_u8(typ | *flag);
            }
            Attr::SourceAddress(socket_addr) => {
                self.put_u8(typ);
                self.put_socket_addr(socket_addr);
            }
            Attr::ChangedAddress(socket_addr) => {
                self.put_u8(typ);
                self.put_socket_addr(socket_addr);
            }
        };
    }
}

impl Attr {
    pub fn typ(&self) -> AttrType {
        match self {
            Attr::MappedAddress(socket_addr) => AttrType::MappedAddress(socket_addr.family()),
            Attr::ResponseAddress(socket_addr) => AttrType::ResponseAddress(socket_addr.family()),
            Attr::ChangeRequest(flag_set) => AttrType::ChangeRequest(*flag_set),
            Attr::SourceAddress(socket_addr) => AttrType::SourceAddress(socket_addr.family()),
            Attr::ChangedAddress(socket_addr) => AttrType::ChangedAddress(socket_addr.family()),
        }
    }

    fn be_attr(input: &[u8]) -> IResult<&[u8], Self> {
        if input.is_empty() {
            return Err(Err::Error(Error::new(input, ErrorKind::Eof)));
        }
        let (remain, typ) = be_u8(input)?;
        let typ: AttrType = typ
            .try_into()
            .map_err(|_| Err::Error(Error::new(input, ErrorKind::Alt)))?;
        match typ {
            AttrType::MappedAddress(family) => {
                let (remain, addr) = be_socket_addr(remain, family)?;
                Ok((remain, Attr::MappedAddress(addr)))
            }
            AttrType::ResponseAddress(family) => {
                let (remain, addr) = be_socket_addr(remain, family)?;
                Ok((remain, Attr::ResponseAddress(addr)))
            }
            AttrType::SourceAddress(family) => {
                let (remain, addr) = be_socket_addr(remain, family)?;
                Ok((remain, Attr::SourceAddress(addr)))
            }
            AttrType::ChangedAddress(family) => {
                let (remain, addr) = be_socket_addr(remain, family)?;
                Ok((remain, Attr::ChangedAddress(addr)))
            }
            AttrType::ChangeRequest(flags) => Ok((remain, Attr::ChangeRequest(flags))),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Request(Vec<Attr>);

/// 目前用到的Request只有3种，一种是空的默认Request；一种是变换IP、Port来响应；一种是只变换端口来响应
/// 可以看出，ChangeRequest属性不可能有超过一个，为满足这种限制，三种Request均直接构造出来，不再有其他
/// 可变操作函数。
impl Default for Request {
    fn default() -> Self {
        Self(Vec::with_capacity(0))
    }
}

pub(crate) trait WriteRequest {
    fn put_request(&mut self, request: &Request);
}

impl<T: BufMut> WriteRequest for T {
    fn put_request(&mut self, request: &Request) {
        for attr in &request.0 {
            self.put_attr(attr);
        }
    }
}

pub fn be_request(input: &[u8]) -> IResult<&[u8], Request> {
    many0(Attr::be_attr).map(Request).parse(input)
}

pub const CHANGE_PORT: u8 = 0x01;
pub const CHANGE_IP: u8 = 0x02;

impl Request {
    pub fn change_ip_and_port() -> Self {
        let mut request = Request::default();
        request.0.push(Attr::ChangeRequest(CHANGE_IP | CHANGE_PORT));
        request
    }

    pub fn change_port() -> Self {
        let mut request = Request::default();
        request.0.push(Attr::ChangeRequest(CHANGE_PORT));
        request
    }

    pub fn add_response_address(&mut self, addr: SocketAddr) -> &mut Self {
        self.0.push(Attr::ResponseAddress(addr));
        self
    }

    // 仅发送响应地址，移除ChangeRequest属性
    pub fn with_response_addr(addr: SocketAddr) -> Self {
        Request(vec![Attr::ResponseAddress(addr)])
    }

    pub fn change_request(&self) -> Option<u8> {
        for attr in &self.0 {
            if let Attr::ChangeRequest(flags) = attr {
                return Some(*flags);
            }
        }
        None
    }

    pub fn response_address(&self) -> Option<&SocketAddr> {
        for attr in &self.0 {
            if let Attr::ResponseAddress(addr) = attr {
                return Some(addr);
            }
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Response(pub Vec<Attr>);

pub(crate) trait WriteResponse {
    fn put_response(&mut self, response: &Response);
}

impl<T: BufMut> WriteResponse for T {
    fn put_response(&mut self, response: &Response) {
        for attr in &response.0 {
            self.put_attr(attr);
        }
    }
}

pub fn be_response(input: &[u8]) -> IResult<&[u8], Response> {
    many0(Attr::be_attr).map(Response).parse(input)
}

impl Response {
    pub fn with(attrs: Vec<Attr>) -> Self {
        Response(attrs)
    }

    pub fn map_addr(&self) -> io::Result<SocketAddr> {
        for attr in &self.0 {
            if let Attr::MappedAddress(addr) = attr {
                return Ok(*addr);
            };
        }
        Err(io::Error::other("No mapped address found in response"))
    }

    pub fn changed_addr(&self) -> io::Result<SocketAddr> {
        for attr in &self.0 {
            if let Attr::ChangedAddress(addr) = attr {
                return Ok(*addr);
            };
        }
        Err(io::Error::other("No changed address found in response"))
    }

    pub fn source_addr(&self) -> io::Result<SocketAddr> {
        for attr in &self.0 {
            if let Attr::SourceAddress(addr) = attr {
                return Ok(*addr);
            };
        }
        Err(io::Error::other("No source address found in response"))
    }
}

pub fn be_packet(input: &[u8]) -> IResult<&[u8], (TransactionId, Packet)> {
    let (remain, typ) = be_u16(input)?;
    let (remain, txid) = take(16usize).parse(remain)?;
    let (remain, packet) = match typ {
        BINDING_REQUEST => map(be_request, Packet::Request).parse(remain)?,
        BINDING_RESPONSE => map(be_response, Packet::Response).parse(remain)?,
        _ => return Err(Err::Error(Error::new(input, ErrorKind::Alt))),
    };
    Ok((remain, (TransactionId::from_slice(txid), packet)))
}

pub trait WritePacket {
    fn put_packet(&mut self, txid: &TransactionId, packet: &Packet);
}

impl<T: BufMut> WritePacket for T {
    fn put_packet(&mut self, txid: &TransactionId, packet: &Packet) {
        match packet {
            Packet::Request(request) => {
                self.put_u16(BINDING_REQUEST);
                self.put_slice(txid.as_ref());
                self.put_request(request);
            }
            Packet::Response(response) => {
                self.put_u16(BINDING_RESPONSE);
                self.put_slice(txid.as_ref());
                self.put_response(response);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_deserialize() {
        assert_eq!(
            Attr::be_attr(&[4, 78, 34, 127, 0, 0, 1][..]),
            Ok((
                &[][..],
                Attr::SourceAddress("127.0.0.1:20002".parse().unwrap())
            ))
        );

        assert_eq!(
            Attr::be_attr(&[6, 78, 34, 127, 0, 0, 1][..]),
            Ok((
                &[][..],
                Attr::ChangedAddress("127.0.0.1:20002".parse().unwrap())
            ))
        );
        assert_eq!(
            Attr::be_attr(&[0, 48, 57, 127, 0, 0, 1][..]),
            Ok((
                &[][..],
                Attr::MappedAddress("127.0.0.1:12345".parse().unwrap())
            ))
        )
    }

    #[test]
    fn request_serialize() {
        let buf = [
            4, 78, 34, 127, 0, 0, 1, 0, 48, 57, 127, 0, 0, 1, 6, 78, 34, 127, 0, 0, 1,
        ];
        let (remain, response) = be_response(&buf).unwrap();
        assert_eq!(remain.len(), 0);
        assert_eq!(
            response,
            Response(vec![
                Attr::SourceAddress("127.0.0.1:20002".parse().unwrap()),
                Attr::MappedAddress("127.0.0.1:12345".parse().unwrap()),
                Attr::ChangedAddress("127.0.0.1:20002".parse().unwrap())
            ])
        );
    }
}
