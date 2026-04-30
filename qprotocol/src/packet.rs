use bytes::BufMut;
use qbase::net::{
    Family,
    addr::{EndpointAddr, WriteEndpointAddr, be_endpoint_addr},
    route::Pathway,
};

const STUN_HEADER_MASK: u8 = 0b1111_1110;
const STUN_HEADER_BITS: u8 = 0b1100_0010;

const FORWARD_HEADER_MASK: u8 = 0b1110_0000;
const FORWARD_VERSION_MASK: u8 = 0b1111_0000;
const FORWARD_HEADER_BITS: u8 = 0b0110_0000;
const FORWARD_BIT: u8 = 0b0000_1000;
const FORWARD_FAMILY_BIT: u8 = 0b0000_0100;
const FORWARD_SRC_TYPE_BIT: u8 = 0b0000_0010;
const FORWARD_DST_TYPE_BIT: u8 = 0b0000_0001;

#[derive(PartialEq, Eq, Debug)]
pub enum HeaderType {
    Stun(u8),    // 最后 bit
    Forward(u8), // 最后 5bit
}

// Stun Packet {
//     Header Form (1) = 1,
//     Fixed Bit (1) = 1,
//     Stun Hdr (6), // Request 0b000010 #Response 0b000011
//     Version (32) = 0,
//     DDIL(8) = 0, // 伪装0长度的目标连接ID
//     SDIL(8) = 0, // 伪装0长度的源连接ID
//     Ver(16), // 2个字节，表示我们自定义的版本号，方便未来升级
//     ... Stun payload
//   }
#[derive(Clone, Copy)]
pub struct StunHeader {
    version: u16,
}

impl StunHeader {
    pub fn new(version: u16) -> Self {
        Self { version }
    }

    pub fn encoding_size() -> usize {
        1 + 4 + 4
    }
}

pub fn be_stun_header(input: &[u8]) -> nom::IResult<&[u8], StunHeader> {
    let (remain, version) = nom::number::streaming::be_u16(input)?;
    Ok((remain, StunHeader { version }))
}

pub trait WriteStunHeader {
    fn put_stun_header(&mut self, stun_header: &StunHeader);
}

impl<T: BufMut> WriteStunHeader for T {
    fn put_stun_header(&mut self, stun_header: &StunHeader) {
        self.put_u8(STUN_HEADER_BITS);
        self.put_u32(0);
        self.put_u8(0);
        self.put_u8(0);
        self.put_u16(stun_header.version);
    }
}

// Forward Packet {
//     Header Form (1) = 0,
//     Fixed Bit (1) = 1,
//     Spin Bit (1) = 1, // 1表示带有转发包头
//     Remain (5), // 使其等于真正QUIC包第一字节的后5bit，飘忽不定，伪装够深
//     Version (4),
//     Forward (1) = 1,
//     Family (1),  // 0表示IPv4，1表示IPv6
//     Src type(1), // 0表示直连，1表示带agent
//     Dst type(1), // 0表示直连，1表示带agent
//     Src endpoint, // 根据src type，是Endpoint::Agent还是Direct
//     Dst endpoint, // 根据dst type，是Endpoint::Agent还是Direct
//     ... Real Quic Packet
//   }
#[derive(Debug, Clone, Copy)]
pub struct ForwardHeader {
    remian: u8,  // 后 5bits
    version: u8, // 前 4bits
    pathway: Pathway,
}

impl ForwardHeader {
    pub fn encoding_size(pathway: &Pathway) -> usize {
        if matches!(pathway.remote(), EndpointAddr::Direct { .. }) {
            return 0;
        }
        1 + 1 + pathway.local().encoding_size() + pathway.remote().encoding_size()
    }

    pub fn pathway(&self) -> Pathway {
        self.pathway
    }

    pub fn new(version: u8, pathway: &Pathway, buffer: &[u8]) -> Self {
        let remian = buffer[0] & 0b0001_1111;
        Self {
            remian,
            version,
            pathway: *pathway,
        }
    }
}

pub trait WriteForwardHeader {
    fn put_forward_header(&mut self, forward_header: &ForwardHeader);
}

impl<T: BufMut> WriteForwardHeader for T {
    fn put_forward_header(&mut self, forward_header: &ForwardHeader) {
        self.put_u8(FORWARD_HEADER_BITS | forward_header.remian);
        let mut flag = (forward_header.version << 4) | FORWARD_BIT;

        if forward_header.pathway.local().ip().is_ipv6() {
            flag |= FORWARD_FAMILY_BIT;
        }
        if matches!(forward_header.pathway.local(), EndpointAddr::Agent { .. }) {
            flag |= FORWARD_SRC_TYPE_BIT;
        }
        if matches!(forward_header.pathway.remote(), EndpointAddr::Agent { .. }) {
            flag |= FORWARD_DST_TYPE_BIT;
        }
        self.put_u8(flag);
        self.put_endpoint_addr(forward_header.pathway.local());
        self.put_endpoint_addr(forward_header.pathway.remote());
    }
}

pub fn be_forward_header(input: &[u8]) -> nom::IResult<&[u8], ForwardHeader> {
    let (remain, first) = nom::number::streaming::be_u8(input)?;
    let version = (first & FORWARD_VERSION_MASK) >> 4;
    let flag = first & !FORWARD_VERSION_MASK;
    let family = match flag & FORWARD_FAMILY_BIT {
        0 => Family::V4,
        _ => Family::V6,
    };

    let src_ep_typ = flag & FORWARD_SRC_TYPE_BIT;
    let dst_ep_typ = flag & FORWARD_DST_TYPE_BIT;
    let (remain, src) = be_endpoint_addr(remain, src_ep_typ, family)?;
    let (remain, dst) = be_endpoint_addr(remain, dst_ep_typ, family)?;
    let pathway = Pathway::new(src, dst);
    Ok((
        remain,
        ForwardHeader {
            remian: first,
            version,
            pathway,
        },
    ))
}

#[derive(Clone, Copy)]
pub enum Header {
    Stun(StunHeader),
    Forward(ForwardHeader),
}

pub fn be_header_type(input: &[u8]) -> nom::IResult<&[u8], HeaderType> {
    let (remain, first) = nom::number::streaming::be_u8(input)?;
    if first & STUN_HEADER_MASK == STUN_HEADER_BITS {
        let (remain, version) = nom::number::streaming::be_u32(remain)?;
        if version == 0 {
            let (remain, _) = nom::number::streaming::be_u8(remain)?;
            let (remain, _) = nom::number::streaming::be_u8(remain)?;
            return Ok((remain, HeaderType::Stun(first & 1)));
        }
    } else if first & FORWARD_HEADER_MASK == FORWARD_HEADER_BITS {
        return Ok((remain, HeaderType::Forward(first & 0b0001_1111)));
    }
    Err(nom::Err::Error(nom::error::make_error(
        input,
        nom::error::ErrorKind::Alt,
    )))
}

pub fn be_header(input: &[u8]) -> nom::IResult<&[u8], Header> {
    let (remain, ty) = be_header_type(input)?;
    match ty {
        HeaderType::Stun(_ty) => {
            let (remain, stun_hdr) = be_stun_header(remain)?;
            Ok((remain, Header::Stun(stun_hdr)))
        }
        HeaderType::Forward(_ty) => {
            let (remain, forward_hdr) = be_forward_header(remain)?;
            Ok((remain, Header::Forward(forward_hdr)))
        }
    }
}

pub trait WriteHeader {
    fn put_header(&mut self, header: &Header);
}

impl<T: BufMut> WriteHeader for T {
    fn put_header(&mut self, header: &Header) {
        match header {
            Header::Stun(stun_header) => {
                self.put_stun_header(stun_header);
            }
            Header::Forward(forward_header) => {
                self.put_forward_header(forward_header);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;

    #[test]
    fn test_stun_header() {
        let stun_hdr = StunHeader::new(0);
        let mut buf = BytesMut::with_capacity(StunHeader::encoding_size());
        buf.put_stun_header(&stun_hdr);
        let (remain, hdr) = be_header_type(&buf[..]).unwrap();
        assert_eq!(hdr, HeaderType::Stun(0));
        let (remain, stun_hdr) = be_stun_header(remain).unwrap();
        assert_eq!(stun_hdr.version, 0);
        assert_eq!(remain.len(), 0)
    }
}
