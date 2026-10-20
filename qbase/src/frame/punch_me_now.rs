use std::net::SocketAddr;

use derive_more::Deref;

use super::{
    EncodeSize, GetFrameType,
    io::{WriteFrame, WriteFrameType},
};
use crate::{
    net::{AddrFamily, Family, NatType, be_socket_addr},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// PUNCH_ME_NOW Frame
///
///```text
/// PUNCH_ME_NOW Frame {
///     Type (i) = 0x3d7e92,0x3d7e93
///     Local Sequence Number (i),
///     Remote Sequence Number (i),
///     [ IPv4 (32) ],
///     [ IPv6 (128) ],
///     Port (16),
///     Tire (i),
///     Nat type (i),
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deref)]
pub struct PunchMeNowFrame {
    local_seq: VarInt,
    remote_seq: VarInt,
    #[deref]
    address: SocketAddr,
    tire: VarInt,
    nat_type: NatType,
}

pub(crate) fn be_punch_me_now_frame(
    family: Family,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], PunchMeNowFrame> {
    move |input| {
        let (remain, local_seq) = be_varint(input)?;
        let (remain, remote_seq) = be_varint(remain)?;
        let (remain, address) = be_socket_addr(remain, family)?;
        let (remain, tire) = be_varint(remain)?;
        let (remain, nat_type) = be_varint(remain)?;
        let nat_type = NatType::try_from(nat_type).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(
                remain,
                nom::error::ErrorKind::Verify,
            ))
        })?;
        Ok((
            remain,
            PunchMeNowFrame {
                local_seq,
                remote_seq,
                address,
                tire,
                nat_type,
            },
        ))
    }
}

impl GetFrameType for PunchMeNowFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::PunchMeNow(self.address.family())
    }
}

impl EncodeSize for PunchMeNowFrame {
    fn max_encoding_size(&self) -> usize {
        4 + 8 + 8 + self.address.max_encoding_size() + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        VarInt::from(self.frame_type()).encoding_size()
            + self.local_seq.encoding_size()
            + self.remote_seq.encoding_size()
            + self.address.encoding_size()
            + self.tire.encoding_size()
            + VarInt::from(self.nat_type).encoding_size()
    }
}

impl PunchMeNowFrame {
    pub fn new(
        local_seq: u32,
        remote_seq: u32,
        address: SocketAddr,
        tire: u32,
        nat_type: NatType,
    ) -> Self {
        Self {
            local_seq: VarInt::from_u32(local_seq),
            remote_seq: VarInt::from_u32(remote_seq),
            address,
            tire: VarInt::from_u32(tire),
            nat_type,
        }
    }

    pub fn local_seq(&self) -> u32 {
        self.local_seq.into_u64() as u32
    }

    pub fn remote_seq(&self) -> u32 {
        self.remote_seq.into_u64() as u32
    }

    pub fn nat_type(&self) -> NatType {
        self.nat_type
    }

    pub fn set_addr(&mut self, addr: SocketAddr) {
        self.address = addr;
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn tire(&self) -> u32 {
        self.tire.into_u64() as u32
    }
}

impl<T: bytes::BufMut> WriteFrame<PunchMeNowFrame> for T {
    fn put_frame(&mut self, frame: &PunchMeNowFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_varint(&frame.local_seq);
        self.put_varint(&frame.remote_seq);
        self.put_u16(frame.address.port());
        match frame.address.ip() {
            std::net::IpAddr::V4(ipv4) => self.put_slice(&ipv4.octets()),
            std::net::IpAddr::V6(ipv6) => self.put_slice(&ipv6.octets()),
        }
        self.put_varint(&frame.tire);
        self.put_varint(&VarInt::from(frame.nat_type));
    }
}
