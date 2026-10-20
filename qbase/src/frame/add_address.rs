use std::net::{IpAddr, SocketAddr};

use derive_more::Deref;

use super::{
    EncodeSize, GetFrameType,
    io::{WriteFrame, WriteFrameType},
};
use crate::{
    net::{AddrFamily, Family, NatType, WriteSocketAddr, be_socket_addr},
    varint::{VarInt, WriteVarInt, be_varint},
};

// ADD_ADDRESS Frame {
//     Type (i) = 0x3d7e90..0x3d7e91,
//     Sequence Number (i),
//     [ IPv4 (32) ],
//     [ IPv6 (128) ],
//     Port (16),
//     Tire (i),
//     NAT Type (i),
// }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deref)]
pub struct AddAddressFrame {
    #[deref]
    address: SocketAddr,
    seq_num: VarInt,
    tire: VarInt,
    nat_type: NatType,
}

pub(crate) fn be_add_address_frame(
    family: Family,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], AddAddressFrame> {
    move |input| {
        let (remain, seq_num) = be_varint(input)?;
        let (remain, addr) = be_socket_addr(remain, family)?;
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
            AddAddressFrame {
                seq_num,
                address: addr,
                tire,
                nat_type,
            },
        ))
    }
}

impl GetFrameType for AddAddressFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::AddAddress(self.address.family())
    }
}

impl EncodeSize for AddAddressFrame {
    fn max_encoding_size(&self) -> usize {
        4 // frame type
            + 8 // seq_num
            + 2  // port
            + 16 // ipv6 IP
            + 8  // tire
            + 8 // nat_type
    }

    fn encoding_size(&self) -> usize {
        let addr_size = match self.address.ip() {
            IpAddr::V4(_) => 2 + 4,
            IpAddr::V6(_) => 2 + 16,
        };
        VarInt::from(self.frame_type()).encoding_size()
            + self.seq_num.encoding_size()
            + addr_size
            + self.tire.encoding_size()
            + VarInt::from(self.nat_type).encoding_size()
    }
}

impl AddAddressFrame {
    pub fn new(seq_num: u32, address: SocketAddr, tire: u32, nat_type: NatType) -> Self {
        Self {
            seq_num: VarInt::from_u32(seq_num),
            address,
            tire: VarInt::from_u32(tire),
            nat_type,
        }
    }

    pub fn seq_num(&self) -> u32 {
        self.seq_num.into_u64() as u32
    }

    pub fn tire(&self) -> u32 {
        self.tire.into_u64() as u32
    }

    pub fn nat_type(&self) -> NatType {
        self.nat_type
    }
}

impl<T: bytes::BufMut> WriteFrame<AddAddressFrame> for T {
    fn put_frame(&mut self, frame: &AddAddressFrame) {
        self.put_frame_type(frame.frame_type());
        self.put_varint(&frame.seq_num);
        self.put_socket_addr(&frame.address);
        self.put_varint(&frame.tire);
        self.put_varint(&VarInt::from(frame.nat_type));
    }
}
