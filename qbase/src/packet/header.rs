use enum_dispatch::enum_dispatch;

use crate::cid::ConnectionId;

/// All structure definitions related to long headers.
pub mod long;
/// All structure definitions related to short headers.
pub mod short;

#[doc(hidden)]
pub use long::{
    DataHeader, HandshakeHeader, InitialHeader, LongHeader, RetryHeader, VersionNegotiationHeader,
    ZeroRttHeader,
    io::{LongHeaderBuilder, WriteSpecific},
};
#[doc(hidden)]
pub use short::OneRttHeader;

use super::r#type::{
    Type,
    long::{Type as LongType, Version, v1},
    short::OneRtt,
};

/// Each packet has its type. For more detailed definition on packet types, see [`Type`].
#[enum_dispatch]
pub trait GetType {
    /// Get the packet type.
    fn get_type(&self) -> Type;
}

/// When encoding a packet for sending, we need to know the size of the packet encoding,
/// so this trait needs to be implemented.
///
/// However, the length field of the packet payload is variable-length encoded and
/// requires special encoding, which is not considered here.
#[enum_dispatch]
pub trait HeaderSize {
    /// Returns the length of the encoded packet header.
    fn size(&self) -> usize {
        0
    }

    fn length_encoding(&self) -> usize {
        0
    }
}

/// Get the Destination Connection ID (DCID) of the packet, each packet has a DCID.
#[enum_dispatch]
pub trait GetDcid {
    /// Get the Destination Connection ID (DCID) of the packet.
    fn dcid(&self) -> &ConnectionId;
}

/// Get the Source Connection ID (SCID) of the packet, only long packets have SCID.
#[enum_dispatch]
pub trait GetScid {
    /// Get the Source Connection ID (SCID) of the packet.
    fn scid(&self) -> &ConnectionId;
}

/// The sum type of all packet headers.
#[derive(Debug, Clone)]
#[enum_dispatch(GetDcid)]
pub enum Header {
    VN(long::VersionNegotiationHeader),
    Retry(long::RetryHeader),
    Initial(long::InitialHeader),
    ZeroRtt(long::ZeroRttHeader),
    Handshake(long::HandshakeHeader),
    OneRtt(short::OneRttHeader),
}

/// The io module for packet headers, including
/// how to parse the header from a UDP packet and
/// how to write the header into a UDP packet.
pub mod io {
    use super::{
        Header, LongHeader, OneRttHeader,
        long::{Handshake, Initial, Retry, VersionNegotiation, ZeroRtt, io::LongHeaderBuilder},
    };
    use crate::{
        cid::be_connection_id,
        packet::{
            header::short::io::be_one_rtt_header,
            r#type::{Type, short::OneRtt},
        },
    };

    /// Parse a packet header from the input buffer,
    /// returns [`Header`] if succeed,
    /// [nom](https://docs.rs/nom/latest/nom/) parser style.
    pub fn be_header(
        packet_type: Type,
        dcid_len: usize,
        input: &[u8],
    ) -> nom::IResult<&[u8], Header> {
        match packet_type {
            Type::Long(long_ty) => {
                let (remain, dcid) = be_connection_id(input)?;
                let (remain, scid) = be_connection_id(remain)?;
                let builder = LongHeaderBuilder { dcid, scid };
                builder.parse(long_ty, remain)
            }
            Type::Short(OneRtt(spin)) => {
                let (remain, one_rtt) = be_one_rtt_header(spin, dcid_len, input)?;
                Ok((remain, Header::OneRtt(one_rtt)))
            }
        }
    }

    /// A [`bytes::BufMut`] extension trait for writing packet headers.
    ///
    /// When sending packets, it is necessary to organize the data and write
    /// various types of QUIC packets into an UDP datagram. This trait will
    /// be used to write the packet header.
    pub trait WriteHeader<H>: bytes::BufMut {
        /// Write a packet header to the buffer.
        fn put_header(&mut self, header: &H);
    }

    impl<T> WriteHeader<Header> for T
    where
        T: bytes::BufMut
            + WriteHeader<LongHeader<VersionNegotiation>>
            + WriteHeader<LongHeader<Retry>>
            + WriteHeader<LongHeader<Initial>>
            + WriteHeader<LongHeader<ZeroRtt>>
            + WriteHeader<LongHeader<Handshake>>
            + WriteHeader<OneRttHeader>,
    {
        fn put_header(&mut self, header: &Header) {
            match header {
                Header::VN(vn) => self.put_header(vn),
                Header::Retry(retry) => self.put_header(retry),
                Header::Initial(initial) => self.put_header(initial),
                Header::ZeroRtt(zero_rtt) => self.put_header(zero_rtt),
                Header::Handshake(handshake) => self.put_header(handshake),
                Header::OneRtt(one_rtt) => self.put_header(one_rtt),
            }
        }
    }
}
