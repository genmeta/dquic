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

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use super::{
        Header, LongHeaderBuilder,
        io::be_header,
        long::{Handshake, Initial, Retry, VersionNegotiation, ZeroRtt},
    };
    use crate::{
        cid::ConnectionId,
        packet::{
            GetDcid, OneRttHeader, SpinBit,
            header::{GetScid, io::WriteHeader},
            r#type::{
                Type,
                long::{self, Ver1},
                short::OneRtt,
            },
        },
    };

    #[test]
    fn test_read_header() {
        // VersionNegotiation Header
        let buf = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02];
        let (remain, vn_long_header) =
            be_header(Type::Long(long::Type::VersionNegotiation), 0, &buf).unwrap();
        assert_eq!(remain.len(), 0);
        match vn_long_header {
            Header::VN(vn) => {
                assert_eq!(vn.dcid(), &ConnectionId::default());
                assert_eq!(vn.scid(), &ConnectionId::default());
                assert_eq!(vn.versions(), &vec![0x01, 0x02]);
            }
            _ => panic!("unexpected header type"),
        }

        // Retry Header
        let buf = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let (remain, retry_long_header) =
            be_header(Type::Long(long::Type::V1(Ver1::RETRY)), 0, &buf).unwrap();
        assert_eq!(remain.len(), 0);
        match retry_long_header {
            Header::Retry(retry) => {
                assert_eq!(retry.dcid(), &ConnectionId::default());
                assert_eq!(retry.scid(), &ConnectionId::default());
                assert_eq!(retry.token().deref(), &[0x00, 0x00, 0x00]);
                assert_eq!(
                    retry.integrity(),
                    &[
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                        0x0c, 0x0d, 0x0e, 0x0f
                    ]
                );
            }
            _ => panic!("unexpected header type"),
        }

        // Retry Header with invalid length
        let buf = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f,
        ];
        match be_header(Type::Long(long::Type::V1(Ver1::RETRY)), 0, &buf) {
            Err(e) => assert_eq!(e, nom::Err::Incomplete(nom::Needed::new(16))),
            _ => panic!("unexpected result"),
        }

        // Initial Header
        let buf = vec![0x00, 0x00, 0x03, 0x01, 0x02, 0x03];
        let (remain, initial_long_header) =
            be_header(Type::Long(long::Type::V1(Ver1::INITIAL)), 0, &buf).unwrap();
        assert_eq!(remain.len(), 0);
        match initial_long_header {
            Header::Initial(initial) => {
                assert_eq!(initial.dcid(), &ConnectionId::default());
                assert_eq!(initial.scid(), &ConnectionId::default());
                assert_eq!(initial.token().deref(), [0x01, 0x02, 0x03,]);
            }
            _ => panic!("unexpected header type"),
        }

        // ZeroRTT Header
        let buf = vec![0x00, 0x00];
        let (remain, zero_rtt_long_header) =
            be_header(Type::Long(long::Type::V1(Ver1::ZERO_RTT)), 0, &buf).unwrap();
        assert_eq!(remain.len(), 0);
        match zero_rtt_long_header {
            Header::ZeroRtt(zero_rtt) => {
                assert_eq!(zero_rtt.dcid(), &ConnectionId::default());
                assert_eq!(zero_rtt.scid(), &ConnectionId::default());
            }
            _ => panic!("unexpected header type"),
        }

        // Handshake Header
        let buf = vec![0x00, 0x00];
        let (remain, handshake_long_header) =
            be_header(Type::Long(long::Type::V1(Ver1::HANDSHAKE)), 0, &buf).unwrap();
        assert_eq!(remain.len(), 0);
        match handshake_long_header {
            Header::Handshake(handshake) => {
                assert_eq!(handshake.dcid(), &ConnectionId::default());
                assert_eq!(handshake.scid(), &ConnectionId::default());
            }
            _ => panic!("unexpected header type"),
        }

        // OneRtt Header
        let buf = vec![];
        let (remain, one_rtt_header) =
            be_header(Type::Short(OneRtt(SpinBit::One)), 0, &buf).unwrap();
        assert_eq!(remain.len(), 0);
        match one_rtt_header {
            Header::OneRtt(one_rtt) => {
                assert_eq!(
                    one_rtt,
                    OneRttHeader::new(SpinBit::One, ConnectionId::default())
                );
            }
            _ => panic!("unexpected header type"),
        }
    }

    #[test]
    fn test_write_header() {
        // VersionNegotiation Header
        let mut buf = vec![];
        let vn_long_header = Header::VN(
            LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default())
                .wrap(VersionNegotiation::new(vec![0x01, 0x02])),
        );
        buf.put_header(&vn_long_header);
        assert_eq!(
            buf,
            [
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x02
            ]
        );

        // Retry Header
        let mut buf = vec![];
        let retry_long_header = Header::Retry(
            LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default()).wrap(
                Retry::new(
                    &[0x00, 0x00, 0x00],
                    &[
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                        0x0c, 0x0d, 0x0e, 0x0f,
                    ],
                ),
            ),
        );
        buf.put_header(&retry_long_header);
        assert_eq!(
            buf,
            [
                0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            ]
        );

        // Initial Header
        let mut buf = vec![];
        let initial_header = Header::Initial(
            LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default())
                .wrap(Initial::with_token(vec![0x01, 0x02, 0x03])),
        );
        buf.put_header(&initial_header);
        assert_eq!(
            buf,
            [
                0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03
            ]
        );

        // ZeroRtt Header
        let mut buf = vec![];
        let zero_rtt_header = Header::ZeroRtt(
            LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default())
                .wrap(ZeroRtt),
        );
        buf.put_header(&zero_rtt_header);
        assert_eq!(buf, [0xd0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);

        // Handshake Header
        let mut buf = vec![];
        let handshake_header = Header::Handshake(
            LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default())
                .wrap(Handshake),
        );
        buf.put_header(&handshake_header);
        assert_eq!(buf, [0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);

        // OneRtt Header with SpinBit::On
        let mut buf = vec![];
        let one_rtt_header =
            Header::OneRtt(OneRttHeader::new(SpinBit::One, ConnectionId::default()));
        buf.put_header(&one_rtt_header);
        assert_eq!(buf, [0x60]);

        // OneRtt Header with SpinBit::Off
        let mut buf = vec![];
        let one_rtt_header =
            Header::OneRtt(OneRttHeader::new(SpinBit::Zero, ConnectionId::default()));
        buf.put_header(&one_rtt_header);
        assert_eq!(buf, [0x40]);
    }
}
