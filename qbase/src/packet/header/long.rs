use derive_more::{Deref, DerefMut};

use super::*;
use crate::{cid::ConnectionId, varint::VarInt};

/// The long header structure, whose specific contents are determined by the
/// concrete packet type, including VN/Retry/Initial/0Rtt/Handshake packet.
///
/// Long headers are used for packets that are sent prior to the establishment
/// of 1-RTT keys. Once 1-RTT keys are available, a sender switches to sending
/// packets using the short header.
///
/// ```text
/// +---------------+-------------+------+--------------+------+--------------+----------+
/// |1|1|X X 0 0 0 0| Version(32) | DCIL | DCID(0..160) | SCIL | SCID(0..160) | Specific |
/// +---+---+---+---+-------------+------+--------------+------+--------------+----------+
///     |<->|<->|<->|
///       |   |   |
///       |   |   +---> packet number length
///       |   +---> reserved bits, must be zero
///       +---> represent specific long packet type
/// ```
///
/// See [Long Header Packet Format](https://www.rfc-editor.org/rfc/rfc9000.html#name-long-header-packets)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Default, Clone, Deref, DerefMut)]
pub struct LongHeader<T> {
    dcid: ConnectionId,
    scid: ConnectionId,
    #[deref]
    #[deref_mut]
    specific: T,
}

impl<T> super::GetDcid for LongHeader<T> {
    fn dcid(&self) -> &ConnectionId {
        &self.dcid
    }
}

impl<T> super::GetScid for LongHeader<T> {
    fn scid(&self) -> &ConnectionId {
        &self.scid
    }
}

// The following is the header definition, which may exist in all future versions
// of QUIC, so it is placed in this file without distinguishing versions.

/// The specific contents of the version negotiation packet, which includes all the
/// version numbers supported by the server.
///
/// When the server receives an initial packet or 0-RTT packet with an unsupported
/// version number, it will respond with a version negotiation packet that contains
/// all the version numbers supported by the server, each version being 32 bits.
#[derive(Debug, Default, Clone)]
pub struct VersionNegotiation {
    versions: Vec<u32>,
}

impl VersionNegotiation {
    /// Create a new VersionNegotiation packet from the version numbers.
    pub fn new(versions: Vec<u32>) -> Self {
        VersionNegotiation { versions }
    }

    /// Get the version numbers supported by the server.
    pub fn versions(&self) -> &Vec<u32> {
        &self.versions
    }
}

/// The specific contents of the retry packet, which includes a retry token and a
/// 16-byte integrity checksum codes.
///
/// After accepting the client's new connection, the server may return a retry packet
/// due to load balancing strategies or simply for address verification,
/// requiring the client to reconnect to the new address with the token.
#[derive(Debug, Default, Clone)]
pub struct Retry {
    token: Vec<u8>,
    integrity: [u8; 16],
}

impl Retry {
    /// Create a new Retry packet from the token and integrity value.
    ///
    /// The token is required to be carried by the Initial packet when the client
    /// reconnects in the future and will be used by the server for address verification.
    pub fn new(token: &[u8], integrity: &[u8]) -> Self {
        let mut retry = Retry {
            token: Vec::from(token),
            integrity: [0; 16],
        };
        retry.integrity.copy_from_slice(integrity);
        retry
    }

    /// Get the retry token.
    pub fn token(&self) -> &Vec<u8> {
        &self.token
    }

    /// Get the integrity value.
    pub fn integrity(&self) -> &[u8; 16] {
        &self.integrity
    }
}

/// The specific contents of the initial packet, which just includes a token.
///
/// The token comes from the Retry packet responded by the server, or it is issued to
/// the client by the server through the NewToken frame in past QUIC connections.
/// After the server receives this token, it will be used for address verification.
/// If the client connects to the server for the first time, the token is empty.
#[derive(Debug, Default, Clone)]
pub struct Initial {
    token: Vec<u8>,
}

impl Initial {
    /// Create a new Initial packet from the token.
    pub fn with_token(token: Vec<u8>) -> Self {
        Initial { token }
    }

    /// Create a new Initial packet from the token slice.
    pub fn from_slice(token: &[u8]) -> Self {
        Initial {
            token: Vec::from(token),
        }
    }

    /// Get the token.
    pub fn token(&self) -> &Vec<u8> {
        &self.token
    }
}

/// The specific contents of the 0-RTT packet, which is empty.
#[derive(Debug, Default, Clone)]
pub struct ZeroRtt;

/// The specific contents of the handshake packet, which is empty.
#[derive(Debug, Default, Clone)]
pub struct Handshake;

impl HeaderSize for Initial {
    fn size(&self) -> usize {
        VarInt::try_from(self.token.len())
            .expect("token length can not be more than 2^62")
            .encoding_size()
            + self.token.len()
    }
}

impl HeaderSize for ZeroRtt {}
impl HeaderSize for Handshake {}

/// Version negotiation packet, which is a long header packet.
///
/// See [version negotiation packet](https://www.rfc-editor.org/rfc/rfc9000.html#name-version-negotiation-packet)
/// in [RFC9000](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
pub type VersionNegotiationHeader = LongHeader<VersionNegotiation>;

/// Retry packet, which is a long header packet.
///
/// See [retry packet](https://www.rfc-editor.org/rfc/rfc9000.html#name-retry-packet)
/// in [RFC9000](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
pub type RetryHeader = LongHeader<Retry>;

/// Initial packet header, which is a long header packet.
///
/// See [initial packet](https://www.rfc-editor.org/rfc/rfc9000.html#name-initial-packet)
/// in [RFC9000](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
pub type InitialHeader = LongHeader<Initial>;

/// Handshake packet header, which is a long header packet.
///
/// See [handshake packet](https://www.rfc-editor.org/rfc/rfc9000.html#name-handshake-packet)
/// in [RFC9000](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
pub type HandshakeHeader = LongHeader<Handshake>;

/// 0-RTT packet header, which is a long header packet.
///
/// See [0-RTT packet](https://www.rfc-editor.org/rfc/rfc9000.html#name-0-rtt-packet)
/// in [RFC9000](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
pub type ZeroRttHeader = LongHeader<ZeroRtt>;

impl<S: HeaderSize> HeaderSize for LongHeader<S> {
    fn size(&self) -> usize {
        1 + 4 +
        1 + self.dcid.len()       // dcid长度最多20字节，长度编码只占1字节，加上cid本身的长度
            + 1 + self.scid.len() // scid一样
            + self.specific.size()
    }

    fn length_encoding(&self) -> usize {
        2 // 长包头都带有length字段，统一2字节，能表达1～16KB的长度的包
    }
}

macro_rules! bind_type {
    ($($type:ty => $value:expr),*) => {
        $(
            impl GetType for $type {
                fn get_type(&self) -> Type {
                    $value
                }
            }
        )*
    };
}

bind_type!(
    VersionNegotiationHeader => Type::Long(LongType::VersionNegotiation),
    RetryHeader => Type::Long(LongType::V1(Version::<1, _>(v1::Type::Retry))),
    InitialHeader => Type::Long(LongType::V1(Version::<1, _>(v1::Type::Initial))),
    ZeroRttHeader => Type::Long(LongType::V1(Version::<1, _>(v1::Type::ZeroRtt))),
    HandshakeHeader => Type::Long(LongType::V1(Version::<1, _>(v1::Type::Handshake)))
);

/// The sum type of long packets that carry data,
/// including Initial, ZeroRtt, and Handshake packets.
#[derive(Debug, Clone)]
#[enum_dispatch(Encode, GetType, GetDcid, GetScid)]
pub enum DataHeader {
    Initial(InitialHeader),
    ZeroRtt(ZeroRttHeader),
    Handshake(HandshakeHeader),
}

/// The io module provides functions for parsing and writing long headers.
pub mod io {
    use std::ops::Deref;

    use bytes::BufMut;
    use nom::{
        Err, Parser,
        bytes::streaming::take,
        combinator::{eof, map},
        multi::{length_data, many_till},
        number::streaming::be_u32,
    };

    use super::*;
    use crate::{
        cid::WriteConnectionId,
        packet::{
            header::io::WriteHeader,
            r#type::{
                io::WritePacketType,
                long::{Type as LongType, v1::Type as LongV1Type},
            },
        },
        varint::{WriteVarInt, be_varint},
    };

    /// Parse the version negotiation packet,
    /// [nom](https://docs.rs/nom/latest/nom/) parser style.
    pub fn be_version_negotiation(input: &[u8]) -> nom::IResult<&[u8], VersionNegotiation> {
        let (remain, (versions, _)) = many_till(be_u32, eof).parse(input)?;
        Ok((remain, VersionNegotiation::new(versions)))
    }

    /// Parse the retry packet,
    /// [nom](https://docs.rs/nom/latest/nom/) parser style.
    pub fn be_retry(input: &[u8]) -> nom::IResult<&[u8], Retry> {
        if input.len() < 16 {
            return Err(Err::Incomplete(nom::Needed::new(16)));
        }
        let token_length = input.len() - 16;
        let (integrity, token) = take(token_length)(input)?;
        Ok((&[][..], Retry::new(token, integrity)))
    }

    /// Parse the initial packet,
    /// [nom](https://docs.rs/nom/latest/nom/) parser style.
    pub fn be_initial(input: &[u8]) -> nom::IResult<&[u8], Initial> {
        map(length_data(be_varint), Initial::from_slice).parse(input)
    }

    /// Parse the 0-RTT packet,
    /// [nom](https://docs.rs/nom/latest/nom/) parser style.
    pub fn be_zero_rtt(input: &[u8]) -> nom::IResult<&[u8], ZeroRtt> {
        Ok((input, ZeroRtt))
    }

    /// Parse the handshake packet,
    /// [nom](https://docs.rs/nom/latest/nom/) parser style.
    pub fn be_handshake(input: &[u8]) -> nom::IResult<&[u8], Handshake> {
        Ok((input, Handshake))
    }

    /// The builder for the long header, which is used to create a long header.
    ///
    /// ## Example
    /// ```
    /// use qbase::{cid::ConnectionId, packet::header::long::io::LongHeaderBuilder};
    ///
    /// let scid = ConnectionId::from_slice(b"scid");
    /// let dcid = ConnectionId::from_slice(b"dcid");
    ///
    /// let handshake_header = LongHeaderBuilder::with_cid(dcid, scid).handshake();
    /// ```
    pub struct LongHeaderBuilder {
        pub(crate) dcid: ConnectionId,
        pub(crate) scid: ConnectionId,
    }

    impl LongHeaderBuilder {
        /// Create a new long header builder with the given destination
        /// and source connection IDs.
        pub fn with_cid(dcid: ConnectionId, scid: ConnectionId) -> Self {
            Self { dcid, scid }
        }

        /// Build into a version negotiation header.
        pub fn vn(self, versions: Vec<u32>) -> LongHeader<VersionNegotiation> {
            self.wrap(VersionNegotiation::new(versions))
        }

        /// Build into a retry header.
        pub fn retry(self, token: Vec<u8>, integrity: [u8; 16]) -> LongHeader<Retry> {
            self.wrap(Retry { token, integrity })
        }

        /// Build into an initial header.
        pub fn initial(self, token: Vec<u8>) -> LongHeader<Initial> {
            self.wrap(Initial::with_token(token))
        }

        /// Build into a 0-RTT header.
        pub fn zero_rtt(self) -> LongHeader<ZeroRtt> {
            self.wrap(ZeroRtt)
        }

        /// Build into a handshake header.
        pub fn handshake(self) -> LongHeader<Handshake> {
            self.wrap(Handshake)
        }

        /// Wrap the specific header into the long generic header.
        /// Return the specific long header.
        pub fn wrap<T>(self, specific: T) -> LongHeader<T> {
            LongHeader {
                dcid: self.dcid,
                scid: self.scid,
                specific,
            }
        }

        /// Parse a long header from the input buffer,
        /// [nom](https://docs.rs/nom/latest/nom/) parser style.
        ///
        /// The input buffer would be the remaining data of the buffer.
        pub fn parse(self, ty: LongType, input: &[u8]) -> nom::IResult<&[u8], Header> {
            match ty {
                LongType::VersionNegotiation => {
                    let (remain, versions) = be_version_negotiation(input)?;
                    Ok((remain, Header::VN(self.wrap(versions))))
                }
                LongType::V1(ty) => match ty.deref() {
                    LongV1Type::Retry => {
                        let (remain, retry) = be_retry(input)?;
                        Ok((remain, Header::Retry(self.wrap(retry))))
                    }
                    LongV1Type::Initial => {
                        let (remain, initial) = be_initial(input)?;
                        Ok((remain, Header::Initial(self.wrap(initial))))
                    }
                    LongV1Type::ZeroRtt => {
                        let (remain, zero_rtt) = be_zero_rtt(input)?;
                        Ok((remain, Header::ZeroRtt(self.wrap(zero_rtt))))
                    }
                    LongV1Type::Handshake => {
                        let (remain, handshake) = be_handshake(input)?;
                        Ok((remain, Header::Handshake(self.wrap(handshake))))
                    }
                },
            }
        }
    }

    /// A [`bytes::BufMut`] extension trait, makes buffer more friendly to write long headers.
    pub trait WriteSpecific<S>: BufMut {
        /// Write the specific header content.
        fn put_specific(&mut self, _specific: &S) {}
    }

    impl<T: BufMut> WriteSpecific<VersionNegotiation> for T {
        fn put_specific(&mut self, specific: &VersionNegotiation) {
            for version in &specific.versions {
                self.put_u32(*version);
            }
        }
    }

    impl<T: BufMut> WriteSpecific<Retry> for T {
        fn put_specific(&mut self, specific: &Retry) {
            self.put_slice(&specific.token);
            self.put_slice(&specific.integrity);
        }
    }

    impl<T: BufMut> WriteSpecific<Initial> for T {
        fn put_specific(&mut self, specific: &Initial) {
            self.put_varint(
                &VarInt::try_from(specific.token.len())
                    .expect("token length can not be more than 2^62"),
            );
            self.put_slice(&specific.token);
        }
    }

    /// 0-Rtt headers are empty, so there is nothing to write.
    impl<T: BufMut> WriteSpecific<ZeroRtt> for T {}
    /// Handshake headers are empty, so there is nothing to write.
    impl<T: BufMut> WriteSpecific<Handshake> for T {}

    impl<T, S> WriteHeader<LongHeader<S>> for T
    where
        T: BufMut + WriteSpecific<S>,
        LongHeader<S>: GetType,
    {
        fn put_header(&mut self, header: &LongHeader<S>) {
            let ty = header.get_type();
            self.put_packet_type(&ty);
            self.put_connection_id(&header.dcid);
            self.put_connection_id(&header.scid);
            self.put_specific(&header.specific);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::header::WriteSpecific;

    #[test]
    fn test_be_version_negotiation() {
        use super::io::be_version_negotiation;

        let buf = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02];
        let (remain, versions) = be_version_negotiation(buf.as_ref()).unwrap();
        assert_eq!(versions.versions, vec![0x01, 0x02]);
        assert_eq!(remain.len(), 0);
    }

    #[test]
    fn test_be_retry() {
        use super::io::be_retry;

        let buf = vec![
            0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let (remain, retry) = be_retry(buf.as_ref()).unwrap();
        assert_eq!(
            retry.integrity,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f
            ]
        );
        assert_eq!(retry.token, vec![0x00, 0x00, 0x00]);
        assert_eq!(remain.len(), 0);
        let buf = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f,
        ];
        match be_retry(&buf) {
            Err(e) => assert_eq!(e, nom::Err::Incomplete(nom::Needed::new(16))),
            _ => panic!("unexpected result"),
        }
    }

    #[test]
    fn test_be_initial() {
        use crate::packet::header::long::io::be_initial;
        // Note: The length of the last bit is filled in when sending, here set as 0x01
        // Consistent behavior with zero_rtt and handshake
        let buf = vec![0x03, 0x00, 0x00, 0x00];
        let (remain, initial) = be_initial(buf.as_ref()).unwrap();
        assert_eq!(initial.token, vec![0x00, 0x00, 0x00]);
        assert_eq!(remain.len(), 0);
    }

    #[test]
    fn test_write_version_negotiation_long_header() {
        use super::{LongHeaderBuilder, VersionNegotiation};
        use crate::cid::ConnectionId;

        let mut buf = Vec::<u8>::new();
        let vn_long_header =
            LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default())
                .wrap(VersionNegotiation::new(vec![0x01, 0x02]));
        buf.put_specific(&vn_long_header.specific);
        assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn test_write_retry_long_header() {
        use super::{LongHeaderBuilder, Retry};
        use crate::cid::ConnectionId;

        let mut buf = Vec::<u8>::new();
        let retry_long_header =
            LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default()).wrap(
                Retry::new(
                    &[0x00, 0x00, 0x00],
                    &[
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                        0x0c, 0x0d, 0x0e, 0x0f,
                    ],
                ),
            );
        buf.put_specific(&retry_long_header.specific);
        assert_eq!(
            buf,
            vec![
                0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            ]
        );
    }

    #[test]
    fn test_write_initial_long_header() {
        use super::LongHeaderBuilder;
        use crate::cid::ConnectionId;

        let mut buf = Vec::<u8>::new();
        let initial_long_header =
            LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default())
                .initial(vec![0x00, 0x00, 0x00]);
        buf.put_specific(&initial_long_header.specific);
        assert_eq!(buf, vec![0x03, 0x00, 0x00, 0x00,]);
    }
}
