use crate::packet::{error::Error, r#type::FIXED_BIT};

/// Long packet types. The 3th and 4th bits of the first byte of the long header
/// represent the specific packet type.
///
/// See [long header packet types](https://www.rfc-editor.org/rfc/rfc9000.html#name-long-header-packet-types)
/// of [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    /// Initial packet type, represented by 0b00
    Initial,
    /// 0-RTT packet type, represented by 0b01
    ZeroRtt,
    /// Handshake packet type, represented by 0b10
    Handshake,
    /// Retry packet type, represented by 0b11
    Retry,
}

const LONG_PACKET_TYPE_MASK: u8 = 0x30;
const INITIAL_PACKET_TYPE: u8 = 0x00;
const ZERO_RTT_PACKET_TYPE: u8 = 0x10;
const HANDSHAKE_PACKET_TYPE: u8 = 0x20;
const RETRY_PACKET_TYPE: u8 = 0x30;

impl From<Type> for u8 {
    fn from(value: Type) -> u8 {
        match value {
            Type::Retry => RETRY_PACKET_TYPE,
            Type::Initial => INITIAL_PACKET_TYPE,
            Type::ZeroRtt => ZERO_RTT_PACKET_TYPE,
            Type::Handshake => HANDSHAKE_PACKET_TYPE,
        }
    }
}

impl TryFrom<u8> for Type {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value & FIXED_BIT == 0 {
            return Err(Error::InvalidFixedBit);
        }
        match value & LONG_PACKET_TYPE_MASK {
            INITIAL_PACKET_TYPE => Ok(Type::Initial),
            ZERO_RTT_PACKET_TYPE => Ok(Type::ZeroRtt),
            HANDSHAKE_PACKET_TYPE => Ok(Type::Handshake),
            RETRY_PACKET_TYPE => Ok(Type::Retry),
            _ => unreachable!(),
        }
    }
}
