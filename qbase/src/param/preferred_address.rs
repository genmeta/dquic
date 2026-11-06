use std::net::{SocketAddrV4, SocketAddrV6};

use getset::{CopyGetters, MutGetters, Setters};
use nom::Parser;

use crate::{
    cid::{ConnectionId, WriteConnectionId, be_connection_id},
    token::{ResetToken, WriteResetToken, be_reset_token},
};

/// The server's preferred address, which is used to effect
/// a change in server address at the end of the handshake.
///
/// See [section-18.2-4.31](https://datatracker.ietf.org/doc/html/rfc9000#section-18.2-4.32)
/// and [figure-22](https://datatracker.ietf.org/doc/html/rfc9000#figure-22)
/// for more details.
#[derive(CopyGetters, Setters, MutGetters, Debug, PartialEq, Clone, Copy)]
pub struct PreferredAddress {
    #[getset(get_copy = "pub", set = "pub")]
    address_v4: SocketAddrV4,
    #[getset(get_copy = "pub", set = "pub")]
    address_v6: SocketAddrV6,
    #[getset(get_copy = "pub", set = "pub")]
    connection_id: ConnectionId,
    #[getset(get_copy = "pub", set = "pub")]
    stateless_reset_token: ResetToken,
}

impl PreferredAddress {
    /// Create a new preferred address.
    pub fn new(address_v4: SocketAddrV4, address_v6: SocketAddrV6, connection_id: ConnectionId, stateless_reset_token: ResetToken) -> Self {
        Self { address_v4, address_v6, connection_id, stateless_reset_token }
    }

    /// Returns the encoding size of the preferred address.
    pub fn encoding_size(&self) -> usize {
        6 + 18 + self.connection_id.encoding_size() + self.stateless_reset_token.encoding_size()
    }
}

/// Parse the preferred address from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_preferred_address(input: &[u8]) -> nom::IResult<&[u8], PreferredAddress> {
    use nom::{bytes::streaming::take, combinator::map};

    let (input, address_v4) = map(take(6usize), |buf: &[u8]| {
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&buf[..4]);
        let port = u16::from_be_bytes([buf[4], buf[5]]);
        SocketAddrV4::new(addr.into(), port)
    })
    .parse(input)?;

    let (input, address_v6) = map(take(18usize), |buf: &[u8]| {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&buf[..16]);
        let port = u16::from_be_bytes([buf[16], buf[17]]);
        SocketAddrV6::new(addr.into(), port, 0, 0)
    })
    .parse(input)?;

    let (input, connection_id) = be_connection_id(input)?;
    let (input, stateless_reset_token) = be_reset_token(input)?;

    Ok((input, PreferredAddress { address_v4, address_v6, connection_id, stateless_reset_token }))
}

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly
/// to write the preferred address.
pub trait WirtePreferredAddress: bytes::BufMut {
    /// Write the preferred address to the buffer.
    fn put_preferred_address(&mut self, addr: &PreferredAddress);
}

impl<T: bytes::BufMut> WirtePreferredAddress for T {
    fn put_preferred_address(&mut self, addr: &PreferredAddress) {
        self.put_slice(&addr.address_v4.ip().octets());
        self.put_u16(addr.address_v4.port());

        self.put_slice(&addr.address_v6.ip().octets());
        self.put_u16(addr.address_v6.port());

        self.put_connection_id(&addr.connection_id);
        self.put_reset_token(&addr.stateless_reset_token);
    }
}
