use std::{
    hash::{Hash, Hasher},
    ops::Deref,
};

use nom::{IResult, bytes::streaming::take, number::streaming::be_u8};
use rand::RngExt;

/// The connection id length must not exceed 20 bytes. See [`ConnectionId`].
pub const MAX_CID_SIZE: usize = 20;

/// Connection ID in [QUIC RFC 9000](https://tools.ietf.org/html/rfc9000).
///
/// In QUIC version 1, this value MUST NOT exceed 20 bytes.
/// Endpoints that receive a version 1 long header with a value larger than
/// 20 MUST drop the packet.
/// See [Connection Id Length](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-3.11).
///
/// See [connection id](https://tools.ietf.org/html/rfc9000#name-connection-id)
/// of [QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)
/// for more details.
#[derive(Clone, Copy, Eq, Default)]
pub struct ConnectionId {
    pub(crate) len: u8,
    pub(crate) bytes: [u8; MAX_CID_SIZE],
}

impl core::fmt::LowerHex for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for &b in self.as_ref() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl core::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::fmt::LowerHex::fmt(self, f)
    }
}

impl core::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::fmt::LowerHex::fmt(self, f)
    }
}

/// Parse a connection ID from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
///
/// ## Note:
///
/// The connection ID length is limited to 20 bytes, or it will return an error.
/// See [`ConnectionId`].
pub fn be_connection_id(input: &[u8]) -> IResult<&[u8], ConnectionId> {
    let (remain, len) = be_u8(input)?;
    be_connection_id_with_len(remain, len as usize)
}

/// Parse a given `len` connection ID from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
///
/// ## Note:
///
/// The connection ID length is limited to 20 bytes, or it will return an error.
pub fn be_connection_id_with_len(input: &[u8], len: usize) -> IResult<&[u8], ConnectionId> {
    if len > MAX_CID_SIZE {
        return Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::TooLarge,
        )));
    }
    let (remain, bytes) = take(len)(input)?;
    Ok((remain, ConnectionId::from_slice(bytes)))
}

/// A BufMut extension trait, makes buffer more friendly to write connection ID.
pub trait WriteConnectionId: bytes::BufMut {
    /// Write a connection ID to the buffer.
    fn put_connection_id(&mut self, cid: &ConnectionId);
}

impl<T: bytes::BufMut> WriteConnectionId for T {
    fn put_connection_id(&mut self, cid: &ConnectionId) {
        self.put_u8(cid.len);
        self.put_slice(cid);
    }
}

impl ConnectionId {
    /// Create a new connection ID from a given bytes slice.
    pub fn from_slice(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_CID_SIZE);
        let mut res = Self {
            len: bytes.len() as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        res.bytes[..bytes.len()].copy_from_slice(bytes);
        res
    }

    /// Random generate a connection ID of the given length.
    /// The connection ID maybe not unique, so it should be checked before use.
    pub fn random_gen(len: usize) -> Self {
        debug_assert!(len <= MAX_CID_SIZE);
        let mut bytes = [0; MAX_CID_SIZE];
        rand::rng().fill(&mut bytes[..len]);
        Self {
            len: len as u8,
            bytes,
        }
    }

    /// Generates a random connection ID like [`Self::random_gen`].
    /// Additionally, allows specific bits of the connection ID to be set to the given mark.
    pub fn random_gen_with_mark(len: usize, mark: u8, mask: u8) -> Self {
        debug_assert!(len > 0 && len <= MAX_CID_SIZE);
        let mut bytes = [0; MAX_CID_SIZE];
        rand::rng().fill(&mut bytes[..len]);
        bytes[0] = (bytes[0] & mask) | mark;
        Self {
            len: len as u8,
            bytes,
        }
    }

    /// Get the encoding size of the connection ID.
    ///
    /// Includes 1-byte length encoding and connection ID bytes.
    pub fn encoding_size(&self) -> usize {
        1 + self.len as usize
    }
}

impl Deref for ConnectionId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes[0..self.len as usize]
    }
}

impl PartialEq<ConnectionId> for ConnectionId {
    fn eq(&self, other: &ConnectionId) -> bool {
        self.len == other.len && self.bytes[..self.len as usize] == other.bytes[..self.len as usize]
    }
}

impl Hash for ConnectionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.len.hash(state);
        self.bytes[..self.len as usize].hash(state);
    }
}
