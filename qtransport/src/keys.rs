//! Keys own retirement and packet protection generations.
use std::sync::Arc;

mod long;
pub mod open;
pub mod seal;
pub mod short;

pub use long::ArcKeys;
pub use short::{ArcOneRttKeys, PacketKeys};

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error(transparent)]
    Connection(#[from] crate::Error),
    #[error("invalid packet layout or capacity")]
    Layout,
    #[error("packet authentication failed")]
    AuthenticationFailed,
    #[error(transparent)]
    Crypto(#[from] qtls::CryptoError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("keys retired")]
pub struct KeyRetired;

/// Authenticate and decrypt a packet body in place with a decoded packet number.
pub trait Open {
    /// Algorithm limit used by the connection's authentication failure budget.
    fn integrity_limit(&self) -> u64;

    /// Return the plaintext length, excluding the authentication tag.
    fn open(&self, pn: u64, buffer: &mut [u8], body_offset: usize) -> Result<usize, PacketError>;
}

/// Protect an assembled packet in place.
pub trait Seal {
    /// Fixed keys return (); 1-RTT keys return the sending generation and Key Phase.
    type Output;

    fn tag_len(&self) -> usize;

    /// Protect the PN in pn_offset..body_offset and a reserved authentication tag.
    /// The caller supplies enough ciphertext/tag for a sample starting at pn_offset + 4.
    fn seal(&self, pn: u64, buffer: &mut [u8], pn_offset: usize, body_offset: usize, tag_len: usize) -> Result<Self::Output, PacketError>;
}

impl<K: Seal + ?Sized> Seal for &K {
    type Output = K::Output;

    fn tag_len(&self) -> usize {
        (**self).tag_len()
    }

    fn seal(&self, pn: u64, buffer: &mut [u8], pn_offset: usize, body_offset: usize, tag_len: usize) -> Result<Self::Output, PacketError> {
        (**self).seal(pn, buffer, pn_offset, body_offset, tag_len)
    }
}

pub enum Keys {
    Long(Arc<qtls::BidirectionalKeys>),
    Short(short::ArcKeys),
}

impl Seal for Keys {
    type Output = Option<u64>;

    fn tag_len(&self) -> usize {
        match self {
            Self::Long(keys) => keys.sealing.tag_len(),
            Self::Short(keys) => keys.tag_len(),
        }
    }

    fn seal(&self, pn: u64, bytes: &mut [u8], pn_offset: usize, body_offset: usize, tag_len: usize) -> Result<Self::Output, PacketError> {
        match self {
            Self::Long(keys) => keys.sealing.seal(pn, bytes, pn_offset, body_offset, tag_len).map(|()| None),
            Self::Short(keys) => keys.seal(pn, bytes, pn_offset, body_offset, tag_len).map(|(generation, _)| Some(generation)),
        }
    }
}

impl Open for Keys {
    fn integrity_limit(&self) -> u64 {
        match self {
            Self::Long(keys) => keys.opening.integrity_limit(),
            Self::Short(keys) => keys.integrity_limit(),
        }
    }

    fn open(&self, pn: u64, buffer: &mut [u8], body_offset: usize) -> Result<usize, PacketError> {
        match self {
            Self::Long(keys) => keys.opening.open(pn, buffer, body_offset),
            Self::Short(keys) => keys.open(pn, buffer, body_offset),
        }
    }
}
