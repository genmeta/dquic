use thiserror::Error;

/// Errors encountered while parsing a datagram.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum Error {
    #[error("Invalid datagram type")]
    InvalidDatagramType,
    #[error("Invalid STUN type")]
    InvalidStunType,
    #[error("Invalid STUN datagram")]
    InvalidStunMessage,
    #[error("Invalid Forward datagram")]
    InvalidForwardDatagram,
}
