//! Classification and wire codecs for UDP datagrams carried by dquic.

pub mod error;
pub mod forward;
pub mod io;
pub mod stun;
pub mod r#type;

pub use error::Error;
pub use io::{Datagram, WriteDatagram, be_datagram};
pub use stun::{
    Attribute, BindingRequest, BindingResponse, MessageType as StunMessageType, TransactionId,
};
pub use r#type::{GetDatagramType, Type, WriteDatagramType, be_datagram_type};
