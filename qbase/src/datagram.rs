//! Classification and wire codecs for UDP datagrams carried by dquic.

/// Default single-datagram receive budget until path MTU discovery is available.
pub const MAX_DATAGRAM_SIZE: usize = 1536;

pub mod error;
pub mod forward;
pub mod io;
pub mod stun;
pub mod r#type;

pub use error::Error;
pub use io::{Datagram, WriteDatagram, be_datagram};
pub use stun::{Attribute, BindingRequest, BindingResponse, MessageType as StunMessageType, TransactionId};
pub use r#type::{GetDatagramType, Type, WriteDatagramType, be_datagram_type};
