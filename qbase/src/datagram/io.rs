use bytes::{BufMut, BytesMut};

use super::{
    Error, forward,
    stun::{self, WriteStunMessage, WriteTransactionId},
    r#type::{GetDatagramType, Type, WriteDatagramType, v0},
};
use crate::net::route::{Pathway, WritePathway, be_pathway};

/// A classified UDP datagram.
#[derive(Debug, Clone, PartialEq)]
pub enum Datagram {
    Stun(stun::TransactionId, stun::Message),
    Forward(Pathway, forward::Payload),
    Raw(BytesMut),
}

impl GetDatagramType for Datagram {
    fn get_datagram_type(&self) -> Type {
        match self {
            Self::Stun(_, message) => message.get_datagram_type(),
            Self::Forward(pathway, _) => pathway.get_datagram_type(),
            Self::Raw(_) => Type::Raw,
        }
    }
}

/// Classifies and decodes one complete UDP datagram.
pub fn be_datagram(bytes: BytesMut) -> Result<Datagram, Error> {
    let (input, ty) = super::be_datagram_type(&bytes).map_err(|_| Error::InvalidDatagramType)?;
    match ty {
        Type::V0(v0::Type::Stun(ty)) => {
            let (input, transaction_id) =
                stun::be_transaction_id(input).map_err(|_| Error::InvalidStunMessage)?;
            let (remain, message) =
                stun::be_stun_message(ty, input).map_err(|_| Error::InvalidStunMessage)?;
            if !remain.is_empty() {
                return Err(Error::InvalidStunMessage);
            }
            Ok(Datagram::Stun(transaction_id, message))
        }
        Type::V0(v0::Type::Forward(family, source, destination)) => {
            let (raw_offset, pathway) = {
                let (raw, pathway) = be_pathway(input, family, source, destination)
                    .map_err(|_| Error::InvalidForwardDatagram)?;
                if raw.is_empty() {
                    return Err(Error::InvalidForwardDatagram);
                }
                (bytes.len() - raw.len(), pathway)
            };
            let payload = forward::Payload::new(bytes, raw_offset);
            Ok(Datagram::Forward(pathway, payload))
        }
        Type::Raw => Ok(Datagram::Raw(bytes)),
    }
}

pub trait WriteDatagram: BufMut {
    fn put_datagram(&mut self, datagram: &Datagram) -> Result<(), Error>;
}

impl<T: BufMut> WriteDatagram for T {
    fn put_datagram(&mut self, datagram: &Datagram) -> Result<(), Error> {
        match datagram {
            Datagram::Stun(transaction_id, message) => {
                self.put_datagram_type(&message.get_datagram_type());
                self.put_transaction_id(transaction_id);
                self.put_stun_message(message);
                Ok(())
            }
            Datagram::Forward(pathway, payload) => {
                self.put_datagram_type(&pathway.get_datagram_type());
                self.put_pathway(pathway);
                self.put_slice(payload.raw());
                Ok(())
            }
            Datagram::Raw(bytes) => {
                self.put_slice(bytes);
                Ok(())
            }
        }
    }
}
