use std::mem;

use bytes::BytesMut;
use nom::{Parser, multi::length_data};

use super::{
    error::Error,
    header::io::be_header,
    r#type::{Type, io::be_packet_type},
    *,
};
use crate::varint::be_varint;

/// Parse the payload of a packet.
///
/// - For long packets, the payload is a [`nom::multi::length_data`].
/// - For 1-RTT packet, the payload is the remaining content of the datagram.
fn be_payload(
    pkty: Type,
    datagram: &mut BytesMut,
    remain_len: usize,
) -> Result<(BytesMut, usize), Error> {
    let offset = datagram.len() - remain_len;
    let input = &datagram[offset..];
    let (remain, payload) = length_data(be_varint).parse(input).map_err(|e| match e {
        ne @ nom::Err::Incomplete(_) => Error::IncompleteHeader(pkty, ne.to_string()),
        _ => unreachable!("parsing packet header never generates error or failure"),
    })?;
    let payload_len = payload.len();
    if payload_len < 20 {
        // The payload needs at least 20 bytes to have enough samples to remove the packet header protection.
        return Err(Error::UnderSampling(pkty, payload.len()));
    }
    let packet_length = datagram.len() - remain.len();
    let bytes = datagram.split_to(packet_length);
    Ok((bytes, packet_length - payload_len))
}

/// Parse the QUIC packet from the datagram, given the length of the DCID.
/// Returns the parsed packet or an error, and the datagram removed the packet's content.
pub fn be_packet(datagram: &mut BytesMut, dcid_len: usize) -> Result<Packet, Error> {
    let input = datagram.as_ref();
    let (remain, pkty) = be_packet_type(input).map_err(|e| match e {
        ne @ nom::Err::Incomplete(_) => Error::IncompleteType(ne.to_string()),
        nom::Err::Error(e) => e,
        _ => unreachable!("parsing packet type never generates failure"),
    })?;
    let (remain, header) = be_header(pkty, dcid_len, remain).map_err(|e| match e {
        ne @ nom::Err::Incomplete(_) => Error::IncompleteHeader(pkty, ne.to_string()),
        _ => unreachable!("parsing packet header never generates error or failure"),
    })?;
    match header {
        Header::VN(header) => {
            datagram.clear();
            Ok(Packet::VN(header))
        }
        Header::Retry(header) => {
            datagram.clear();
            Ok(Packet::Retry(header))
        }
        Header::Initial(header) => {
            let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Long(long::DataHeader::Initial(header)),
                bytes,
                offset,
            }))
        }
        Header::ZeroRtt(header) => {
            let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Long(long::DataHeader::ZeroRtt(header)),
                bytes,
                offset,
            }))
        }
        Header::Handshake(header) => {
            let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Long(long::DataHeader::Handshake(header)),
                bytes,
                offset,
            }))
        }
        Header::OneRtt(header) => {
            if remain.len() < 20 {
                // The payload needs at least 20 bytes to have enough samples to remove the packet header protection.
                return Err(Error::UnderSampling(pkty, remain.len()));
            }
            let remain_len = remain.len();
            let bytes = mem::replace(datagram, BytesMut::new());
            let offset = bytes.len() - remain_len;
            datagram.clear();
            Ok(Packet::Data(DataPacket {
                header: DataHeader::Short(header),
                bytes,
                offset,
            }))
        }
    }
}
