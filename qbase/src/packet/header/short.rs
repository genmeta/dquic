use super::*;
use crate::{cid::ConnectionId, packet::SpinBit};

/// A packet with a short header does not include a length,
/// so it can only be the last packet in a UDP datagram.
///
/// ```text
///      +---spin bit
///      |     +---key phase bits
///      |     |
/// +----+-----+----+------+--------------+----......---+
/// |1|1|S r r K PN | DCIL | DCID(0..160) | Payload ... |
/// +-----+---+-+---+------+--------------+----......---+
///       |<->| |<->|
///         |     |
///         |     +---> packet number length
///         +---> reserved bits, must be 0
/// ```
///
/// See [1-RTT Packet](https://www.rfc-editor.org/rfc/rfc9000.html#name-1-rtt-packet)
/// in [RFC9000](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OneRttHeader {
    // For simplicity, the spin bit is also part of the 1RTT header.
    spin: SpinBit,
    dcid: ConnectionId,
}

impl OneRttHeader {
    /// Create a new 1RTT header.
    pub fn new(spin: SpinBit, dcid: ConnectionId) -> Self {
        Self { spin, dcid }
    }

    /// Get the spin bit.
    pub fn spin(&self) -> SpinBit {
        self.spin
    }
}

impl HeaderSize for OneRttHeader {
    fn size(&self) -> usize {
        1 + self.dcid.len()
    }
}

impl GetType for OneRttHeader {
    fn get_type(&self) -> Type {
        Type::Short(OneRtt(self.spin))
    }
}

impl super::GetDcid for OneRttHeader {
    fn dcid(&self) -> &ConnectionId {
        &self.dcid
    }
}

/// The io module provides functions for parsing and writing 1RTT headers.
pub mod io {
    use bytes::BufMut;

    use super::{GetType, OneRttHeader};
    use crate::packet::{header::io::WriteHeader, signal::SpinBit, r#type::io::WritePacketType};

    /// Parse a 1RTT header from the input buffer,
    /// [nom](https://docs.rs/nom/latest/nom/) parser style.
    pub fn be_one_rtt_header(
        spin: SpinBit,
        dcid_len: usize,
        input: &[u8],
    ) -> nom::IResult<&[u8], OneRttHeader> {
        use nom::bytes::streaming::take;
        let (remain, dcid) = take(dcid_len)(input)?;
        let dcid = crate::cid::ConnectionId::from_slice(dcid);
        Ok((remain, OneRttHeader { spin, dcid }))
    }

    impl<T: BufMut> WriteHeader<OneRttHeader> for T {
        fn put_header(&mut self, header: &OneRttHeader) {
            let ty = header.get_type();
            self.put_packet_type(&ty);
            self.put_slice(&header.dcid);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::header::io::WriteHeader;

    #[test]
    fn test_read_one_rtt_header() {
        use super::io::be_one_rtt_header;
        use crate::packet::{SpinBit, header::ConnectionId};

        let (remain, header) = be_one_rtt_header(SpinBit::One, 0, &[][..]).unwrap();

        assert_eq!(remain.len(), 0);
        assert_eq!(header.spin, SpinBit::One);
        assert_eq!(header.dcid, ConnectionId::default());
    }

    #[test]
    fn test_write_one_rtt_header() {
        use super::OneRttHeader;
        use crate::{cid::ConnectionId, packet::SpinBit};

        let mut buf = vec![];
        let header = OneRttHeader {
            spin: SpinBit::One,
            dcid: ConnectionId::default(),
        };

        buf.put_header(&header);
        // Note: 0x60 == SHORT_HEADER_BIT | FIXED_BIT | Toggle<SPIN_BIT>.value()
        assert_eq!(buf, [0x60]);
    }
}
