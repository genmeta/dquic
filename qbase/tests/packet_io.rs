use bytes::BytesMut;
use qbase::packet::{DataHeader, Packet, PacketReader, long};

// Initial packet from the former writer test, with a transparent authentication tag.
const INITIAL: &[u8] = b"\xc1\x00\x00\x00\x01\x08testdcid\x08testscid\x0atest_token\x40\x21\x00\x00\x06\x00\x0cclient_hellotransparent_keys";

#[test]
fn initial_length_excludes_trailing_datagram_bytes() {
    let mut padded = BytesMut::from(INITIAL);
    padded.resize(1200, 0);
    let Packet::Data(packet) = PacketReader::new(padded, 8).next().unwrap().unwrap() else {
        panic!("expected Initial packet");
    };
    assert!(matches!(
        packet.header,
        DataHeader::Long(long::DataHeader::Initial(_))
    ));
    assert_eq!(packet.bytes.as_ref(), INITIAL);
}

#[test]
fn coalesced_initial_packets_are_read_separately() {
    let mut coalesced = BytesMut::from(INITIAL);
    coalesced.extend_from_slice(INITIAL);
    let mut packets = PacketReader::new(coalesced, 8);
    for _ in 0..2 {
        let Packet::Data(packet) = packets.next().unwrap().unwrap() else {
            panic!("expected Initial packet");
        };
        assert!(matches!(
            packet.header,
            DataHeader::Long(long::DataHeader::Initial(_))
        ));
        assert_eq!(packet.bytes.as_ref(), INITIAL);
    }
    assert!(packets.next().is_none());
}
