use qbase::packet::number::{PacketNumber, WritePacketNumber};

#[test]
fn test_read_packet_number() {
    let buf = [0x00];
    assert_eq!(
        (&[][..], qbase::packet::number::PacketNumber::U8(0)),
        qbase::packet::number::take_pn_len(1)(&buf).unwrap()
    );

    let buf = [0x01, 0x00];
    assert_eq!(
        (&[][..], qbase::packet::number::PacketNumber::U16(1 << 8)),
        qbase::packet::number::take_pn_len(2)(&buf).unwrap()
    );

    let buf = [0x01, 0x00, 0x00];
    assert_eq!(
        (&[][..], qbase::packet::number::PacketNumber::U24(1 << 16)),
        qbase::packet::number::take_pn_len(3)(&buf).unwrap()
    );

    let buf = [0x01, 0x00, 0x00, 0x00];
    assert_eq!(
        (&[][..], qbase::packet::number::PacketNumber::U32(1 << 24)),
        qbase::packet::number::take_pn_len(4)(&buf).unwrap()
    );
}

#[test]
#[should_panic]
fn test_read_packet_number_too_large() {
    let buf = [0x01, 0x00, 0x00, 0x00, 0x00];
    qbase::packet::number::take_pn_len(5)(&buf).unwrap();
}

#[test]
fn test_write_packet_number() {
    let mut buf = vec![];
    buf.put_packet_number(PacketNumber::encode(0, 0));
    // Minimum 16-bit PN encoding ensures delayed packets on slower paths remain decodable
    assert_eq!(buf, [0x00, 0x00]);

    buf.clear();
    buf.put_packet_number(PacketNumber::encode(1 << 8, 0));
    assert_eq!(buf, [0x01, 0x00]);

    buf.clear();
    buf.put_packet_number(PacketNumber::encode(1 << 16, 0));
    assert_eq!(buf, [0x01, 0x00, 0x00]);

    buf.clear();
    buf.put_packet_number(PacketNumber::encode(1 << 24, 0));
    assert_eq!(buf, [0x01, 0x00, 0x00, 0x00]);
}

#[test]
fn test_encode_packet_number() {
    let pn = qbase::packet::number::PacketNumber::encode((1 << 31) - 1, 0);
    assert_eq!(pn.decode(0), (1 << 31) - 1);

    let pn = qbase::packet::number::PacketNumber::encode(0, 0);
    assert_eq!(pn.decode(0), 0);
}

#[test]
#[should_panic]
fn test_encode_packet_number_overflow() {
    PacketNumber::encode(1 << 31, 0);
}

#[test]
fn pn_encoding_selects_two_three_and_four_bytes_from_the_ack_gap() {
    let largest = 1 << 40;
    for (gap, size) in [(32767, 2), (32768, 3), (8388607, 3), (8388608, 4)] {
        let pn = largest + gap;
        let encoded = PacketNumber::encode(pn, largest);
        assert_eq!(encoded.size(), size);
        assert_eq!(encoded.decode(pn), pn);
    }
}
