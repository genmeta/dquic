use qbase::{
    frame::{EncodeSize, FrameType, GetFrameType, io::WriteFrame, *},
    varint::VarInt,
};

#[test]
fn test_ack_frame() {
    // test frame type, encoding size, and max encoding size
    let mut frame = AckFrame::new(
        VarInt::from_u32(0x1234),
        VarInt::from_u32(0x1234),
        VarInt::from_u32(0x1234),
        vec![(VarInt::from_u32(3), VarInt::from_u32(20))],
        None,
    );
    assert_eq!(frame.frame_type(), FrameType::Ack(Ecn::None));
    assert_eq!(frame.encoding_size(), 1 + 2 * 3 + 1 + 2);
    assert_eq!(frame.max_encoding_size(), 1 + 4 * 8 + 2 * 8);

    // test set_ecn and take_ecn
    let ecn = EcnCounts::new(VarInt::from_u32(0x1234), VarInt::from_u32(0x1234), VarInt::from_u32(0x1234));
    frame.set_ecn(ecn);
    assert!(frame.ecn().is_some());
    assert_eq!(frame.take_ecn(), Some(ecn));
}

#[test]
fn test_write_ack_frame() {
    let mut buf = Vec::new();
    let frame = AckFrame::new(
        VarInt::from_u32(0x1234),
        VarInt::from_u32(0x1234),
        VarInt::from_u32(0x1234),
        vec![(VarInt::from_u32(3), VarInt::from_u32(20))],
        Some(EcnCounts::new(VarInt::from_u32(0x1234), VarInt::from_u32(0x1234), VarInt::from_u32(0x1234))),
    );

    buf.put_frame(&frame);
    assert_eq!(
        buf,
        vec![
            0x03, 0x52, 0x34, 0x52, 0x34, 0x01, 0x52, 0x34, 3, 20, // frame
            0x52, 0x34, 0x52, 0x34, 0x52, 0x34 // ecn
        ]
    );
}

#[test]
fn test_ack_frame_into_iter() {
    // let mut frame = AckFrame::new(1000, 0, 0x1234, None).unwrap();
    let frame = AckFrame::new(
        VarInt::from_u32(1000),
        VarInt::from_u32(0x1234),
        VarInt::from_u32(0),
        vec![
            (VarInt::from_u32(0), VarInt::from_u32(2)),
            (VarInt::from_u32(4), VarInt::from_u32(30)),
            (VarInt::from_u32(7), VarInt::from_u32(40)),
        ],
        None,
    );
    // frame.alternating_gap_and_range(0, 2);
    // frame.alternating_gap_and_range(4, 30);
    // frame.alternating_gap_and_range(7, 40);

    let mut iter = frame.iter();
    assert_eq!(iter.next(), Some(1000..=1000));
    assert_eq!(iter.next(), Some(996..=998));
    assert_eq!(iter.next(), Some(960..=990));
    assert_eq!(iter.next(), Some(911..=951));
    assert_eq!(iter.next(), None);
}

#[test]
fn test_read_ecn_count() {
    let frame = super::parse_frame(&[0x03, 0, 0, 0, 0, 0x52, 0x34, 0x52, 0x34, 0x52, 0x34], FrameType::Ack(Ecn::Exist));
    let Frame::Ack(frame) = frame else {
        panic!("expected ACK frame")
    };
    assert_eq!(frame.ecn(), Some(EcnCounts::new(VarInt::from_u32(0x1234), VarInt::from_u32(0x1234), VarInt::from_u32(0x1234))));
}

#[test]
fn test_read_ack_frame() {
    assert_eq!(
        super::parse_frame(&[0x02, 0x52, 0x34, 0x52, 0x34, 0x01, 0x52, 0x34, 3, 20], FrameType::Ack(Ecn::None)),
        Frame::Ack(AckFrame::new(
            VarInt::from_u32(0x1234),
            VarInt::from_u32(0x1234),
            VarInt::from_u32(0x1234),
            vec![(VarInt::from_u32(3), VarInt::from_u32(20))],
            None
        ))
    );
}

#[test]
fn frame_reader_decodes_ack_delay_and_preserves_ranges_and_ecn() {
    use qbase::{
        packet::r#type::{Type, short::OneRtt},
        varint::VARINT_MAX,
    };

    for (exponent, encoded, decoded) in [(0, 7, 7), (3, 7, 56), (20, 7, 7 << 20), (3, 1 << 61, VARINT_MAX), (3, VARINT_MAX, VARINT_MAX)] {
        for ecn in [None, Some(EcnCounts::new(1u32.into(), 2u32.into(), 3u32.into()))] {
            let ranges = vec![(1u32.into(), 0u32.into())];
            let mut bytes = bytes::BytesMut::new();
            bytes.put_frame(&AckFrame::new(3u32.into(), encoded.try_into().unwrap(), 0u32.into(), ranges.clone(), ecn));
            bytes.put_frame(&PingFrame);
            let mut reader = FrameReader::new(bytes.freeze(), Type::Short(OneRtt(0.into()))).with_ack_delay_exponent(exponent);
            assert_eq!(
                reader.next().unwrap().unwrap(),
                (
                    Frame::Ack(AckFrame::new(3u32.into(), decoded.try_into().unwrap(), 0u32.into(), ranges, ecn)),
                    FrameType::Ack(if ecn.is_some() { Ecn::Exist } else { Ecn::None }),
                )
            );
            assert_eq!(reader.next().unwrap().unwrap(), (Frame::Ping(PingFrame), FrameType::Ping));
            assert!(reader.next().is_none());
        }
    }
}

#[test]
fn frame_reader_does_not_apply_peer_ack_delay_exponent_to_handshake_spaces() {
    use qbase::packet::r#type::{
        Type,
        long::{Type::V1, Ver1},
    };

    let ack = AckFrame::new(0u32.into(), 7u32.into(), 0u32.into(), vec![], None);
    let mut bytes = bytes::BytesMut::new();
    bytes.put_frame(&ack);
    for packet_type in [Type::Long(V1(Ver1::INITIAL)), Type::Long(V1(Ver1::HANDSHAKE))] {
        let mut reader = FrameReader::new(bytes.clone().freeze(), packet_type).with_ack_delay_exponent(20);
        assert_eq!(reader.next().unwrap().unwrap().0, Frame::Ack(ack.clone()));
        assert!(reader.next().is_none());
    }
}
