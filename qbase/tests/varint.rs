use qbase::varint::{EncodeBytes, VarInt, WriteVarInt};

#[test]
fn test_equal() {
    let val = VarInt::from_u64(0).unwrap();
    assert_eq!(val, 0);
    assert!(val == 0);
    assert!(val != 1)
}

#[test]
fn test_be_varint() {
    {
        let buf = &[0b00000001u8, 0x01][..];
        let r = qbase::varint::be_varint(buf);
        assert_eq!(r, Ok((&[0x01][..], VarInt::from_u64(1).unwrap())));
    }
    {
        let buf = &[0b01000000u8, 0x06u8][..];
        let r = qbase::varint::be_varint(buf);
        assert_eq!(r, Ok((&[][..], VarInt::from_u64(6).unwrap())));
    }
    {
        let buf = &[0b10000000u8, 1, 1, 1][..];
        let r = qbase::varint::be_varint(buf);
        assert_eq!(r, Ok((&[][..], VarInt::from_u64(0x010101).unwrap())));
    }
    {
        let buf = &[0b11000000u8, 1, 1, 1, 1, 1, 1, 1][..];
        let r = qbase::varint::be_varint(buf);
        assert_eq!(
            r,
            Ok((&[][..], VarInt::from_u64(0x01010101010101).unwrap()))
        );
    }
    {
        let buf = &[0b11000000u8, 0x06u8][..];
        let r = qbase::varint::be_varint(buf);
        assert_eq!(r, Err(nom::Err::Incomplete(nom::Needed::new(6))));
    }
}

fn assert_put_varint_eq(val: u64, expected: &[u8]) {
    let val = VarInt::from_u64(val).unwrap();
    let mut buf = vec![];
    buf.put_varint(&val);
    assert_eq!(buf, expected);
}

#[test]
fn test_put_varint() {
    assert_put_varint_eq(0x0000_0000_0000_0000, &[0]);
    assert_put_varint_eq(0x0000_0000_0000_003F, &[0x3F]);
    assert_put_varint_eq(0x0000_0000_0000_0040, &[0x40, 0x40]);
    assert_put_varint_eq(0x0000_0000_0000_3FFF, &[0x7F, 0xFF]);
    assert_put_varint_eq(0x0000_0000_0000_4000, &[0x80, 0x00, 0x40, 0x00]);
    assert_put_varint_eq(0x0000_0000_3FFF_FFFF, &[0xBF, 0xFF, 0xFF, 0xFF]);
    assert_put_varint_eq(
        0x0000_0000_4000_0000,
        &[0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00],
    );
    assert_put_varint_eq(
        0x3FFF_FFFF_FFFF_FFFF,
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    );
}

#[test]
fn test_encode_varint() {
    let val = VarInt::from_u32(1);
    let mut encode_buf = [0u8; 8];

    let mut buf = &mut encode_buf[..];
    buf.put_varint(&val);
    assert_eq!(buf.len(), 7);
    assert_eq!(encode_buf[0..1], [0x01]);

    let mut buf = &mut encode_buf[..];
    buf.encode_varint(&val, EncodeBytes::Two);
    assert_eq!(buf.len(), 6);
    assert_eq!(encode_buf[0..2], [0x40, 0x01]);
}
