use qbase::packet::r#type::short::*;

#[test]
fn test_write_short_type() {
    use qbase::packet::r#type::short::OneRtt;

    let mut buf = vec![];
    let ty = OneRtt::from(0x00);
    buf.put_short_type(&ty);
    // Note: 0x40 == SHORT_HEADER_BIT | qbase::packet::r#type::short::FIXED_BIT | 0x00
    assert_eq!(buf, vec![0x40]);

    let mut buf = vec![];
    let ty = OneRtt::from(0x20);
    buf.put_short_type(&ty);
    // Note: 0x60 == SHORT_HEADER_BIT | qbase::packet::r#type::short::FIXED_BIT | 0x20
    assert_eq!(buf, vec![0x60]);
}
