#[test]
fn test_try_from() {
    use qbase::packet::{error::Error, r#type::long::v1::Type};

    assert_eq!(Type::try_from(0xc0), Ok(Type::Initial));
    assert_eq!(Type::try_from(0xd0), Ok(Type::ZeroRtt));
    assert_eq!(Type::try_from(0xe0), Ok(Type::Handshake));
    assert_eq!(Type::try_from(0xf0), Ok(Type::Retry));
    assert_eq!(Type::try_from(0x00), Err(Error::InvalidFixedBit));
}
