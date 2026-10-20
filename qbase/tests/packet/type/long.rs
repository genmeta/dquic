#[path = "long/v1.rs"]
mod v1;

use qbase::packet::r#type::long::Ver1;

#[test]
fn test_read_long_type() {
    use qbase::packet::r#type::long::{Type, io::parse_long_type};

    let buf = vec![0x00, 0x00, 0x00, 0x01];
    let (remain, ty) = parse_long_type(0xc0)(&buf).unwrap();
    assert_eq!(remain.len(), 0);
    assert_eq!(ty, Type::V1(Ver1::INITIAL));

    let buf = vec![0x00, 0x00, 0x00, 0x00];
    let (remain, ty) = parse_long_type(0x80)(&buf).unwrap();
    assert_eq!(remain.len(), 0);
    assert_eq!(ty, Type::VersionNegotiation);
}

#[test]
#[should_panic]
fn test_read_long_type_with_wrong_version() {
    use qbase::packet::r#type::long::{Type, io::parse_long_type};

    let buf = vec![0x00, 0x00, 0x00, 0x03];
    let (remain, ty) = parse_long_type(0xc0)(&buf).unwrap();
    assert_eq!(remain.len(), 0);
    assert_eq!(ty, Type::V1(Ver1::INITIAL));
}

#[test]
fn test_write_long_type() {
    use qbase::packet::r#type::long::{Type, io::WriteLongType};

    let mut buf = vec![];
    let ty = Type::V1(Ver1::INITIAL);
    buf.put_long_type(&ty);
    assert_eq!(buf, vec![0xc0, 0x00, 0x00, 0x00, 0x01]);
}

#[test]
fn test_write_version_negotiation_long_type() {
    use qbase::packet::r#type::long::{Type, io::WriteLongType};

    let mut buf = vec![];
    let ty = Type::VersionNegotiation;
    buf.put_long_type(&ty);
    assert_eq!(buf, vec![0x80, 0x00, 0x00, 0x00, 0x00]);
}
