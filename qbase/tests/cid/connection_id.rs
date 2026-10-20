use qbase::cid::*;

#[test]
fn test_read_connection_id() {
    let buf = vec![0x04, 0x01, 0x02, 0x03, 0x04];
    let (remain, cid) = be_connection_id(&buf).unwrap();
    assert!(remain.is_empty());
    assert_eq!(*cid, [0x01, 0x02, 0x03, 0x04],);

    let buf = vec![21, 0x01, 0x02, 0x03, 0x04];
    assert_eq!(
        be_connection_id(&buf),
        Err(nom::Err::Error(nom::error::make_error(
            &buf[1..],
            nom::error::ErrorKind::TooLarge
        )))
    );
}

#[test]
#[should_panic]
fn test_cid_from_large_slice() {
    ConnectionId::from_slice(&[0; MAX_CID_SIZE + 1]);
}

#[test]
fn test_write_connection_id() {
    use bytes::{Bytes, BytesMut};
    let mut buf = BytesMut::new();
    let cid = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04]);
    buf.put_connection_id(&cid);
    assert_eq!(
        buf.freeze(),
        Bytes::from_static(&[0x04, 0x01, 0x02, 0x03, 0x04])
    );
}
