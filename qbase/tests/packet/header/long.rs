use qbase::packet::header::WriteSpecific;

#[test]
fn test_be_version_negotiation() {
    use qbase::packet::header::long::io::be_version_negotiation;

    let buf = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02];
    let (remain, versions) = be_version_negotiation(buf.as_ref()).unwrap();
    assert_eq!(*versions.versions(), vec![0x01, 0x02]);
    assert_eq!(remain.len(), 0);
}

#[test]
fn test_be_retry() {
    use qbase::packet::header::long::io::be_retry;

    let buf = vec![
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let (remain, retry) = be_retry(buf.as_ref()).unwrap();
    assert_eq!(
        *retry.integrity(),
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f
        ]
    );
    assert_eq!(*retry.token(), vec![0x00, 0x00, 0x00]);
    assert_eq!(remain.len(), 0);
    let buf = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    match be_retry(&buf) {
        Err(e) => assert_eq!(e, nom::Err::Incomplete(nom::Needed::new(16))),
        _ => panic!("unexpected result"),
    }
}

#[test]
fn test_be_initial() {
    use qbase::packet::header::long::io::be_initial;
    // Note: The length of the last bit is filled in when sending, here set as 0x01
    // Consistent behavior with zero_rtt and handshake
    let buf = vec![0x03, 0x00, 0x00, 0x00];
    let (remain, initial) = be_initial(buf.as_ref()).unwrap();
    assert_eq!(*initial.token(), vec![0x00, 0x00, 0x00]);
    assert_eq!(remain.len(), 0);
}

#[test]
fn test_write_version_negotiation_long_header() {
    use qbase::{
        cid::ConnectionId,
        packet::header::{LongHeaderBuilder, long::VersionNegotiation},
    };

    let mut buf = Vec::<u8>::new();
    let vn_long_header =
        LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default())
            .wrap(VersionNegotiation::new(vec![0x01, 0x02]));
    buf.put_specific(&*vn_long_header);
    assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02]);
}

#[test]
fn test_write_retry_long_header() {
    use qbase::{
        cid::ConnectionId,
        packet::header::{LongHeaderBuilder, long::Retry},
    };

    let mut buf = Vec::<u8>::new();
    let retry_long_header =
        LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default()).wrap(
            Retry::new(
                &[0x00, 0x00, 0x00],
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ],
            ),
        );
    buf.put_specific(&*retry_long_header);
    assert_eq!(
        buf,
        vec![
            0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ]
    );
}

#[test]
fn test_write_initial_long_header() {
    use qbase::{cid::ConnectionId, packet::header::LongHeaderBuilder};

    let mut buf = Vec::<u8>::new();
    let initial_long_header =
        LongHeaderBuilder::with_cid(ConnectionId::default(), ConnectionId::default())
            .initial(vec![0x00, 0x00, 0x00]);
    buf.put_specific(&*initial_long_header);
    assert_eq!(buf, vec![0x03, 0x00, 0x00, 0x00,]);
}
