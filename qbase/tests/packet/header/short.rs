use qbase::packet::{GetDcid, header::io::WriteHeader};

#[test]
fn test_read_one_rtt_header() {
    use qbase::{
        cid::ConnectionId,
        packet::{SpinBit, header::short::io::be_one_rtt_header},
    };

    let (remain, header) = be_one_rtt_header(SpinBit::One, 0, &[][..]).unwrap();

    assert_eq!(remain.len(), 0);
    assert_eq!(header.spin(), SpinBit::One);
    assert_eq!(*header.dcid(), ConnectionId::default());
}

#[test]
fn test_write_one_rtt_header() {
    use qbase::{
        cid::ConnectionId,
        packet::{SpinBit, header::short::OneRttHeader},
    };

    let mut buf = vec![];
    let header = OneRttHeader::new(SpinBit::One, ConnectionId::default());

    buf.put_header(&header);
    // Note: 0x60 == SHORT_HEADER_BIT | FIXED_BIT | Toggle<SPIN_BIT>.value()
    assert_eq!(buf, [0x60]);
}
